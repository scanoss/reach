// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	sitter "github.com/smacker/go-tree-sitter"
	treeruby "github.com/smacker/go-tree-sitter/ruby"
)

const (
	rubyNodeCall               = "call"
	rubyNodeMethod             = "method"
	rubyNodeSingletonMethod    = "singleton_method"
	rubyNodeClass              = "class"
	rubyNodeModule             = "module"
	rubyNodeAssignment         = "assignment"
	rubyNodeOperatorAssignment = "operator_assignment"
	rubyNodeScopeResolution    = "scope_resolution"
	rubyNodeConstant           = "constant"
	rubyNodeComment            = "comment"
	rubyNodeIdentifier         = "identifier"
	rubyNodeInstanceVariable   = "instance_variable"
	rubyNodeArgumentList       = "argument_list"
	rubyScopeSeparator         = "::"
)

// RubyParser extracts Ruby method declarations, calls and requires.
type RubyParser struct {
	parser       *sitter.Parser
	includeTests bool
	anchors      callAnchors
}

// NewRubyParser creates a Ruby source parser backed by tree-sitter.
func NewRubyParser(opts ...ParserOption) *RubyParser {
	cfg := newParserConfig(opts)
	parser := sitter.NewParser()
	parser.SetLanguage(treeruby.GetLanguage())
	return &RubyParser{parser: parser, includeTests: cfg.includeTests}
}

// CloneParser returns an independent parser for concurrent use.
func (p *RubyParser) CloneParser() Parser {
	return NewRubyParser(WithIncludeTests(p.includeTests))
}

// PackageSeparator is Ruby's namespace separator.
func (p *RubyParser) PackageSeparator() string { return rubyScopeSeparator }

// SubPackagePath nests a directory under its parent namespace.
func (p *RubyParser) SubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + rubyScopeSeparator + dirName
}

// ParseDirectory parses the Ruby sources directly under dir.
func (p *RubyParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("callgraph: ruby parser: read directory %s: %w", dir, err)
	}
	analyses := make([]*FileAnalysis, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != ".rb" {
			continue
		}
		if !p.includeTests && rubyIsTestFile(entry.Name()) {
			continue
		}
		filePath := filepath.Join(dir, entry.Name())
		analysis, err := p.parseFile(filePath, packagePath)
		if err != nil {
			log.Error().Err(err).Str("file", filePath).Str("package", packagePath).Msg("failed to parse file")
			continue
		}
		analyses = append(analyses, analysis)
	}
	return analyses, nil
}

// rubyIsTestFile reports the gem conventions for a test file, both the
// `_test.rb` suffix and the `_spec.rb` RSpec one.
func rubyIsTestFile(name string) bool {
	return strings.HasSuffix(name, "_test.rb") || strings.HasSuffix(name, "_spec.rb")
}

func (p *RubyParser) parseFile(filePath, packagePath string) (*FileAnalysis, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("callgraph: ruby parser: read %s: %w", filePath, err)
	}
	tree, err := p.parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("callgraph: ruby parser: parse %s: %w", filePath, err)
	}
	defer tree.Close()
	defer p.anchors.reset()

	analysis := &FileAnalysis{
		FilePath:    filePath,
		PackageName: packagePath,
		PackagePath: packagePath,
		Imports:     make(map[string]string),
	}
	root := tree.RootNode()
	// A local bound once to a constant stands for it at every call on that
	// local: `m = Digest::MD5; m.hexdigest(x)` is a Digest::MD5 call.
	p.walk(root, src, filePath, packagePath, "", analysis)
	// Top-level statements belong to no method; the module init owns them, as
	// it does for Python.
	moduleIdx := rubyModuleDecl(root, filePath, packagePath, analysis)
	p.collectInto(root, src, filePath, packagePath, rubyScopeAliases(root, src), analysis, moduleIdx)
	analysis.Functions[moduleIdx].AttributeStores = rubyModuleAttributeStores(root, src)
	return analysis, nil
}

// walk records requires, method declarations and calls. namespace is the
// enclosing module/class nesting, which owns the methods declared in it.
func (p *RubyParser) walk(node *sitter.Node, src []byte, filePath, packagePath, namespace string,
	analysis *FileAnalysis) {
	switch node.Type() {
	case rubyNodeClass, rubyNodeModule:
		child := rubyNamespaceOf(node, src, namespace)
		rubySupertypes(node, src, child, analysis)
		for i := 0; i < int(node.ChildCount()); i++ {
			p.walk(node.Child(i), src, filePath, packagePath, child, analysis)
		}
		return
	case rubyNodeMethod, rubyNodeSingletonMethod:
		if decl := rubyMethodDecl(node, src, filePath, packagePath, namespace); decl != nil {
			if body := node.ChildByFieldName("body"); body != nil {
				// A method's locals are its own: a constant bound in one body
				// must not type a same-named parameter of another.
				scoped := rubyScopeAliases(body, src)
				for i := 0; i < int(body.ChildCount()); i++ {
					p.walkCalls(body.Child(i), src, filePath, packagePath, scoped,
						rubyValueScope{literals: rubyBoundLiterals(body, src), params: rubyParameterIndices(decl.Parameters)},
						&decl.Calls)
				}
				decl.Calls = append(decl.Calls,
					rubyBareSelfCalls(body, src, filePath, packagePath, decl.Parameters)...)
				decl.AttributeStores = rubyAttributeStores(body, src)
			}
			analysis.Functions = append(analysis.Functions, *decl)
		}
		// A nested def owns its own calls; recursing here would record them twice.
		p.walkNested(node, src, filePath, packagePath, namespace, analysis)
		return
	case rubyNodeCall:
		if path, ok := rubyRequirePath(node, src); ok {
			analysis.Imports[rubyRequireAlias(path)] = path
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walk(node.Child(i), src, filePath, packagePath, namespace, analysis)
	}
}

// walkNested finds the defs declared inside a method body, which own their own
// calls.
func (p *RubyParser) walkNested(node *sitter.Node, src []byte, filePath, packagePath, namespace string,
	analysis *FileAnalysis) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case rubyNodeMethod, rubyNodeSingletonMethod, rubyNodeClass, rubyNodeModule:
			p.walk(child, src, filePath, packagePath, namespace, analysis)
		default:
			p.walkNested(child, src, filePath, packagePath, namespace, analysis)
		}
	}
}

// parseCall resolves a call's receiver to the constant it names, so the callee
// carries the type the receiver denotes.
func (p *RubyParser) parseCall(node *sitter.Node, src []byte, filePath, packagePath string,
	aliases map[string]string, values rubyValueScope) *FunctionCall {
	method := node.ChildByFieldName("method")
	if method == nil {
		return nil
	}
	args := rubyCallArguments(node, src)
	call := &FunctionCall{
		// The name carries the call's arity, as every other parser's does:
		// the stored key is "pkg.(Type).method#N", and a key without the
		// suffix is not read back as a method at all.
		Callee:      FunctionID{Package: packagePath, Name: fmt.Sprintf("%s#%d", method.Content(src), len(args))},
		Raw:         node.Content(src),
		FilePath:    filePath,
		Line:        int(node.StartPoint().Row) + 1,
		StartCol:    int(node.StartPoint().Column) + 1,
		EndLine:     int(node.EndPoint().Row) + 1,
		EndCol:      int(node.EndPoint().Column) + 1,
		ASTKind:     node.Type(),
		AssignedVar: rubyAssignedVar(node, src),
		Arguments:   args,
		// Where each argument came from, the six kinds every other
		// language reports.
		ArgumentSources: rubyArgumentSources(node, src, values.literals, values.params),
	}
	receiver := node.ChildByFieldName("receiver")
	if receiver == nil {
		// `Digest(:MD5)`: a method whose name is spelled as a constant, not a
		// constant read. It owns nothing, so the name alone keys it.
		return call
	}
	switch receiver.Type() {
	case rubyNodeScopeResolution, rubyNodeConstant:
		call.Callee.Type = rubyConstantName(receiver.Content(src))
		call.StaticReceiver = true
	case rubyNodeIdentifier:
		name := receiver.Content(src)
		call.ReceiverVar = name
		if constant, ok := aliases[name]; ok {
			call.Callee.Type = constant
			call.StaticReceiver = true
		}
	case rubyNodeInstanceVariable:
		// `@algorithm.sign(..)`: the receiver is named, its type is not. The
		// name is what says the call has one, which is what tells a call the
		// graph resolved from one it only guessed.
		call.ReceiverVar = receiver.Content(src)
	case rubyNodeCall:
		// A chain link: the receiver is the previous call, which carries the
		// type. The builder joins them through the chain, not through a type
		// — except where the previous link names the type itself:
		// `Encode.new(..).segments` runs a method of `Encode`, the one class
		// an instantiation can return.
		if constant := rubyInstantiatedConstant(receiver, src); constant != "" {
			call.Callee.Type = constant
		} else if rubyIsSelfClass(receiver, src) {
			// `self.class.default_cert_store`: the receiver is the caller's
			// own class, which only the whole declaration knows.
			call.RubySelfClassReceiver = true
		}
	}
	return call
}

// rubyScopeAliases maps each local that one scope assigns a constant exactly
// once to that constant. A local written more than once, by assignment or by
// an operator assignment, names no single constant and is left out. Nested
// scopes are not descended into: their locals are their own.
func rubyScopeAliases(scope *sitter.Node, src []byte) map[string]string {
	aliases := map[string]string{}
	collectRubyConstantAliases(scope, src, aliases)
	return aliases
}

func collectRubyConstantAliases(node *sitter.Node, src []byte, aliases map[string]string) {
	counts := map[string]int{}
	var walk func(n *sitter.Node, root bool)
	walk = func(n *sitter.Node, root bool) {
		if !root && isFunctionContainer(n.Type()) {
			return // a nested scope binds its own locals
		}
		switch n.Type() {
		case rubyNodeAssignment, rubyNodeOperatorAssignment:
			left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
			if left != nil && left.Type() == rubyNodeIdentifier {
				name := left.Content(src)
				counts[name]++
				if n.Type() == rubyNodeAssignment && right != nil &&
					(right.Type() == rubyNodeScopeResolution || right.Type() == rubyNodeConstant) {
					aliases[name] = rubyConstantName(right.Content(src))
				}
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i), false)
		}
	}
	walk(node, true)
	for name, n := range counts {
		if n > 1 {
			delete(aliases, name)
		}
	}
}

// rubyNamespaceOf nests a class or module name under its enclosing namespace.
func rubyNamespaceOf(node *sitter.Node, src []byte, parent string) string {
	name := node.ChildByFieldName("name")
	if name == nil {
		return parent
	}
	if parent == "" {
		return name.Content(src)
	}
	return parent + rubyScopeSeparator + name.Content(src)
}

func rubyMethodDecl(node *sitter.Node, src []byte, filePath, packagePath, namespace string) *FunctionDecl {
	name := node.ChildByFieldName("name")
	if name == nil {
		return nil
	}
	params := rubyMethodParameters(node, src)
	return &FunctionDecl{
		// A `def self.x` is reached through the class, never through an
		// instance; Ruby lets a class declare both sides under one name
		// (`Request.execute` and `Request.new.execute`), so the side is what
		// tells the two declarations apart.
		Static: node.Type() == rubyNodeSingletonMethod,
		// The name carries the method's arity, as a call's callee does: the
		// builder matches a call to a declaration by comparing the two, so a
		// declaration written without it is reachable from nothing.
		ID:         FunctionID{Package: packagePath, Type: namespace, Name: fmt.Sprintf("%s#%d", name.Content(src), len(params))},
		FilePath:   filePath,
		StartLine:  int(node.StartPoint().Row) + 1,
		EndLine:    int(node.EndPoint().Row) + 1,
		StartCol:   int(node.StartPoint().Column) + 1,
		EndCol:     int(node.EndPoint().Column) + 1,
		OwnerType:  namespace,
		Parameters: params,
	}
}

// rubyMethodParameters are the parameters a `def` declares. A block
// parameter (`&blk`) is one, as Ruby counts it in arity terms for the
// purposes of matching a call that passes a block inline.
func rubyMethodParameters(node *sitter.Node, src []byte) []FunctionParameter {
	list := node.ChildByFieldName("parameters")
	if list == nil {
		return nil
	}
	params := make([]FunctionParameter, 0, int(list.NamedChildCount()))
	for i := 0; i < int(list.NamedChildCount()); i++ {
		p := list.NamedChild(i)
		params = append(params, FunctionParameter{Name: p.Content(src)})
	}
	return params
}

// rubyRequirePath returns the library a `require` or `require_relative` names.
func rubyRequirePath(node *sitter.Node, src []byte) (string, bool) {
	method := node.ChildByFieldName("method")
	if method == nil || node.ChildByFieldName("receiver") != nil {
		return "", false
	}
	switch method.Content(src) {
	case "require", "require_relative":
	default:
		return "", false
	}
	args := node.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return "", false
	}
	return strings.Trim(args.NamedChild(0).Content(src), `"'`), true
}

// rubyRequireAlias is the constant a require conventionally defines: the last
// path segment, which is what the file then calls into.
func rubyRequireAlias(path string) string {
	if i := strings.LastIndex(path, "/"); i >= 0 {
		return path[i+1:]
	}
	return path
}

func rubyCallArguments(node *sitter.Node, src []byte) []string {
	args := node.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	out := make([]string, 0, args.NamedChildCount())
	for i := 0; i < int(args.NamedChildCount()); i++ {
		child := args.NamedChild(i)
		if child.Type() == rubyNodeComment {
			// A comment between arguments is a named node of the grammar
			// and not an argument: counting it gives the call an arity its
			// source never passes, and no rule reaches it.
			continue
		}
		out = append(out, child.Content(src))
	}
	return out
}

// rubyAssignedVar is the local a call's result is bound to; only the outermost
// call of a chain carries it.
func rubyAssignedVar(node *sitter.Node, src []byte) string {
	parent := node.Parent()
	if parent == nil || parent.Type() != rubyNodeAssignment {
		return ""
	}
	if right := parent.ChildByFieldName("right"); right == nil || !right.Equal(node) {
		return ""
	}
	left := parent.ChildByFieldName("left")
	if left == nil {
		return ""
	}
	switch left.Type() {
	case rubyNodeIdentifier:
		return left.Content(src)
	case rubyNodeInstanceVariable:
		// `@signer = Aws::Sigv4::Signer.new(..)`: the name keeps its `@`, so
		// an instance variable is never confused with a local of the same
		// name, and the class it belongs to can type it for every method.
		return left.Content(src)
	}
	return ""
}

// collectInto gathers the calls no method declares, so the module init owns
// every top-level statement of the file.
func (p *RubyParser) collectInto(root *sitter.Node, src []byte, filePath, packagePath string,
	aliases map[string]string, analysis *FileAnalysis, idx int) {
	values := rubyValueScope{literals: rubyBoundLiterals(root, src)}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case rubyNodeMethod, rubyNodeSingletonMethod:
			return // its own declaration already took them
		case rubyNodeCall:
			if call := p.parseCall(n, src, filePath, packagePath, aliases, values); call != nil {
				p.anchors.set(call, n)
				analysis.Functions[idx].Calls = append(analysis.Functions[idx].Calls, *call)
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(root)
}

func (p *RubyParser) walkCalls(node *sitter.Node, src []byte, filePath, packagePath string,
	aliases map[string]string, values rubyValueScope, calls *[]FunctionCall) {
	switch node.Type() {
	case rubyNodeMethod, rubyNodeSingletonMethod:
		return // a nested def owns its own calls
	}
	if node.Type() == rubyNodeCall {
		if call := p.parseCall(node, src, filePath, packagePath, aliases, values); call != nil {
			p.anchors.set(call, node)
			*calls = append(*calls, *call)
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkCalls(node.Child(i), src, filePath, packagePath, aliases, values, calls)
	}
}

// rubyModuleDecl returns the index of the file's `<module>`, creating it when
// the file has none.
func rubyModuleDecl(root *sitter.Node, filePath, packagePath string, analysis *FileAnalysis) int {
	// A Ruby package is a directory, so every file of one would key its
	// module init the same way and the graph would keep a single file's
	// top-level code. The file is what `require` names, so it is what keys
	// the init that owns its statements.
	modulePath := rubyModulePath(filePath, packagePath)
	for i := range analysis.Functions {
		if fn := &analysis.Functions[i]; fn.ID.Name == moduleInitMethodName && fn.ID.Type == "" && fn.ID.Package == modulePath {
			return i
		}
	}
	analysis.Functions = append(analysis.Functions, FunctionDecl{
		ID:           FunctionID{Package: modulePath, Name: moduleInitMethodName},
		FilePath:     filePath,
		StartLine:    int(root.StartPoint().Row) + 1,
		EndLine:      int(root.EndPoint().Row) + 1,
		StartCol:     int(root.StartPoint().Column) + 1,
		EndCol:       int(root.EndPoint().Column) + 1,
		OwnerType:    "module",
		OwnerName:    modulePath,
		FunctionType: functionTypeModuleInit,
	})
	return len(analysis.Functions) - 1
}

// rubyConstantName drops the leading separator of a root-qualified constant,
// `::OpenSSL::Cipher`, which denotes the same type as `OpenSSL::Cipher`.
func rubyConstantName(name string) string {
	return strings.TrimPrefix(name, rubyScopeSeparator)
}

// rubyInstantiatedConstant is the constant a call instantiates, as in
// `Encode.new(..)`, and empty for every other call: only `new` is known to
// return an instance of the constant that receives it.
func rubyInstantiatedConstant(node *sitter.Node, src []byte) string {
	method := node.ChildByFieldName("method")
	if method == nil || method.Content(src) != "new" {
		return ""
	}
	receiver := node.ChildByFieldName("receiver")
	if receiver == nil {
		return ""
	}
	switch receiver.Type() {
	case rubyNodeScopeResolution, rubyNodeConstant:
		return rubyConstantName(receiver.Content(src))
	}
	return ""
}

// rubyModulePath is the package a file's module init is keyed under: the
// directory's package plus the file's own name, the one `require` uses.
func rubyModulePath(filePath, packagePath string) string {
	stem := strings.TrimSuffix(filepath.Base(filePath), filepath.Ext(filePath))
	if stem == "" {
		return packagePath
	}
	if packagePath == "" {
		return stem
	}
	return packagePath + rubyScopeSeparator + stem
}

// rubyIsSelfClass reports the call `self.class`, the receiver that denotes
// the class of the object running the method.
func rubyIsSelfClass(node *sitter.Node, src []byte) bool {
	method := node.ChildByFieldName("method")
	if method == nil || method.Content(src) != "class" {
		return false
	}
	receiver := node.ChildByFieldName("receiver")
	return receiver != nil && receiver.Content(src) == "self"
}

// rubySupertypes records what a class or module takes its methods from: the
// superclass it declares, and every module its body includes, extends or
// prepends. Ruby composes with modules far more than it subclasses, and a
// class that only includes one declares no method of its own -- `class
// Basement; include HTTParty; end` answers `Basement.put` from the module.
func rubySupertypes(node *sitter.Node, src []byte, typ string, analysis *FileAnalysis) {
	if typ == "" {
		return
	}
	add := func(name string) {
		if name == "" {
			return
		}
		if analysis.Supertypes == nil {
			analysis.Supertypes = map[string][]string{}
		}
		for _, seen := range analysis.Supertypes[typ] {
			if seen == name {
				return
			}
		}
		analysis.Supertypes[typ] = append(analysis.Supertypes[typ], name)
	}
	if super := node.ChildByFieldName("superclass"); super != nil {
		add(rubyConstantName(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(super.Content(src)), "<"))))
	}
	body := node.ChildByFieldName("body")
	if body == nil {
		return
	}
	for i := 0; i < int(body.ChildCount()); i++ {
		if name, ok := rubyMixedInModule(body.Child(i), src); ok {
			add(name)
		}
	}
}

// rubyMixedInModule is the module a body statement mixes in.
func rubyMixedInModule(node *sitter.Node, src []byte) (string, bool) {
	if node.Type() != rubyNodeCall || node.ChildByFieldName("receiver") != nil {
		return "", false
	}
	method := node.ChildByFieldName("method")
	if method == nil {
		return "", false
	}
	switch method.Content(src) {
	case "include", "extend", "prepend":
	default:
		return "", false
	}
	args := node.ChildByFieldName("arguments")
	if args == nil || args.NamedChildCount() == 0 {
		return "", false
	}
	first := args.NamedChild(0)
	switch first.Type() {
	case rubyNodeConstant, rubyNodeScopeResolution:
		return rubyConstantName(first.Content(src)), true
	}
	return "", false
}

// rubyValueScope is what a body knows about the names its calls pass: the
// literal each local holds, and the position of each parameter.
type rubyValueScope struct {
	literals map[string]string
	params   map[string]int
}
