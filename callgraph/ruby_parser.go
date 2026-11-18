// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/ruby"
)

// Ruby node types this parser reads, as tree-sitter-ruby names them.
const (
	rubyNodeCall            = "call"
	rubyNodeIdentifier      = "identifier"
	rubyNodeConstant        = "constant"
	rubyNodeScopeResolution = "scope_resolution"
	rubyNodeArgumentList    = "argument_list"
	rubyNodeMethod          = "method"
	rubyNodeSingletonMethod = "singleton_method"
	rubyNodeClass           = "class"
	rubyNodeModule          = "module"
	rubyNodeBodyStatement   = "body_statement"
	rubyNodeAssignment      = "assignment"
	rubyNodeString          = "string"
	rubyNodeStringContent   = "string_content"
)

// rubyRequire and rubyRequireRelative are the two ways a Ruby file names
// another: `require 'openssl'` reaches the load path (a gem or the standard
// library), `require_relative 'helper'` a path beside the file. Both are
// ordinary calls in the grammar, which is why they are read here rather than
// by an import rule.
const (
	rubyRequire         = "require"
	rubyRequireRelative = "require_relative"
)

// rubyTopLevel is the owner of the calls a file makes outside any method: Ruby
// runs a file's body, so those calls are real and a graph that dropped them
// would miss, say, a `OpenSSL::Cipher.new` at the top of a script.
const rubyTopLevel = "<main>"

// RubyParser builds a call graph from Ruby source with tree-sitter.
type RubyParser struct {
	parser       *sitter.Parser
	includeTests bool
}

// NewRubyParser returns a parser for Ruby source.
func NewRubyParser(opts ...ParserOption) *RubyParser {
	cfg := newParserConfig(opts)
	parser := sitter.NewParser()
	parser.SetLanguage(ruby.GetLanguage())
	return &RubyParser{parser: parser, includeTests: cfg.includeTests}
}

// CloneParser returns an independent RubyParser with the same configuration,
// for concurrent use (tree-sitter parsers are not reentrant).
func (p *RubyParser) CloneParser() Parser {
	return NewRubyParser(WithIncludeTests(p.includeTests))
}

// PackageSeparator is Ruby's namespace separator.
func (p *RubyParser) PackageSeparator() string { return "::" }

// SubPackagePath names a directory below parentPath. Ruby has no package
// declaration: a file's namespace comes from its `module`/`class` nesting, and
// the path only locates the file.
func (p *RubyParser) SubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + "/" + dirName
}

// SkipsDirNamed skips the directories a Ruby project keeps dependencies and
// build output in, so a scan reads the project's own source.
func (p *RubyParser) SkipsDirNamed(name string) bool {
	switch name {
	case "vendor", ".bundle", "tmp", "coverage", "pkg", "node_modules":
		return true
	}
	return !p.includeTests && (name == "spec" || name == "test")
}

// ParseFile extracts requires, method declarations and calls from one Ruby file.
func (p *RubyParser) ParseFile(filePath, packagePath string) (*FileAnalysis, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", filePath, err)
	}
	tree, err := p.parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", filePath, err)
	}
	defer tree.Close()

	analysis := &FileAnalysis{
		FilePath:    filePath,
		PackagePath: packagePath,
		PackageName: rubyPackageName(filePath),
		Imports:     make(map[string]string),
	}
	root := tree.RootNode()
	p.extractRequires(root, src, analysis)

	// A file's body runs: its calls belong to <main>, and the methods it
	// declares are walked with the namespace their class or module nesting
	// gives them.
	main := FunctionDecl{
		ID:        FunctionID{Package: packagePath, Name: rubyTopLevel},
		FilePath:  filePath,
		StartLine: 1,
	}
	p.walk(root, src, filePath, packagePath, "", &main, analysis)
	if len(main.Calls) > 0 {
		main.EndLine = int(root.EndPoint().Row) + 1
		analysis.Functions = append(analysis.Functions, main)
	}
	return analysis, nil
}

// rubyPackageName is the file's base name without its extension, which is how
// a `require` names it.
func rubyPackageName(filePath string) string {
	return strings.TrimSuffix(filepath.Base(filePath), ".rb")
}

// extractRequires records every `require` and `require_relative` of the file.
// The key is how the source would name what the file loads -- the last segment
// of the required path -- and the value is the path as written.
func (p *RubyParser) extractRequires(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	if node.Type() == rubyNodeCall {
		if name := rubyCallName(node, src); name == rubyRequire || name == rubyRequireRelative {
			if path := rubyFirstStringArgument(node, src); path != "" {
				segment := path
				if i := strings.LastIndex(segment, "/"); i >= 0 {
					segment = segment[i+1:]
				}
				analysis.Imports[segment] = path
			}
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		p.extractRequires(node.NamedChild(i), src, analysis)
	}
}

// walk descends the tree, collecting the calls of the function it is inside
// and opening a new one at every method declaration. namespace is the
// `module`/`class` nesting of the node, which is what qualifies a method.
func (p *RubyParser) walk(node *sitter.Node, src []byte, filePath, packagePath, namespace string, fn *FunctionDecl, analysis *FileAnalysis) {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		switch child.Type() {
		case rubyNodeModule, rubyNodeClass:
			name := rubyDeclaredName(child, src)
			inner := namespace
			if name != "" {
				inner = rubyJoin(namespace, name)
			}
			p.walk(child, src, filePath, packagePath, inner, fn, analysis)
		case rubyNodeMethod, rubyNodeSingletonMethod:
			p.extractMethod(child, src, filePath, packagePath, namespace, analysis)
		default:
			if child.Type() == rubyNodeCall {
				if call, ok := p.callOf(child, src, filePath); ok {
					fn.Calls = append(fn.Calls, call)
				}
			}
			p.walk(child, src, filePath, packagePath, namespace, fn, analysis)
		}
	}
}

// extractMethod records one `def` and the calls in its body.
func (p *RubyParser) extractMethod(node *sitter.Node, src []byte, filePath, packagePath, namespace string, analysis *FileAnalysis) {
	name := rubyMethodName(node, src)
	if name == "" {
		return
	}
	fn := FunctionDecl{
		ID:        FunctionID{Package: packagePath, Type: namespace, Name: name},
		FilePath:  filePath,
		StartLine: int(node.StartPoint().Row) + 1,
		EndLine:   int(node.EndPoint().Row) + 1,
		StartCol:  int(node.StartPoint().Column) + 1,
		EndCol:    int(node.EndPoint().Column) + 1,
		OwnerType: namespace,
		Static:    node.Type() == rubyNodeSingletonMethod,
	}
	p.walk(node, src, filePath, packagePath, namespace, &fn, analysis)
	analysis.Functions = append(analysis.Functions, fn)
}

// callOf reads one call node. A receiver written as a constant path
// (`OpenSSL::HMAC.hexdigest`) qualifies the callee with it; a receiver that is
// a local (`cipher.encrypt`) is kept caller-local in ReceiverVar, for the
// builder to resolve from the assignment that bound it.
func (p *RubyParser) callOf(node *sitter.Node, src []byte, filePath string) (FunctionCall, bool) {
	name := rubyCallName(node, src)
	if name == "" || name == rubyRequire || name == rubyRequireRelative {
		return FunctionCall{}, false
	}
	call := FunctionCall{
		Callee:   FunctionID{Name: name},
		Raw:      node.Content(src),
		FilePath: filePath,
		Line:     int(node.StartPoint().Row) + 1,
		EndLine:  int(node.EndPoint().Row) + 1,
		StartCol: int(node.StartPoint().Column) + 1,
		EndCol:   int(node.EndPoint().Column) + 1,
	}
	if receiver := node.ChildByFieldName("receiver"); receiver != nil {
		switch receiver.Type() {
		case rubyNodeScopeResolution, rubyNodeConstant:
			call.Callee.Type = receiver.Content(src)
		case rubyNodeIdentifier:
			call.ReceiverVar = receiver.Content(src)
		default:
			call.ReceiverVar = receiver.Content(src)
		}
	}
	if parent := node.Parent(); parent != nil && parent.Type() == rubyNodeAssignment {
		if target := parent.ChildByFieldName("left"); target != nil && target.Type() == rubyNodeIdentifier {
			call.AssignedVar = target.Content(src)
		}
	}
	return call, true
}

// rubyCallName is the method a call names, with no receiver.
func rubyCallName(node *sitter.Node, src []byte) string {
	if method := node.ChildByFieldName("method"); method != nil {
		return method.Content(src)
	}
	return ""
}

// rubyFirstStringArgument is the content of the first string argument, which
// is what a `require` names.
func rubyFirstStringArgument(node *sitter.Node, src []byte) string {
	args := node.ChildByFieldName("arguments")
	if args == nil {
		return ""
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		if arg := args.NamedChild(i); arg.Type() == rubyNodeString {
			for j := 0; j < int(arg.NamedChildCount()); j++ {
				if part := arg.NamedChild(j); part.Type() == rubyNodeStringContent {
					return part.Content(src)
				}
			}
		}
	}
	return ""
}

// rubyDeclaredName is the name a `class` or `module` declares.
func rubyDeclaredName(node *sitter.Node, src []byte) string {
	if name := node.ChildByFieldName("name"); name != nil {
		return name.Content(src)
	}
	return ""
}

// rubyMethodName is the name a `def` declares. A singleton method
// (`def self.sign`) names the method only: its owner is the enclosing class.
func rubyMethodName(node *sitter.Node, src []byte) string {
	if name := node.ChildByFieldName("name"); name != nil {
		return name.Content(src)
	}
	return ""
}

// rubyJoin nests a namespace segment under its parent.
func rubyJoin(parent, name string) string {
	if parent == "" {
		return name
	}
	return parent + "::" + name
}

// ParseDirectory parses every Ruby file of a directory.
func (p *RubyParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
	return p.ParseDirectorySelected(dir, packagePath, nil)
}

// ParseDirectorySelected implements SelectiveParser.
func (p *RubyParser) ParseDirectorySelected(dir, packagePath string, keep func(path string) bool) ([]*FileAnalysis, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading directory %s: %w", dir, err)
	}
	analyses := make([]*FileAnalysis, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rb") {
			continue
		}
		if !p.includeTests && rubyTestFile(entry.Name()) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if keep != nil && !keep(path) {
			continue
		}
		analysis, err := p.ParseFile(path, packagePath)
		if err != nil {
			continue // one unreadable file does not fail the directory
		}
		analyses = append(analyses, analysis)
	}
	return analyses, nil
}

// rubyTestFile reports the two names a Ruby test file is given, so a scan that
// does not include tests skips them wherever they sit.
func rubyTestFile(name string) bool {
	return strings.HasSuffix(name, "_spec.rb") || strings.HasSuffix(name, "_test.rb")
}
