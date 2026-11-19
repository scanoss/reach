// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"context"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"strings"

	"github.com/rs/zerolog/log"
	sitter "github.com/smacker/go-tree-sitter"
	treecsharp "github.com/smacker/go-tree-sitter/csharp"
)

const (
	csharpNodeUsingDirective      = "using_directive"
	csharpNodeNamespace           = "namespace_declaration"
	csharpNodeFileNamespace       = "file_scoped_namespace_declaration"
	csharpNodeClass               = "class_declaration"
	csharpNodeStruct              = "struct_declaration"
	csharpNodeInterface           = "interface_declaration"
	csharpNodeRecord              = "record_declaration"
	csharpNodeRecordStruct        = "record_struct_declaration"
	csharpNodeMethod              = "method_declaration"
	csharpNodeConstructor         = "constructor_declaration"
	csharpNodeInvocation          = "invocation_expression"
	csharpNodeMemberAccess        = "member_access_expression"
	csharpNodeObjectCreation      = "object_creation_expression"
	csharpNodeArgument            = "argument"
	csharpNodeIdentifier          = "identifier"
	csharpNodeQualifiedName       = "qualified_name"
	csharpNodeGenericName         = "generic_name"
	csharpNodeVariableDeclaration = "variable_declaration"
	csharpNodeVariableDeclarator  = "variable_declarator"
	csharpNodeAssignment          = "assignment_expression"
	csharpNodeBlock               = "block"
	csharpNodeFieldDeclaration    = "field_declaration"
	csharpNodeProperty            = "property_declaration"
	csharpNodeLocalDeclaration    = "local_declaration_statement"
	csharpNodeArrowClause         = "arrow_expression_clause"
	csharpNodeStringLiteral       = "string_literal"
	csharpNodeVerbatimString      = "verbatim_string_literal"
	csharpNodeImplicitType        = "implicit_type"
	csharpSeparator               = "."
)

// CSharpParser extracts C# declarations, calls and using directives.
type CSharpParser struct {
	parser       *sitter.Parser
	includeTests bool
	anchors      callAnchors
}

// NewCSharpParser creates a C# source parser backed by tree-sitter.
func NewCSharpParser(opts ...ParserOption) *CSharpParser {
	cfg := newParserConfig(opts)
	parser := sitter.NewParser()
	parser.SetLanguage(treecsharp.GetLanguage())
	return &CSharpParser{parser: parser, includeTests: cfg.includeTests}
}

// CloneParser returns an independent parser for concurrent use.
func (p *CSharpParser) CloneParser() Parser {
	return NewCSharpParser(WithIncludeTests(p.includeTests))
}

// PackageSeparator is the C# namespace separator.
func (p *CSharpParser) PackageSeparator() string { return csharpSeparator }

// SubPackagePath nests a directory under its parent namespace: the project
// layout a C# solution uses by convention. A file's declared namespace always
// wins over it, so this only names files that declare none.
func (p *CSharpParser) SubPackagePath(parentPath, dirName string) string {
	if parentPath == "" {
		return dirName
	}
	return parentPath + csharpSeparator + dirName
}

// ParseDirectory parses the C# sources directly under dir.
func (p *CSharpParser) ParseDirectory(dir, packagePath string) ([]*FileAnalysis, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("callgraph: csharp parser: read directory %s: %w", dir, err)
	}
	analyses := make([]*FileAnalysis, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || strings.ToLower(filepath.Ext(entry.Name())) != ".cs" {
			continue
		}
		if !p.includeTests && csharpIsTestFile(entry.Name()) {
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

// csharpIsTestFile reports the .NET naming conventions for a test file, and
// the `.test.cs` spelling the rule fixtures use.
func csharpIsTestFile(name string) bool {
	lower := strings.ToLower(name)
	if strings.Contains(lower, ".test.") || strings.Contains(lower, ".tests.") {
		return true
	}
	base := strings.TrimSuffix(lower, ".cs")
	return strings.HasSuffix(base, "test") || strings.HasSuffix(base, "tests")
}

func (p *CSharpParser) parseFile(filePath, packagePath string) (*FileAnalysis, error) {
	src, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("callgraph: csharp parser: read %s: %w", filePath, err)
	}
	tree, err := p.parser.ParseCtx(context.TODO(), nil, src)
	if err != nil {
		return nil, fmt.Errorf("callgraph: csharp parser: parse %s: %w", filePath, err)
	}
	defer tree.Close()
	defer p.anchors.reset()

	analysis := &FileAnalysis{
		FilePath:      filePath,
		PackageName:   packagePath,
		PackagePath:   packagePath,
		Imports:       make(map[string]string),
		ImportAliases: make(map[string]string),
		ClassBases:    make(map[string][]string),
		NamedValues:   make(map[string]NamedValue),
		Supertypes:    make(map[string][]string),
	}
	root := tree.RootNode()
	p.collectUsings(root, src, analysis)
	// A file that declares a namespace is keyed by it, as a Java file is keyed
	// by its package: the directory it sits in names nothing a caller writes.
	if ns := csharpFirstNamespace(root, src); ns != "" {
		analysis.PackageName, analysis.PackagePath = ns, ns
	}
	// The walk starts on the directory's path: a file that declares no
	// namespace keeps it, and the first declaration replaces it.
	p.walk(root, src, filePath, packagePath, "", false, analysis)
	recordCSharpOwnerAlternatives(analysis)
	return analysis, nil
}

// csharpFirstNamespace names the namespace a file declares, block-scoped or
// file-scoped. A file declaring several keeps the first as its own; each
// declaration still keys its own types (walk carries the namespace down).
func csharpFirstNamespace(node *sitter.Node, src []byte) string {
	switch node.Type() {
	case csharpNodeNamespace, csharpNodeFileNamespace:
		if name := node.ChildByFieldName("name"); name != nil {
			return name.Content(src)
		}
		return ""
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if ns := csharpFirstNamespace(node.Child(i), src); ns != "" {
			return ns
		}
	}
	return ""
}

// collectUsings reads the file's using directives. A plain `using N;` imports
// every type of a namespace, the shape C# uses where Java writes a type
// import, so it is recorded as an on-demand import; `using A = N.T;` binds a
// name that stands for a path, and `using static N.T;` opens a type's statics.
func (p *CSharpParser) collectUsings(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	if node.Type() == csharpNodeUsingDirective {
		csharpUsing(node, src, analysis)
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.collectUsings(node.Child(i), src, analysis)
	}
}

func csharpUsing(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	alias := ""
	if name := node.ChildByFieldName("name"); name != nil {
		alias = name.Content(src)
	}
	isStatic, isGlobal := false, false
	var path string
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		switch child.Type() {
		case "static":
			isStatic = true
		case "global":
			isGlobal = true
		case csharpNodeQualifiedName, csharpNodeIdentifier, "alias_qualified_name", csharpNodeGenericName:
			if node.FieldNameForChild(i) == "name" {
				continue
			}
			path = child.Content(src)
		}
	}
	if path == "" {
		return
	}
	kind := csharpUsingNamespace
	switch {
	case alias != "":
		kind = csharpUsingAlias
		analysis.ImportAliases[alias] = path
		analysis.Imports[alias] = path
	case isStatic:
		kind = csharpUsingStatic
		analysis.StaticWildcardImports = append(analysis.StaticWildcardImports, path)
	default:
		analysis.WildcardImports = append(analysis.WildcardImports, path)
	}
	start, end := node.StartPoint(), node.EndPoint()
	using := CSharpUsing{
		Namespace: path, Alias: alias, Kind: kind, Global: isGlobal,
		Line: int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
		Text: node.Content(src),
	}
	if end.Row != start.Row {
		using.EndLine = int(end.Row) + 1
	}
	analysis.CSharpUsings = append(analysis.CSharpUsings, using)
}

// The kinds of using directive a C# file writes. A matcher reads them to
// qualify a type the source writes unqualified, the way the reference
// matcher resolves a using.
const (
	csharpUsingNamespace = "using"
	csharpUsingAlias     = "alias"
	csharpUsingStatic    = "static"
)

// CSharpUsing is one using directive of a C# file, with the span of the
// directive as written. Namespace is the path it brings in: the namespace of
// a plain using, the path an alias stands for, the type a static using opens.
type CSharpUsing struct {
	Namespace, Alias, Kind, Text    string
	Global                          bool
	Line, StartCol, EndCol, EndLine int
}

func (p *CSharpParser) walk(node *sitter.Node, src []byte, filePath, namespace, typePath string, declared bool, analysis *FileAnalysis) {
	switch node.Type() {
	case csharpNodeNamespace:
		// A declaration is absolute unless it nests inside another: C# nests
		// `namespace A { namespace B {} }` as A.B and nothing else.
		if name := node.ChildByFieldName("name"); name != nil {
			if declared {
				namespace = csharpJoin(namespace, name.Content(src))
			} else {
				namespace = name.Content(src)
			}
			declared = true
		}
	case csharpNodeClass, csharpNodeStruct, csharpNodeInterface, csharpNodeRecord, csharpNodeRecordStruct:
		if name := node.ChildByFieldName("name"); name != nil {
			typePath = csharpJoin(typePath, name.Content(src))
			csharpRecordBases(node, src, namespace, typePath, analysis)
			if decl := p.parseClassInitializer(node, src, filePath, namespace, typePath, analysis); decl != nil {
				analysis.Functions = append(analysis.Functions, *decl)
			}
		}
	case csharpNodeMethod, csharpNodeConstructor, csharpNodeProperty:
		if decl := p.parseFunction(node, src, filePath, namespace, typePath, analysis); decl != nil {
			analysis.Functions = append(analysis.Functions, *decl)
		}
		return
	case csharpNodeFieldDeclaration:
		csharpRecordFieldValues(node, src, namespace, typePath, analysis)
	}
	// A file-scoped namespace leaves the declarations it covers as its
	// siblings, so its scope carries forward across them rather than nesting.
	childNamespace, childDeclared := namespace, declared
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == csharpNodeFileNamespace {
			if name := child.ChildByFieldName("name"); name != nil {
				childNamespace, childDeclared = name.Content(src), true
			}
			continue
		}
		p.walk(child, src, filePath, childNamespace, typePath, childDeclared, analysis)
	}
}

// csharpJoin appends a segment to a dotted path. A namespace written as
// `A.B` in a nested declaration keeps its dots.
func csharpJoin(prefix, segment string) string {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return prefix
	}
	if prefix == "" {
		return segment
	}
	return prefix + csharpSeparator + segment
}

// csharpRecordBases records a type's base list as its supertypes, erased to
// the names the source writes: the graph resolves them against the file's
// usings as it does for a call's owner.
func csharpRecordBases(node *sitter.Node, src []byte, namespace, typePath string, analysis *FileAnalysis) {
	bases := []string{}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() != "base_list" {
			continue
		}
		for j := 0; j < int(child.NamedChildCount()); j++ {
			if name := csharpTypeName(child.NamedChild(j), src); name != "" {
				bases = append(bases, name)
			}
		}
	}
	analysis.ClassBases[typePath] = bases
	// The key is stored even with no base list: its presence records that the
	// file declares the type, which is what settles a guessed owner.
	analysis.Supertypes[csharpJoin(namespace, typePath)] = bases
}

// csharpRecordFieldValues records the string constants a type declares, under
// the name a use spells them with: `Algorithms.Name` for a field of a type,
// so a rule reading a constant argument can follow it.
func csharpRecordFieldValues(node *sitter.Node, src []byte, namespace, typePath string, analysis *FileAnalysis) {
	declaration := csharpChildByType(node, csharpNodeVariableDeclaration)
	if declaration == nil {
		return
	}
	for i := 0; i < int(declaration.NamedChildCount()); i++ {
		declarator := declaration.NamedChild(i)
		if declarator.Type() != csharpNodeVariableDeclarator {
			continue
		}
		name := declarator.ChildByFieldName("name")
		if name == nil {
			continue
		}
		value, ok := csharpStringValue(declarator, src)
		if !ok {
			continue
		}
		key := csharpJoin(csharpJoin(namespace, typePath), name.Content(src))
		analysis.NamedValues[key] = NamedValue{
			Value:    value,
			FilePath: analysis.FilePath,
			Line:     int(declarator.StartPoint().Row) + 1,
		}
	}
}

// csharpStringValue is the string a declarator initializes its name with.
func csharpStringValue(declarator *sitter.Node, src []byte) (string, bool) {
	for i := 0; i < int(declarator.NamedChildCount()); i++ {
		child := declarator.NamedChild(i)
		switch child.Type() {
		case csharpNodeStringLiteral, csharpNodeVerbatimString:
			return csharpStringContent(child, src), true
		}
	}
	return "", false
}

func csharpStringContent(node *sitter.Node, src []byte) string {
	text := node.Content(src)
	text = strings.TrimPrefix(text, "@")
	return strings.Trim(text, `"`)
}

func (p *CSharpParser) parseFunction(node *sitter.Node, src []byte, filePath, namespace, typePath string, analysis *FileAnalysis) *FunctionDecl {
	name := csharpFunctionName(node, src)
	body := node.ChildByFieldName("body")
	if name == "" {
		return nil
	}
	parameters := csharpParameters(node.ChildByFieldName("parameters"), src)
	decl := &FunctionDecl{
		ID:           FunctionID{Package: namespace, Type: typePath, Name: csharpMethodWithArity(name, len(parameters))},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		StartCol:     int(node.StartPoint().Column) + 1,
		EndCol:       int(node.EndPoint().Column) + 1,
		OwnerType:    "class",
		OwnerName:    csharpJoin(namespace, typePath),
		FunctionType: "method",
		Static:       csharpHasModifier(node, src, "static"),
		Parameters:   parameters,
		ReturnType:   csharpReturnType(node, src),
	}
	if node.Type() == csharpNodeConstructor {
		decl.FunctionType = "constructor"
	}
	variableTypes := make(map[string]string, len(parameters))
	for _, parameter := range parameters {
		if parameter.Name != "" && parameter.Type != "" {
			variableTypes[parameter.Name] = parameter.Type
		}
	}
	if body == nil {
		// An expression-bodied member (`=> SHA256.Create()`) has no block; its
		// arrow clause holds the calls, and a property its accessor list.
		body = csharpChildByType(node, csharpNodeArrowClause)
	}
	if body == nil {
		body = csharpChildByType(node, "accessor_list")
	}
	if body == nil {
		return decl
	}
	p.walkCalls(body, src, filePath, namespace, typePath, variableTypes, analysis, &decl.Calls)
	decl.Declarations = csharpDeclarations(body, src)
	return decl
}

// parseClassInitializer collects the calls a type's field initializers make
// into one synthetic declaration, as Java's class initializer does: a
// `private static readonly SHA256 H = SHA256.Create();` is a call of the type,
// made outside any method body.
func (p *CSharpParser) parseClassInitializer(node *sitter.Node, src []byte, filePath, namespace, typePath string, analysis *FileAnalysis) *FunctionDecl {
	body := node.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	var calls []FunctionCall
	variableTypes := map[string]string{}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		field := body.NamedChild(i)
		if field.Type() != csharpNodeFieldDeclaration {
			continue
		}
		p.walkCalls(field, src, filePath, namespace, typePath, variableTypes, analysis, &calls)
	}
	if len(calls) == 0 {
		return nil
	}
	return &FunctionDecl{
		ID:           FunctionID{Package: namespace, Type: typePath, Name: csharpMethodWithArity(clinitMethodName, 0)},
		FilePath:     filePath,
		StartLine:    int(node.StartPoint().Row) + 1,
		EndLine:      int(node.EndPoint().Row) + 1,
		StartCol:     int(node.StartPoint().Column) + 1,
		EndCol:       int(node.EndPoint().Column) + 1,
		OwnerType:    "class",
		OwnerName:    csharpJoin(namespace, typePath),
		FunctionType: "method",
		Static:       true,
		Calls:        calls,
	}
}

// csharpFunctionName is the declared name, or the constructor name the graph
// keys a `new T(..)` call with.
func csharpFunctionName(node *sitter.Node, src []byte) string {
	if node.Type() == csharpNodeConstructor {
		return constructorMethodName
	}
	name := node.ChildByFieldName("name")
	if name == nil {
		return ""
	}
	return name.Content(src)
}

// csharpMethodWithArity is the key spelling of a method: every function key
// of a graph carries the arity its call site writes.
func csharpMethodWithArity(name string, arity int) string {
	if name == "" {
		return name
	}
	return fmt.Sprintf("%s#%d", name, arity)
}

func csharpReturnType(node *sitter.Node, src []byte) string {
	returns := node.ChildByFieldName("returns")
	if returns == nil || returns.Type() == csharpNodeImplicitType {
		return ""
	}
	return strings.TrimSpace(returns.Content(src))
}

func csharpHasModifier(node *sitter.Node, src []byte, modifier string) bool {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if child.Type() == "modifier" && child.Content(src) == modifier {
			return true
		}
	}
	return false
}

func csharpParameters(list *sitter.Node, src []byte) []FunctionParameter {
	if list == nil {
		return nil
	}
	var parameters []FunctionParameter
	for i := 0; i < int(list.NamedChildCount()); i++ {
		parameter := list.NamedChild(i)
		if parameter.Type() != "parameter" {
			continue
		}
		name, typeName := parameter.ChildByFieldName("name"), parameter.ChildByFieldName("type")
		entry := FunctionParameter{}
		if name != nil {
			entry.Name = name.Content(src)
		}
		if typeName != nil {
			entry.Type = strings.TrimSpace(typeName.Content(src))
		}
		parameters = append(parameters, entry)
	}
	return parameters
}

// csharpDeclarations lists a body's local declarations with their span, the
// scope fact a syntactic matcher reads beside the calls.
func csharpDeclarations(body *sitter.Node, src []byte) []VarDecl {
	var out []VarDecl
	csharpWalk(body, func(node *sitter.Node) {
		if node.Type() != csharpNodeLocalDeclaration {
			return
		}
		declaration := csharpChildByType(node, csharpNodeVariableDeclaration)
		if declaration == nil {
			return
		}
		typeNode := declaration.ChildByFieldName("type")
		typeName := ""
		if typeNode != nil && typeNode.Type() != csharpNodeImplicitType {
			typeName = strings.TrimSpace(typeNode.Content(src))
		}
		start, end := node.StartPoint(), node.EndPoint()
		for i := 0; i < int(declaration.NamedChildCount()); i++ {
			declarator := declaration.NamedChild(i)
			if declarator.Type() != csharpNodeVariableDeclarator {
				continue
			}
			name := declarator.ChildByFieldName("name")
			if name == nil {
				continue
			}
			decl := VarDecl{
				Type: typeName, Name: name.Content(src),
				Line: int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
			}
			if end.Row != start.Row {
				decl.EndLine = int(end.Row) + 1
			}
			out = append(out, decl)
		}
	})
	return out
}

func csharpWalk(node *sitter.Node, visit func(*sitter.Node)) {
	if node == nil {
		return
	}
	visit(node)
	for i := 0; i < int(node.ChildCount()); i++ {
		csharpWalk(node.Child(i), visit)
	}
}

func csharpChildByType(node *sitter.Node, kind string) *sitter.Node {
	if node == nil {
		return nil
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		if child := node.Child(i); child.Type() == kind {
			return child
		}
	}
	return nil
}

func (p *CSharpParser) walkCalls(node *sitter.Node, src []byte, filePath, namespace, typePath string, variableTypes map[string]string, analysis *FileAnalysis, calls *[]FunctionCall) {
	if csharpIntroducesScope(node.Type()) {
		variableTypes = maps.Clone(variableTypes)
	}
	if node.Type() == csharpNodeLocalDeclaration {
		csharpRecordDeclaredTypes(node, src, variableTypes)
	}
	switch node.Type() {
	case csharpNodeInvocation:
		if call := p.parseInvocation(node, src, filePath, namespace, typePath, variableTypes, analysis); call != nil {
			p.anchors.set(call, node)
			*calls = append(*calls, *call)
		}
	case csharpNodeObjectCreation:
		if call := p.parseObjectCreation(node, src, filePath, namespace, analysis); call != nil {
			p.anchors.set(call, node)
			*calls = append(*calls, *call)
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkCalls(node.Child(i), src, filePath, namespace, typePath, variableTypes, analysis, calls)
	}
}

func csharpIntroducesScope(kind string) bool {
	switch kind {
	case csharpNodeBlock, "if_statement", "switch_statement", "for_statement", "for_each_statement", "while_statement", "do_statement", "catch_clause", "using_statement", lambdaExpressionNode:
		return true
	default:
		return false
	}
}

// csharpRecordDeclaredTypes types the locals a declaration binds. A `var`
// declaration takes the type of the constructor it is initialized with, the
// one shape C# infers that a rule anchors on.
func csharpRecordDeclaredTypes(node *sitter.Node, src []byte, types map[string]string) {
	declaration := csharpChildByType(node, csharpNodeVariableDeclaration)
	if declaration == nil {
		return
	}
	typeNode := declaration.ChildByFieldName("type")
	declared := ""
	if typeNode != nil && typeNode.Type() != csharpNodeImplicitType {
		declared = csharpTypeName(typeNode, src)
	}
	for i := 0; i < int(declaration.NamedChildCount()); i++ {
		declarator := declaration.NamedChild(i)
		if declarator.Type() != csharpNodeVariableDeclarator {
			continue
		}
		name := declarator.ChildByFieldName("name")
		if name == nil {
			continue
		}
		typeName := declared
		if typeName == "" {
			typeName = csharpInferredType(declarator, src)
		}
		if typeName != "" {
			types[name.Content(src)] = typeName
		}
	}
}

// csharpInferredType is the type a `var` declarator's initializer gives it:
// a constructed type today, which is what `var e = new SM4Engine()` needs.
func csharpInferredType(declarator *sitter.Node, src []byte) string {
	for i := 0; i < int(declarator.NamedChildCount()); i++ {
		child := declarator.NamedChild(i)
		if child.Type() == csharpNodeObjectCreation {
			return csharpTypeName(child.ChildByFieldName("type"), src)
		}
	}
	return ""
}

// csharpTypeName is a type as the source writes it, without its generic
// arguments: `List<T>` is List, `N.T<X>` is N.T. Generic arguments never name
// the owner of a call.
func csharpTypeName(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	switch node.Type() {
	case csharpNodeGenericName:
		if name := node.ChildByFieldName("name"); name != nil {
			return name.Content(src)
		}
		return ""
	case csharpNodeQualifiedName:
		qualifier, name := node.ChildByFieldName("qualifier"), node.ChildByFieldName("name")
		if qualifier == nil || name == nil {
			return strings.TrimSpace(node.Content(src))
		}
		return csharpJoin(csharpTypeName(qualifier, src), csharpTypeName(name, src))
	case "nullable_type", "array_type":
		return csharpTypeName(node.ChildByFieldName("type"), src)
	}
	return strings.TrimSpace(node.Content(src))
}

func (p *CSharpParser) parseInvocation(node *sitter.Node, src []byte, filePath, namespace, typePath string, variableTypes map[string]string, analysis *FileAnalysis) *FunctionCall {
	function := node.ChildByFieldName("function")
	if function == nil {
		return nil
	}
	call := &FunctionCall{
		Callee:      FunctionID{Package: namespace},
		Raw:         function.Content(src),
		FilePath:    filePath,
		Line:        int(node.StartPoint().Row) + 1,
		EndLine:     int(node.EndPoint().Row) + 1,
		StartCol:    int(node.StartPoint().Column) + 1,
		EndCol:      int(node.EndPoint().Column) + 1,
		Arguments:   csharpArguments(node.ChildByFieldName("arguments"), src),
		AssignedVar: csharpAssignedVar(node, src),
		ChainID:     csharpChainID(node),
	}
	switch function.Type() {
	case csharpNodeIdentifier, csharpNodeGenericName:
		// A bare call is a method of the type that declares the caller.
		call.Callee.Name = csharpTypeName(function, src)
		call.Callee.Type = typePath
	case csharpNodeMemberAccess:
		name := function.ChildByFieldName("name")
		receiver := function.ChildByFieldName("expression")
		if name == nil || receiver == nil {
			return nil
		}
		call.Callee.Name = csharpTypeName(name, src)
		p.resolveReceiver(call, receiver, src, namespace, typePath, variableTypes, analysis)
	default:
		return nil
	}
	if call.Callee.Name == "" {
		return nil
	}
	call.Callee.Name = csharpMethodWithArity(call.Callee.Name, len(call.Arguments))
	return call
}

// resolveReceiver types a member call's receiver: a local the body declared,
// `this`, a constructor the call is chained on, or a type name the file's
// usings qualify.
func (p *CSharpParser) resolveReceiver(call *FunctionCall, receiver *sitter.Node, src []byte, namespace, typePath string, variableTypes map[string]string, analysis *FileAnalysis) {
	switch receiver.Type() {
	case csharpNodeIdentifier:
		text := receiver.Content(src)
		if declared, ok := variableTypes[text]; ok {
			call.ReceiverVar = text
			call.Callee.Type = declared
			call.Callee.Package = csharpOwnerNamespace(declared, namespace, analysis)
			call.Callee.Type = csharpSimpleName(declared)
			return
		}
		call.StaticReceiver = true
		call.Callee.Type = text
		call.Callee.Package = csharpOwnerNamespace(text, namespace, analysis)
	case "this_expression":
		call.Callee.Type = typePath
		call.Callee.Package = namespace
	case csharpNodeMemberAccess, csharpNodeQualifiedName:
		// A dotted receiver is a qualified type (`N.M.T.Create()`) unless its
		// head is a local: the parser keeps the written path and the graph
		// splits it on the namespace the file knows.
		written := csharpTypeName(receiver, src)
		if head, _, ok := strings.Cut(written, csharpSeparator); ok {
			if declared, isLocal := variableTypes[head]; isLocal {
				call.ReceiverVar = head
				call.Callee.Type = csharpSimpleName(declared)
				call.Callee.Package = csharpOwnerNamespace(declared, namespace, analysis)
				return
			}
		}
		call.StaticReceiver = true
		call.Callee.Type = csharpSimpleName(written)
		call.Callee.Package = csharpOwnerNamespace(written, namespace, analysis)
	case csharpNodeObjectCreation:
		call.Callee.Type = csharpSimpleName(csharpTypeName(receiver.ChildByFieldName("type"), src))
		call.Callee.Package = csharpOwnerNamespace(csharpTypeName(receiver.ChildByFieldName("type"), src), namespace, analysis)
	case csharpNodeInvocation:
		// A fluent link keeps the caller's namespace and no owner: the type
		// resolver binds it from what the previous link returns.
		call.Callee.Package = namespace
	default:
		call.Callee.Package = namespace
	}
}

func (p *CSharpParser) parseObjectCreation(node *sitter.Node, src []byte, filePath, namespace string, analysis *FileAnalysis) *FunctionCall {
	written := csharpTypeName(node.ChildByFieldName("type"), src)
	if written == "" {
		return nil
	}
	arguments := csharpArguments(node.ChildByFieldName("arguments"), src)
	return &FunctionCall{
		Callee: FunctionID{
			Package: csharpOwnerNamespace(written, namespace, analysis),
			Type:    csharpSimpleName(written),
			Name:    csharpMethodWithArity(constructorMethodName, len(arguments)),
		},
		Raw:            node.Content(src),
		FilePath:       filePath,
		Line:           int(node.StartPoint().Row) + 1,
		EndLine:        int(node.EndPoint().Row) + 1,
		StartCol:       int(node.StartPoint().Column) + 1,
		EndCol:         int(node.EndPoint().Column) + 1,
		Arguments:      arguments,
		AssignedVar:    csharpAssignedVar(node, src),
		StaticReceiver: true,
	}
}

// csharpSimpleName is a written type's last segment: the name the graph keys a
// type with, its namespace held in the callee's package.
func csharpSimpleName(written string) string {
	if idx := strings.LastIndex(written, csharpSeparator); idx >= 0 {
		return written[idx+1:]
	}
	return written
}

// csharpOwnerNamespace is the namespace a written type name belongs to: the
// qualifier it carries, the path an alias stands for, or the caller's own
// namespace when the name is unqualified. An unqualified name resolved through
// an on-demand using is settled graph-wide from OwnerAlternatives.
func csharpOwnerNamespace(written, namespace string, analysis *FileAnalysis) string {
	expanded := csharpExpandAlias(written, analysis)
	if idx := strings.LastIndex(expanded, csharpSeparator); idx >= 0 {
		return expanded[:idx]
	}
	return namespace
}

// csharpExpandAlias substitutes the path a `using A = N.M;` alias stands for
// at the head of a written name, so `A.T` reads as `N.M.T`.
func csharpExpandAlias(written string, analysis *FileAnalysis) string {
	head, rest, dotted := strings.Cut(written, csharpSeparator)
	path, aliased := analysis.ImportAliases[head]
	if !aliased {
		return written
	}
	if !dotted {
		return path
	}
	return csharpJoin(path, rest)
}

func csharpArguments(list *sitter.Node, src []byte) []string {
	if list == nil {
		return nil
	}
	var arguments []string
	for i := 0; i < int(list.NamedChildCount()); i++ {
		argument := list.NamedChild(i)
		if argument.Type() != csharpNodeArgument {
			continue
		}
		arguments = append(arguments, strings.TrimSpace(argument.Content(src)))
	}
	return arguments
}

// csharpAssignedVar names the local a call's result is bound to, the identity
// a rule follows from a constructor to the calls made on the object.
func csharpAssignedVar(node *sitter.Node, src []byte) string {
	parent := node.Parent()
	if parent == nil {
		return ""
	}
	switch parent.Type() {
	case csharpNodeVariableDeclarator:
		if name := parent.ChildByFieldName("name"); name != nil {
			return name.Content(src)
		}
	case csharpNodeAssignment:
		left, right := parent.ChildByFieldName("left"), parent.ChildByFieldName("right")
		if left != nil && right != nil && sameSyntaxNode(right, node) && left.Type() == csharpNodeIdentifier {
			return left.Content(src)
		}
	}
	return ""
}

// csharpChainID groups the links of a fluent chain under the byte offset of
// its root call, so a rule can enumerate the chain a finding sits in.
func csharpChainID(node *sitter.Node) string {
	root := node
	for {
		member := root.Parent()
		if member == nil || member.Type() != csharpNodeMemberAccess || !sameSyntaxNode(member.ChildByFieldName("expression"), root) {
			break
		}
		call := member.Parent()
		if call == nil || call.Type() != csharpNodeInvocation || !sameSyntaxNode(call.ChildByFieldName("function"), member) {
			break
		}
		root = call
	}
	if sameSyntaxNode(root, node) {
		function := node.ChildByFieldName("function")
		if function == nil || function.Type() != csharpNodeMemberAccess {
			return ""
		}
		if receiver := function.ChildByFieldName("expression"); receiver == nil || receiver.Type() != csharpNodeInvocation {
			return ""
		}
	}
	return fmt.Sprintf("%d", root.StartByte())
}

// recordCSharpOwnerAlternatives marks each call whose owner namespace the
// parser guessed. C# writes every type through an on-demand using, so an
// unqualified owner is keyed on the file's own namespace and the graph
// settles it against the usings.
func recordCSharpOwnerAlternatives(analysis *FileAnalysis) {
	if len(analysis.WildcardImports) == 0 {
		return
	}
	for i := range analysis.Functions {
		calls := analysis.Functions[i].Calls
		for j := range calls {
			calls[j].OwnerAlternatives = csharpOwnerAlternatives(calls[j].Callee, analysis)
		}
	}
}

func csharpOwnerAlternatives(callee FunctionID, analysis *FileAnalysis) []string {
	typ := callee.Type
	if typ == "" || strings.ContainsAny(typ, ".<>[]()") {
		return nil
	}
	if _, declared := analysis.ClassBases[typ]; declared {
		return nil
	}
	if callee.Package != analysis.PackagePath {
		return nil
	}
	alternatives := []string{csharpJoin(analysis.PackagePath, typ)}
	for _, wildcard := range analysis.WildcardImports {
		alternatives = append(alternatives, wildcard+csharpSeparator+typ)
	}
	return alternatives
}
