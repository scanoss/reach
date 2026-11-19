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
	csharpNodeUsingStatement      = "using_statement"
	csharpNodeGlobalStatement     = "global_statement"
	csharpNodeLocalFunction       = "local_function_statement"
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

// csharpIsTestFile reports a file named as a test, the `.test.cs` spelling
// the rule fixtures use. A `FooTests.cs` is not one: .NET puts its tests in a
// project of their own rather than in a suffix, the name is ordinary source
// to every other scanner, and skipping it lost real findings on the
// real-code corpus.
func csharpIsTestFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, ".test.") || strings.Contains(lower, ".tests.")
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
	p.walk(root, src, filePath, packagePath, "", "", false, nil, analysis)
	if decl := p.parseTopLevelProgram(root, src, filePath, analysis.PackagePath, analysis); decl != nil {
		analysis.Functions = append(analysis.Functions, *decl)
	}
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

func (p *CSharpParser) walk(node *sitter.Node, src []byte, filePath, namespace, typePath, ownerType string, declared bool, fields *csharpFields, analysis *FileAnalysis) {
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
			// An interface's methods are the dispatch the graph expands to
			// the types that implement them, so the kind is kept.
			ownerType = "class"
			if node.Type() == csharpNodeInterface {
				ownerType = ownerTypeInterface
			}
			csharpRecordBases(node, src, namespace, typePath, analysis)
			fields = csharpFieldFacts(node, src)
			p.readFieldInitializers(node, src, filePath, namespace, typePath, fields, analysis)
			analysis.Functions = append(analysis.Functions,
				p.parseClassInitializer(node, src, filePath, namespace, typePath, fields, analysis)...)
		}
	case csharpNodeMethod, csharpNodeConstructor, csharpNodeProperty:
		if decl := p.parseFunction(node, src, filePath, namespace, typePath, ownerType, fields, analysis); decl != nil {
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
		p.walk(child, src, filePath, childNamespace, typePath, ownerType, childDeclared, fields, analysis)
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
	// file declares the type, which is what settles a guessed owner. A base is
	// written unqualified, so it is listed under every namespace that could
	// declare it, as Java lists a type of an on-demand import.
	analysis.Supertypes[csharpJoin(namespace, typePath)] = csharpQualifiedBases(bases, namespace, analysis)
}

// csharpQualifiedBases qualifies each base a type names: with the namespace
// it is written in, and with each namespace a using brings in. A base already
// written qualified is kept as it is.
func csharpQualifiedBases(bases []string, namespace string, analysis *FileAnalysis) []string {
	out := make([]string, 0, len(bases))
	for _, base := range bases {
		if strings.Contains(base, csharpSeparator) {
			out = append(out, csharpExpandBaseAlias(base, analysis))
			continue
		}
		out = append(out, csharpJoin(namespace, base))
		for _, wildcard := range analysis.WildcardImports {
			out = append(out, wildcard+csharpSeparator+base)
		}
	}
	return out
}

// csharpExpandBaseAlias substitutes a using alias at the head of a written
// base name.
func csharpExpandBaseAlias(base string, analysis *FileAnalysis) string {
	head, rest, ok := strings.Cut(base, csharpSeparator)
	if path, aliased := analysis.ImportAliases[head]; aliased && ok {
		return csharpJoin(path, rest)
	}
	return base
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

func (p *CSharpParser) parseFunction(node *sitter.Node, src []byte, filePath, namespace, typePath, ownerType string, fields *csharpFields, analysis *FileAnalysis) *FunctionDecl {
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
		OwnerType:    ownerType,
		OwnerName:    csharpJoin(namespace, typePath),
		FunctionType: "method",
		Static:       csharpHasModifier(node, src, "static"),
		Abstract:     ownerType == ownerTypeInterface || csharpHasModifier(node, src, "abstract"),
		EntryKind:    csharpEntryKind(name, csharpHasModifier(node, src, "static")),
		Parameters:   parameters,
		ReturnType:   csharpReturnType(node, src),
	}
	if node.Type() == csharpNodeConstructor {
		decl.FunctionType = "constructor"
		if fields != nil {
			decl.Calls = append(decl.Calls, fields.instanceCalls...)
		}
	}
	variableTypes := make(map[string]string, len(parameters))
	for _, parameter := range parameters {
		if parameter.Name != "" && parameter.Type != "" {
			variableTypes[parameter.Name] = parameter.Type
		}
	}
	// A member's calls are in its block; an expression-bodied one has an
	// arrow clause instead, and a property has its accessors and, when it is
	// declared with one, its initializer
	// (`public byte[] Key { get; } = RandomNumberGenerator.GetBytes(16);`).
	bodies := []*sitter.Node{body}
	if body == nil {
		bodies = []*sitter.Node{
			csharpChildByType(node, csharpNodeArrowClause),
			csharpChildByType(node, "accessor_list"),
			node.ChildByFieldName("value"),
		}
	}
	values := newCSharpValues(fields.literals(), fields.declaredTypes())
	for _, parameter := range parameters {
		values.declare(parameter.Name, parameter.Type)
	}
	read := false
	for i, part := range bodies {
		// An arrow-bodied member is both the arrow clause and the value, so
		// the same node is listed twice; read each node once.
		if part == nil || csharpSeenBefore(bodies[:i], part) {
			continue
		}
		read = true
		values.countWrites(part, src)
		p.walkCalls(part, src, filePath, namespace, typePath, variableTypes, values, analysis, &decl.Calls)
		decl.Declarations = append(decl.Declarations, csharpDeclarations(part, src)...)
		decl.AttributeStores = append(decl.AttributeStores, csharpAttributeStores(part, src)...)
	}
	if !read {
		return decl
	}
	return decl
}

// parseClassInitializer collects the calls a type's field initializers make
// into one synthetic declaration, as Java's class initializer does: a
// `private static readonly SHA256 H = SHA256.Create();` is a call of the type,
// made outside any method body.
// parseTopLevelProgram reads a file written as top-level statements, which
// C# compiles into the entry point of the program: the statements become the
// body of a `Main` the compiler generates on a `Program` class. Without it
// every call of such a file is invisible, and a console program written this
// way is all of them.
func (p *CSharpParser) parseTopLevelProgram(root *sitter.Node, src []byte, filePath, namespace string, analysis *FileAnalysis) *FunctionDecl {
	var statements []*sitter.Node
	for i := 0; i < int(root.ChildCount()); i++ {
		if child := root.Child(i); child.Type() == csharpNodeGlobalStatement {
			statements = append(statements, child)
		}
	}
	if len(statements) == 0 {
		return nil
	}
	decl := &FunctionDecl{
		ID:           FunctionID{Package: namespace, Type: "Program", Name: csharpMethodWithArity("Main", 1)},
		FilePath:     filePath,
		StartLine:    int(statements[0].StartPoint().Row) + 1,
		EndLine:      int(statements[len(statements)-1].EndPoint().Row) + 1,
		StartCol:     int(statements[0].StartPoint().Column) + 1,
		EndCol:       int(statements[len(statements)-1].EndPoint().Column) + 1,
		OwnerType:    "class",
		OwnerName:    csharpJoin(namespace, "Program"),
		FunctionType: "method",
		Static:       true,
		EntryKind:    RootKindMain,
		Parameters:   []FunctionParameter{{Name: "args", Type: "string[]"}},
	}
	values := newCSharpValues(nil, nil)
	variableTypes := map[string]string{}
	for _, statement := range statements {
		// A local function declared among the statements owns its own body.
		if statement.NamedChildCount() == 1 && statement.NamedChild(0).Type() == csharpNodeLocalFunction {
			if local := p.parseFunction(statement.NamedChild(0), src, filePath, namespace, "Program", "class", nil, analysis); local != nil {
				analysis.Functions = append(analysis.Functions, *local)
			}
			continue
		}
		values.countWrites(statement, src)
		p.walkCalls(statement, src, filePath, namespace, "Program", variableTypes, values, analysis, &decl.Calls)
		decl.Declarations = append(decl.Declarations, csharpDeclarations(statement, src)...)
		decl.AttributeStores = append(decl.AttributeStores, csharpAttributeStores(statement, src)...)
	}
	return decl
}

// readFieldInitializers records the calls a type's field initializers make,
// kept apart by whether the field is static: a static field runs once at
// class load, an instance field once per construction.
func (p *CSharpParser) readFieldInitializers(node *sitter.Node, src []byte, filePath, namespace, typePath string, fields *csharpFields, analysis *FileAnalysis) {
	body := node.ChildByFieldName("body")
	if body == nil || fields == nil {
		return
	}
	variableTypes := map[string]string{}
	values := newCSharpValues(fields.literals(), fields.declaredTypes())
	for i := 0; i < int(body.NamedChildCount()); i++ {
		field := body.NamedChild(i)
		if field.Type() != csharpNodeFieldDeclaration {
			continue
		}
		var calls []FunctionCall
		p.walkCalls(field, src, filePath, namespace, typePath, variableTypes, values, analysis, &calls)
		if csharpHasModifier(field, src, "static") || csharpHasModifier(field, src, "const") {
			fields.staticCalls = append(fields.staticCalls, calls...)
			continue
		}
		fields.instanceCalls = append(fields.instanceCalls, calls...)
	}
}

// parseClassInitializer collects the calls a type's field initializers make.
// A static field runs at class load, as Java's class initializer does; an
// instance field runs in the constructor, so its calls go to the type's
// constructors -- to the one C# generates when the type declares none, which
// is what a `new T()` of such a type calls.
func (p *CSharpParser) parseClassInitializer(node *sitter.Node, src []byte, filePath, namespace, typePath string, fields *csharpFields, analysis *FileAnalysis) []FunctionDecl {
	body := node.ChildByFieldName("body")
	if body == nil || fields == nil {
		return nil
	}
	decl := func(name string, static bool, calls []FunctionCall) FunctionDecl {
		return FunctionDecl{
			ID:           FunctionID{Package: namespace, Type: typePath, Name: name},
			FilePath:     filePath,
			StartLine:    int(node.StartPoint().Row) + 1,
			EndLine:      int(node.EndPoint().Row) + 1,
			StartCol:     int(node.StartPoint().Column) + 1,
			EndCol:       int(node.EndPoint().Column) + 1,
			OwnerType:    "class",
			OwnerName:    csharpJoin(namespace, typePath),
			FunctionType: "method",
			Static:       static,
			Calls:        calls,
		}
	}
	var out []FunctionDecl
	if len(fields.staticCalls) > 0 {
		out = append(out, decl(csharpMethodWithArity(clinitMethodName, 0), true, fields.staticCalls))
	}
	if len(fields.instanceCalls) > 0 && !csharpDeclaresConstructor(body) {
		out = append(out, decl(csharpMethodWithArity(constructorMethodName, 0), false, fields.instanceCalls))
	}
	return out
}

// csharpDeclaresConstructor reports a type body that declares one.
func csharpDeclaresConstructor(body *sitter.Node) bool {
	for i := 0; i < int(body.NamedChildCount()); i++ {
		if body.NamedChild(i).Type() == csharpNodeConstructor {
			return true
		}
	}
	return false
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

// csharpSeenBefore reports a node already in the list.
func csharpSeenBefore(nodes []*sitter.Node, node *sitter.Node) bool {
	for _, seen := range nodes {
		if seen != nil && sameSyntaxNode(seen, node) {
			return true
		}
	}
	return false
}

// csharpEntryKind marks the program's entry point: C# spells it `Main`, and
// the shared main detection reads the lowercase name Java and Go use.
func csharpEntryKind(name string, static bool) RootKind {
	if static && name == "Main" {
		return RootKindMain
	}
	return ""
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

func (p *CSharpParser) walkCalls(node *sitter.Node, src []byte, filePath, namespace, typePath string, variableTypes map[string]string, values *csharpValues, analysis *FileAnalysis, calls *[]FunctionCall) {
	if csharpIntroducesScope(node.Type()) {
		variableTypes = maps.Clone(variableTypes)
		values = values.clone()
	}
	if node.Type() == csharpNodeLocalDeclaration || node.Type() == csharpNodeUsingStatement {
		csharpRecordDeclaredTypes(node, src, variableTypes)
	}
	values.record(node, src)
	switch node.Type() {
	case csharpNodeInvocation:
		if call := p.parseInvocation(node, src, filePath, namespace, typePath, variableTypes, values, analysis); call != nil {
			p.anchors.set(call, node)
			*calls = append(*calls, *call)
		}
	case csharpNodeObjectCreation:
		if call := p.parseObjectCreation(node, src, filePath, namespace, values, analysis); call != nil {
			p.anchors.set(call, node)
			*calls = append(*calls, *call)
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		p.walkCalls(node.Child(i), src, filePath, namespace, typePath, variableTypes, values, analysis, calls)
	}
}

func csharpIntroducesScope(kind string) bool {
	switch kind {
	case csharpNodeBlock, "if_statement", "switch_statement", "for_statement", "for_each_statement", "while_statement", "do_statement", "catch_clause", csharpNodeUsingStatement, lambdaExpressionNode:
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

func (p *CSharpParser) parseInvocation(node *sitter.Node, src []byte, filePath, namespace, typePath string, variableTypes map[string]string, values *csharpValues, analysis *FileAnalysis) *FunctionCall {
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
	call.ArgumentSources = csharpArgumentSources(call.Arguments, values, filePath, call.Line)
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

func (p *CSharpParser) parseObjectCreation(node *sitter.Node, src []byte, filePath, namespace string, values *csharpValues, analysis *FileAnalysis) *FunctionCall {
	written := csharpTypeName(node.ChildByFieldName("type"), src)
	if written == "" {
		return nil
	}
	arguments := csharpArguments(node.ChildByFieldName("arguments"), src)
	line := int(node.StartPoint().Row) + 1
	return &FunctionCall{
		ArgumentSources: csharpArgumentSources(arguments, values, filePath, line),
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
