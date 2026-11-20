// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// The C++ parser records, beside each call's key, how the call was written
// (cppCallFacts) and, per file, the classes it declares (cppFileFacts), and per
// function its declared return type (cppFunctionFacts). A call's key is what
// one file says; which definition it names often depends on other files (a
// member's type declared in a header, the class hierarchy, the namespace a
// type was declared in), so resolveCPPCalls reads these facts once every file
// is parsed (graph-algo-cpp-4, cpp_call_resolution.go).

const (
	cppNodeFieldExpression     = "field_expression"
	cppNodeFieldInitializer    = "field_initializer"
	cppNodeFieldInitializers   = "field_initializer_list"
	cppNodeFieldDeclaration    = "field_declaration"
	cppNodeBaseClassClause     = "base_class_clause"
	cppNodeTemplateFunction    = "template_function"
	cppNodeTemplateArguments   = "template_argument_list"
	cppNodeTypeDescriptor      = "type_descriptor"
	cppNodePointerDeclarator   = "pointer_declarator"
	cppNodeArrayDeclarator     = "array_declarator"
	cppNodeParenthesizedExpr   = "parenthesized_expression"
	cppNodePlaceholderType     = "placeholder_type_specifier"
	cppNodeThis                = "this"
	cppByValueMarker           = "\x00byvalue:"
	cppUsingNamespaceDirective = "using namespace "
)

// cppCallShape is the syntax a call's callee is written in.
type cppCallShape int

const (
	// The zero shape is one resolveCPPCalls leaves as the parser keyed it.
	_ cppCallShape = iota
	// cppCallFree is an unqualified name: `f(x)`, `f<T>(x)`.
	cppCallFree
	// cppCallQualified is a scoped name: `ns::f(x)`, `T::create(x)`.
	cppCallQualified
	// cppCallMember is a member call: `v.f(x)`, `p->f(x)`, `g().f(x)`.
	cppCallMember
	// cppCallConstruct is a construction of Callee.Type: a declaration, a
	// new expression, a compound literal, std::make_unique / make_shared.
	cppCallConstruct
	// cppCallMemberInit is an entry of a constructor's member initializer
	// list, `m_x(args)`: a construction of the member's type, or of a base.
	cppCallMemberInit
)

// cppCallFacts is how a C++ call was written, for resolveCPPCalls.
type cppCallFacts struct {
	shape cppCallShape
	// scope is the scope a qualified callee is written with (`ns` of
	// `ns::f`), as written.
	scope string
	// receiver is the expression a member call is made on.
	receiver *cppExpr
	// arrow reports a member call written with `->`.
	arrow bool
	// smart marks a construction by std::make_unique / std::make_shared,
	// whose value is a smart pointer to the constructed type.
	smart bool
	// member is the name a member initializer list entry initializes.
	member string
	// edges are the targets the call reaches beside its callee, filled by
	// resolveCPPCalls: other bodies of the definition and overrides.
	edges []cppEdge
	// drop marks a member initializer resolveCPPCalls found no type for.
	drop bool
}

// cppEdge is one more target of a call: its key, the edge kind, and for a
// dispatch edge the type the call was made on.
type cppEdge struct {
	key          string
	kind         EdgeKind
	declaredType string
}

// cppExprKind is the shape of a receiver expression.
type cppExprKind int

const (
	cppExprVariable cppExprKind = iota + 1
	cppExprThis
	cppExprField
	cppExprCall
)

// cppExpr is a receiver expression as resolveCPPCalls reads it.
type cppExpr struct {
	kind cppExprKind
	// name is the variable's name (cppExprVariable) or the member's
	// (cppExprField).
	name string
	// declared is the variable's declared type as the parser recorded it:
	// "" when nothing in the function declares it (a member, a global),
	// "auto" for a deduced one.
	declared string
	// local reports a variable declared in the function or a parameter.
	local bool
	// byValue reports a local object, not a pointer or reference: a call on
	// it is never dispatched to an override.
	byValue bool
	// inner is the expression whose member a cppExprField reads, and arrow
	// reports that it is read with `->`.
	inner *cppExpr
	arrow bool
	// span locates the call a cppExprCall is: line, start column, end line,
	// end column, as FunctionCall records them.
	span [4]int
}

// cppFunctionFacts is what a C++ definition declares about its result.
type cppFunctionFacts struct {
	// returns is the declared return type as written, without
	// cv-qualifiers, pointer or reference declarators; "" for none
	// (a constructor) or a deduced one.
	returns string
	// returnsMember is the member a function with a deduced return type
	// (`auto`, `const auto&`) returns, when every return names the same one.
	returnsMember string
	// static marks a function with internal linkage (`static` at namespace
	// scope), visible only in its file.
	static bool
}

// cppFileFacts is what one C++ file declares for the resolution of calls in
// any file: its classes, and the namespaces its using-directives name.
type cppFileFacts struct {
	classes []cppClassFacts
	usings  []string
}

// cppClassFacts is one class or struct definition (a body, not a forward
// declaration).
type cppClassFacts struct {
	name   string
	file   string
	fields map[string]cppFieldFacts
	// methods are the member functions the body declares.
	methods map[string]bool
	bases   []string
}

// cppFieldFacts is one data member.
type cppFieldFacts struct {
	// typ is the declared type as written, without cv-qualifiers.
	typ string
	// ctor is the constructor name of a class-typed member held by value
	// (cppConstructedName), "" for any other member.
	ctor string
}

// cppReceiverExpr reads a member call's receiver.
func cppReceiverExpr(node *sitter.Node, src []byte, variableTypes map[string]string) *cppExpr {
	if node == nil {
		return nil
	}
	switch node.Type() {
	case cNodeIdentifier:
		name := node.Content(src)
		declared, local := variableTypes[name]
		_, byValue := variableTypes[cppByValueMarker+name]
		return &cppExpr{kind: cppExprVariable, name: name, declared: declared, local: local, byValue: byValue}
	case cppNodeThis:
		return &cppExpr{kind: cppExprThis}
	case cppNodeFieldExpression:
		field := node.ChildByFieldName("field")
		inner := cppReceiverExpr(node.ChildByFieldName("argument"), src, variableTypes)
		if field == nil || inner == nil {
			return nil
		}
		return &cppExpr{kind: cppExprField, name: field.Content(src), inner: inner, arrow: cppArrowAccess(node, src)}
	case cNodeCallExpression:
		return &cppExpr{kind: cppExprCall, span: cppNodeSpan(node)}
	case cppNodeParenthesizedExpr:
		if node.NamedChildCount() == 1 {
			return cppReceiverExpr(node.NamedChild(0), src, variableTypes)
		}
	}
	return nil
}

// cppArrowAccess reports a field expression written with `->`.
func cppArrowAccess(node *sitter.Node, src []byte) bool {
	if op := node.ChildByFieldName("operator"); op != nil {
		return op.Content(src) == "->"
	}
	return false
}

// cppNodeSpan is a node's span as FunctionCall records a call's.
func cppNodeSpan(node *sitter.Node) [4]int {
	return [4]int{int(node.StartPoint().Row) + 1, int(node.StartPoint().Column) + 1, int(node.EndPoint().Row) + 1, int(node.EndPoint().Column) + 1}
}

// cppCallSpan is a call's span, comparable with cppNodeSpan.
func cppCallSpan(call *FunctionCall) [4]int {
	return [4]int{call.Line, call.StartCol, call.EndLine, call.EndCol}
}

// cppRecordByValue marks name as a local object declared by value, or clears
// the mark when the declarator is a pointer or reference.
func cppRecordByValue(declarator *sitter.Node, name string, types map[string]string) {
	switch declarator.Type() {
	case cNodeIdentifier, cppNodeFunctionDeclarator:
		types[cppByValueMarker+name] = ""
	case cppNodeInitDeclarator:
		if inner := declarator.ChildByFieldName("declarator"); inner != nil && inner.Type() == cNodeIdentifier {
			types[cppByValueMarker+name] = ""
			return
		}
		delete(types, cppByValueMarker+name)
	default:
		delete(types, cppByValueMarker+name)
	}
}

// cppSmartConstruction reads `std::make_unique<T>(...)`,
// `std::make_shared<T>(...)` and the same unqualified: the type node of T, or
// nil for any other call.
func cppSmartConstruction(function *sitter.Node, src []byte) *sitter.Node {
	if function.Type() == cppNodeQualifiedIdentifier {
		scope, name := function.ChildByFieldName("scope"), function.ChildByFieldName("name")
		if scope == nil || scope.Content(src) != "std" || name == nil {
			return nil
		}
		function = name
	}
	if function.Type() != cppNodeTemplateFunction {
		return nil
	}
	name, args := function.ChildByFieldName("name"), function.ChildByFieldName("arguments")
	if name == nil || args == nil || args.NamedChildCount() == 0 {
		return nil
	}
	switch name.Content(src) {
	case "make_unique", "make_shared":
	default:
		return nil
	}
	first := args.NamedChild(0)
	if first.Type() != cppNodeTypeDescriptor {
		return nil
	}
	typeNode := first.ChildByFieldName("type")
	if cppConstructedName(typeNode, src) == "" {
		return nil
	}
	return typeNode
}

// cppSmartConstructionCall is the construction of T a make_unique<T> /
// make_shared<T> call performs, spanning the call.
func cppSmartConstructionCall(call *FunctionCall, typeNode *sitter.Node, src []byte, packagePath string) *FunctionCall {
	construct := *call
	construct.Callee = FunctionID{Package: packagePath, Type: cppCanonicalType(typeNode.Content(src)), Name: cppConstructedName(typeNode, src)}
	construct.Raw = typeNode.Content(src)
	construct.ReceiverVar = ""
	construct.ChainID = ""
	construct.Arguments = append([]string(nil), call.Arguments...)
	construct.cpp = &cppCallFacts{shape: cppCallConstruct, smart: true}
	return &construct
}

// cppMemberInitCall is the construction a member initializer list entry
// `m_x(args)` / `m_x{args}` performs. Which type it constructs is the
// member's, known once every file is read, so the callee is left for
// resolveCPPCalls; Raw is the name as written.
func cppMemberInitCall(node *sitter.Node, src []byte, filePath, packagePath string) *FunctionCall {
	if node.NamedChildCount() < 2 {
		return nil
	}
	name, args := node.NamedChild(0), node.NamedChild(int(node.NamedChildCount())-1)
	if args.Type() != "argument_list" && args.Type() != "initializer_list" {
		return nil
	}
	member := cppMemberInitName(name, src)
	if member == "" {
		return nil
	}
	span := cppNodeSpan(node)
	return &FunctionCall{
		Callee:    FunctionID{Package: packagePath, Name: member},
		Raw:       name.Content(src),
		FilePath:  filePath,
		Line:      span[0],
		StartCol:  span[1],
		EndLine:   span[2],
		EndCol:    span[3],
		Arguments: cppConstructionArguments(args, src),
		cpp:       &cppCallFacts{shape: cppCallMemberInit, member: member},
	}
}

// cppMemberInitName is the name an initializer entry names: a member
// (`m_x`), or a base written as a type (`Base`, `ns::Base`, `Base<T>`),
// template arguments dropped.
func cppMemberInitName(node *sitter.Node, src []byte) string {
	switch node.Type() {
	case "field_identifier", cNodeIdentifier, cppNodeTypeIdentifier:
		return node.Content(src)
	case cppNodeQualifiedIdentifier, cppNodeTemplateType:
		return cppStripTemplateArgs(cppCanonicalType(node.Content(src)))
	}
	return ""
}

// cppDeclaredReturn reads a definition's declared return type: the type
// node as written, or "" for none (a constructor, a destructor, a
// conversion operator) or a deduced one (`auto`, `decltype(auto)`), which
// reports deduced.
func cppDeclaredReturn(node *sitter.Node, src []byte) (returns string, deduced bool) {
	typeNode := node.ChildByFieldName("type")
	if typeNode == nil {
		return "", false
	}
	if typeNode.Type() == cppNodePlaceholderType {
		return "", true
	}
	if typeNode.Type() == "primitive_type" {
		return "", false
	}
	return cppCanonicalType(typeNode.Content(src)), false
}

// cppReturnedMember names the member every return statement of body returns
// (`return m_key;`, `return this->m_key;`), "" when a return returns
// anything else or a name the function declares (a local or parameter).
func cppReturnedMember(body *sitter.Node, src []byte, locals map[string]bool) string {
	member, ok := "", true
	var walk func(*sitter.Node)
	walk = func(n *sitter.Node) {
		if !ok || n.Type() == lambdaExpressionNode {
			return
		}
		if n.Type() == cNodeReturnStatement {
			name := ""
			if expr := cReturnExpression(n); expr != nil {
				name = cppMemberName(expr, src, locals)
			}
			if name == "" || (member != "" && member != name) {
				ok = false
				return
			}
			member = name
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(body)
	if !ok {
		return ""
	}
	return member
}

func cppMemberName(expr *sitter.Node, src []byte, locals map[string]bool) string {
	switch expr.Type() {
	case cNodeIdentifier:
		if name := expr.Content(src); !locals[name] {
			return name
		}
	case cppNodeFieldExpression:
		argument, field := expr.ChildByFieldName("argument"), expr.ChildByFieldName("field")
		if argument != nil && argument.Type() == cppNodeThis && field != nil {
			return field.Content(src)
		}
	case cppNodeParenthesizedExpr:
		if expr.NamedChildCount() == 1 {
			return cppMemberName(expr.NamedChild(0), src, locals)
		}
	}
	return ""
}

// cppFunctionLocals is the set of names a definition declares: its
// parameters and the variables of its body.
func cppFunctionLocals(decl *FunctionDecl) map[string]bool {
	locals := make(map[string]bool, len(decl.Parameters)+len(decl.Declarations))
	for _, p := range decl.Parameters {
		locals[p.Name] = true
	}
	for _, d := range decl.Declarations {
		locals[d.Name] = true
	}
	return locals
}

// collectCPPFileFacts reads the classes a file defines, under the scope
// collectCPPDeclaredTypes names them by, and its using-directives.
func collectCPPFileFacts(root *sitter.Node, src []byte, filePath string, includes []CInclude) *cppFileFacts {
	facts := &cppFileFacts{}
	collectCPPClasses(root, src, "", filePath, &facts.classes)
	for _, include := range includes {
		if ns, ok := strings.CutPrefix(include.Text, cppUsingNamespaceDirective); include.Using && ok {
			if ns = cppCanonicalType(strings.TrimSuffix(strings.TrimSpace(ns), ";")); ns != "" {
				facts.usings = append(facts.usings, ns)
			}
		}
	}
	return facts
}

func collectCPPClasses(node *sitter.Node, src []byte, scope, filePath string, out *[]cppClassFacts) {
	nextScope := cppNestedScope(node, src, scope)
	if nextScope != scope && (node.Type() == "class_specifier" || node.Type() == "struct_specifier") {
		if body := node.ChildByFieldName("body"); body != nil {
			*out = append(*out, cppClassOf(node, body, src, nextScope, filePath))
		}
	}
	childScope := nextScope
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if next, handled := cppMacroScope(child, src, childScope, nextScope); handled {
			childScope = next
			continue
		}
		collectCPPClasses(child, src, childScope, filePath, out)
	}
}

func cppClassOf(node, body *sitter.Node, src []byte, name, filePath string) cppClassFacts {
	class := cppClassFacts{name: name, file: filePath, fields: make(map[string]cppFieldFacts), methods: make(map[string]bool)}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		clause := node.NamedChild(i)
		if clause.Type() != cppNodeBaseClassClause {
			continue
		}
		for j := 0; j < int(clause.NamedChildCount()); j++ {
			switch base := clause.NamedChild(j); base.Type() {
			case cppNodeTypeIdentifier, cppNodeQualifiedIdentifier, cppNodeTemplateType:
				class.bases = append(class.bases, cppCanonicalType(base.Content(src)))
			}
		}
	}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		field := body.NamedChild(i)
		if field.Type() == "template_declaration" {
			for j := 0; j < int(field.NamedChildCount()); j++ {
				if inner := field.NamedChild(j); inner.Type() == cppNodeFunctionDefinition || inner.Type() == cppNodeFieldDeclaration {
					field = inner
				}
			}
		}
		if field.Type() == cppNodeFunctionDefinition {
			// An inline definition, and a pure virtual or defaulted
			// declaration, which tree-sitter-cpp reads as a definition
			// without a body.
			if name := cppMethodDeclaratorName(field.ChildByFieldName("declarator"), src); name != "" {
				class.methods[name] = true
			}
			continue
		}
		if field.Type() != cppNodeFieldDeclaration {
			continue
		}
		typeNode := field.ChildByFieldName("type")
		if typeNode == nil {
			continue
		}
		for j := 0; j < int(field.ChildCount()); j++ {
			if field.FieldNameForChild(j) != "declarator" {
				continue
			}
			declarator := field.Child(j)
			if method := cppMethodDeclaratorName(declarator, src); method != "" {
				class.methods[method] = true
				continue
			}
			name, byValue, ok := cppFieldDeclarator(declarator, src)
			if !ok {
				continue
			}
			facts := cppFieldFacts{typ: cppCanonicalType(typeNode.Content(src))}
			if byValue {
				facts.ctor = cppConstructedName(typeNode, src)
			}
			class.fields[name] = facts
		}
	}
	return class
}

// cppMethodDeclaratorName names the member function a member declarator
// declares (`void f() const;`, `virtual R* g() = 0;`), or "".
func cppMethodDeclaratorName(node *sitter.Node, src []byte) string {
	for current := node; current != nil; {
		switch current.Type() {
		case cppNodeFunctionDeclarator:
			name, _ := cppDeclaratorIdentity(current.ChildByFieldName("declarator"), src)
			return name
		case cppNodePointerDeclarator, cppNodeReferenceDeclarator:
			next := current.ChildByFieldName("declarator")
			if next == nil && current.NamedChildCount() > 0 {
				next = current.NamedChild(int(current.NamedChildCount()) - 1)
			}
			current = next
		default:
			return ""
		}
	}
	return ""
}

// cppFieldDeclarator reads a data member's declarator: its name and whether
// it holds the object by value; ok is false for a member function's
// declaration or an array.
func cppFieldDeclarator(node *sitter.Node, src []byte) (name string, byValue, ok bool) {
	switch node.Type() {
	case "field_identifier":
		return node.Content(src), true, true
	case cppNodePointerDeclarator, cppNodeReferenceDeclarator:
		for current := node; current != nil; {
			switch current.Type() {
			case "field_identifier":
				return current.Content(src), false, true
			case cppNodeFunctionDeclarator, cppNodeArrayDeclarator:
				return "", false, false
			}
			next := current.ChildByFieldName("declarator")
			if next == nil && current.NamedChildCount() > 0 {
				next = current.NamedChild(int(current.NamedChildCount()) - 1)
			}
			current = next
		}
	}
	return "", false, false
}

// cppStripTemplateArgs drops every template argument list of a type name:
// `a::B<int>::C<x::Y>` → `a::B::C`.
func cppStripTemplateArgs(name string) string {
	if !strings.Contains(name, "<") {
		return name
	}
	var b strings.Builder
	depth := 0
	for _, r := range name {
		switch {
		case r == '<':
			depth++
		case r == '>':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// cppSplitScope splits a qualified name at its top-level `::`, template
// arguments kept whole: `a::B<x::Y>::f` → [a, B<x::Y>, f].
func cppSplitScope(name string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(name); i++ {
		switch name[i] {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		case ':':
			if depth == 0 && i+1 < len(name) && name[i+1] == ':' {
				parts = append(parts, name[start:i])
				start = i + 2
				i++
			}
		}
	}
	return append(parts, name[start:])
}

// cppTemplateArgs splits the top-level template arguments of a type name:
// `std::unique_ptr<A, D<x, y>>` → [A, D<x, y>].
func cppTemplateArgs(name string) []string {
	open := strings.IndexByte(name, '<')
	if open < 0 || !strings.HasSuffix(name, ">") {
		return nil
	}
	inner := name[open+1 : len(name)-1]
	var args []string
	depth, start := 0, 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '<', '(':
			depth++
		case '>', ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(inner[start:i]))
				start = i + 1
			}
		}
	}
	return append(args, strings.TrimSpace(inner[start:]))
}

// cppMaskClassMacros blanks the export macro of a class written `class
// QPDF_DLL_CLASS Name { ... }` / `class API Name : public Base { ... }`.
// tree-sitter-cpp, which does not expand macros, reads the macro as the
// class's name and the rest as a function definition, so the class, its
// members and its bases were lost (graph-algo-cpp-4). The shape is
// unambiguous: a function definition whose declarator is a bare name and
// whose type is a class or struct specifier without a body is never a
// function. The macro, an upper-case identifier, is replaced by spaces, so
// every byte offset and column stays as written; ok is false when the file
// has no such class.
func cppMaskClassMacros(root *sitter.Node, src []byte) ([]byte, bool) {
	var masked []byte
	walkCNodes(root, func(n *sitter.Node) {
		if n.Type() != cppNodeFunctionDefinition {
			return
		}
		typeNode, declarator := n.ChildByFieldName("type"), n.ChildByFieldName("declarator")
		if typeNode == nil || declarator == nil || declarator.Type() != cNodeIdentifier {
			return
		}
		if typeNode.Type() != "class_specifier" && typeNode.Type() != "struct_specifier" || typeNode.ChildByFieldName("body") != nil {
			return
		}
		name := typeNode.ChildByFieldName("name")
		if name == nil || name.Type() != cppNodeTypeIdentifier || !cppMacroName(name.Content(src)) {
			return
		}
		if masked == nil {
			masked = append([]byte(nil), src...)
		}
		for i := name.StartByte(); i < name.EndByte(); i++ {
			masked[i] = ' '
		}
	})
	return masked, masked != nil
}

// cppMacroName reports a name spelled as a macro is: upper-case letters,
// digits and underscores, starting with a letter or underscore.
func cppMacroName(name string) bool {
	if name == "" || (name[0] >= '0' && name[0] <= '9') {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
