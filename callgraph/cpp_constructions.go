// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// C++ constructs an object without a call_expression in four shapes, and the
// parser records each as a call to the constructed type's constructor, keyed
// (T).T as a constructor definition is: Callee.Type is the type as written
// (without a leading "::", template arguments kept, as a variable's declared
// type is), Callee.Name its last segment without template arguments, Raw the
// type's text. The span (Line, StartCol, EndLine, EndCol) and the anchor node
// (ASTKind, NamedASTPath) are, per shape:
//
//   - `T v(args);`, `T v{args};`: the span runs from the start of the
//     declaration's type to the end of the declarator, so its text is
//     `T v(args)` (qualifiers before the type, and the `;`, stay out). The
//     anchor is the init_declarator, or the function_declarator tree-sitter
//     reads `T v(a, ns::b)` as when every argument also reads as a type name
//     (a declaration of a function, which a function body never means).
//     `T v();` declares a function, but OpenGrep matches it as `T $K(...);`:
//     it is a site too (graph-algo-cpp-3), anchored on the
//     function_declarator, with no arguments; its span reads `T v()`.
//   - `T v;`: the same span, `T v`; the anchor is the declarator's identifier.
//   - `new T(args)`, `new T{args}`, `new T`: the span and the anchor are the
//     new_expression.
//   - `T{args}`: the span and the anchor are the compound_literal_expression.
//
// With several declarators (`T a(1), b(2);`) each is a site, and the text of
// a later one holds the declarators before it: `T a(1), b(2)` for b.
//
// A temporary written `T(args)` is a call_expression already and stays one,
// keyed as a call of the function T: the syntax does not tell a type from a
// function. Not recorded: a type that names no class (a primitive, `auto`, an
// elaborated `struct S`, a dependent `typename`, `decltype`), a pointer,
// reference or array declarator, an `extern` declaration, copy-initialization
// (`T v = e;`, where e is the site when it is a call; the declaration is
// listed among the function's Declarations), and an array new (`new T[n]`).

const (
	cppNodeDeclaration          = "declaration"
	cppNodeInitDeclarator       = "init_declarator"
	cppNodeFunctionDeclarator   = "function_declarator"
	cppNodeNewExpression        = "new_expression"
	cppNodeCompoundLiteral      = "compound_literal_expression"
	cppNodeTypeIdentifier       = "type_identifier"
	cppNodeTemplateType         = "template_type"
	cppNodeParameterDeclaration = "parameter_declaration"
)

// constructionSites records the constructor calls node writes, when it is a
// declaration, a new_expression or a compound literal.
func (p *CPPParser) constructionSites(node *sitter.Node, src []byte, filePath, packagePath string, localTypes map[string]bool, calls *[]FunctionCall) {
	switch node.Type() {
	case cppNodeDeclaration:
		typeNode := node.ChildByFieldName("type")
		if cppConstructedName(typeNode, src) == "" || cppExternDeclaration(node, src) {
			return
		}
		for i := 0; i < int(node.ChildCount()); i++ {
			if node.FieldNameForChild(i) != "declarator" {
				continue
			}
			declarator := node.Child(i)
			name, args, ok := cppConstructedDeclarator(declarator, src)
			if !ok {
				continue
			}
			call := cppConstruction(typeNode, args, typeNode, declarator, src, filePath, packagePath, localTypes)
			call.AssignedVar = name
			p.anchors.set(call, declarator)
			*calls = append(*calls, *call)
		}
	case cppNodeNewExpression, cppNodeCompoundLiteral:
		typeNode := node.ChildByFieldName("type")
		if cppConstructedName(typeNode, src) == "" || node.ChildByFieldName("declarator") != nil {
			return
		}
		args := node.ChildByFieldName("arguments")
		if node.Type() == cppNodeCompoundLiteral {
			args = node.ChildByFieldName("value")
		}
		call := cppConstruction(typeNode, args, node, node, src, filePath, packagePath, localTypes)
		call.AssignedVar = cppAssignedVar(node, src)
		p.anchors.set(call, node)
		*calls = append(*calls, *call)
	}
}

// cppConstruction is the call of typeNode's constructor with args (nil for
// none), spanning from the start of from to the end of to.
func cppConstruction(typeNode, args, from, to *sitter.Node, src []byte, filePath, packagePath string, localTypes map[string]bool) *FunctionCall {
	call := &FunctionCall{
		Callee:    FunctionID{Package: packagePath, Type: cppCanonicalType(typeNode.Content(src)), Name: cppConstructedName(typeNode, src)},
		Raw:       typeNode.Content(src),
		FilePath:  filePath,
		Line:      int(from.StartPoint().Row) + 1,
		StartCol:  int(from.StartPoint().Column) + 1,
		EndLine:   int(to.EndPoint().Row) + 1,
		EndCol:    int(to.EndPoint().Column) + 1,
		Arguments: cppConstructionArguments(args, src),
	}
	if localTypes[call.Callee.Type] {
		call.Callee.Linkage = LinkageInternal
	}
	return call
}

// cppConstructedName is the constructor name of a type that names a class:
// its last segment without template arguments (`Botan::AES_256` → AES_256,
// `std::vector<uint8_t>` → vector), or "" for any other type.
func cppConstructedName(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	switch node.Type() {
	case cppNodeTypeIdentifier:
		return node.Content(src)
	case cppNodeTemplateType:
		return cppConstructedName(node.ChildByFieldName("name"), src)
	case cppNodeQualifiedIdentifier:
		return cppConstructedName(node.ChildByFieldName("name"), src)
	}
	return ""
}

// cppConstructedDeclarator reads a declarator of a class-typed declaration:
// the variable it constructs and the argument node (nil for a default
// construction), or ok false for a declarator that constructs nothing or
// constructs it by copy.
func cppConstructedDeclarator(node *sitter.Node, src []byte) (name string, args *sitter.Node, ok bool) {
	switch node.Type() {
	case cNodeIdentifier:
		return node.Content(src), nil, true
	case cppNodeInitDeclarator:
		declarator, value := node.ChildByFieldName("declarator"), node.ChildByFieldName("value")
		if declarator == nil || declarator.Type() != cNodeIdentifier || value == nil || cppHasChild(node, "=") {
			return "", nil, false
		}
		if value.Type() != "argument_list" && value.Type() != "initializer_list" {
			return "", nil, false
		}
		return declarator.Content(src), value, true
	case cppNodeFunctionDeclarator:
		declarator, parameters := node.ChildByFieldName("declarator"), node.ChildByFieldName("parameters")
		if declarator == nil || declarator.Type() != cNodeIdentifier {
			return "", nil, false
		}
		if cppEmptyParameters(node, parameters) {
			return declarator.Content(src), nil, true
		}
		if !cppParametersReadAsArguments(node, parameters) {
			return "", nil, false
		}
		return declarator.Content(src), parameters, true
	}
	return "", nil, false
}

// cppParametersReadAsArguments reports whether a function declarator in a
// function body is an object declaration tree-sitter took for a function's:
// `QCryptographicHash h(QCryptographicHash::Sha256)`, `seal::KeyGenerator
// keygen(context)`. It is when the list holds at least one parameter, each a
// bare name or scoped name with nothing else (no parameter name, qualifier,
// pointer or reference), and nothing follows the list (`const`, `noexcept`,
// a trailing return).
func cppParametersReadAsArguments(declarator, parameters *sitter.Node) bool {
	if parameters == nil || parameters.Type() != cNodeParameterList || parameters.NamedChildCount() == 0 {
		return false
	}
	if declarator.NamedChildCount() != 2 {
		return false
	}
	for i := 0; i < int(parameters.NamedChildCount()); i++ {
		parameter := parameters.NamedChild(i)
		if parameter.Type() != cppNodeParameterDeclaration || parameter.NamedChildCount() != 1 {
			return false
		}
		typeNode := parameter.ChildByFieldName("type")
		if typeNode == nil || !cppNameReadsAsValue(typeNode) {
			return false
		}
	}
	return true
}

// cppEmptyParameters reports whether a function declarator is `v()` with
// nothing after the list: `T v();`, which declares a function (the most
// vexing parse) and which OpenGrep matches as `T $K(...);`.
func cppEmptyParameters(declarator, parameters *sitter.Node) bool {
	return parameters != nil && parameters.Type() == cNodeParameterList && parameters.NamedChildCount() == 0 && declarator.NamedChildCount() == 2
}

// cppNameReadsAsValue reports whether a type name could be an expression: an
// identifier or a scoped identifier, with no template arguments.
func cppNameReadsAsValue(node *sitter.Node) bool {
	switch node.Type() {
	case cppNodeTypeIdentifier:
		return true
	case cppNodeQualifiedIdentifier:
		scope, name := node.ChildByFieldName("scope"), node.ChildByFieldName("name")
		return scope != nil && scope.Type() == "namespace_identifier" && name != nil && cppNameReadsAsValue(name)
	}
	return false
}

// cppConstructionArguments splits a construction's argument list, `(a, b)` or
// `{a, b}`, into its arguments as written.
func cppConstructionArguments(args *sitter.Node, src []byte) []string {
	if args == nil {
		return nil
	}
	content := strings.TrimSpace(args.Content(src))
	if strings.HasPrefix(content, "{") && strings.HasSuffix(content, "}") {
		content = "(" + content[1:len(content)-1] + ")"
	}
	return parseArgumentsFromDelimitedContent(content)
}

func cppExternDeclaration(node *sitter.Node, src []byte) bool {
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Type() == "storage_class_specifier" && child.Content(src) == "extern" {
			return true
		}
	}
	return false
}

func cppHasChild(node *sitter.Node, kind string) bool {
	for i := 0; i < int(node.ChildCount()); i++ {
		if node.Child(i).Type() == kind {
			return true
		}
	}
	return false
}
