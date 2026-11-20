// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// The facts of a C++ file a syntactic matcher reads beside its calls
// (graph-algo-cpp-3): the using directives and declarations, listed with the
// #include directives; the local declarations of each function body, as C's
// are listed; and each function's parameters as written.

const (
	cppNodeUsingDeclaration      = "using_declaration"
	cppNodeOperatorName          = "operator_name"
	cppNodeReferenceDeclarator   = "reference_declarator"
	cppNodeFieldDeclarationList  = "field_declaration_list"
	cppNodeOptionalParameterDecl = "optional_parameter_declaration"
	cppNodeVariadicParameterDecl = "variadic_parameter_declaration"
)

// WrittenParameter is one parameter of a C++ function as the source writes
// it (graph-algo-cpp-3). Type is the declaration without the parameter's name
// and default value, whitespace runs collapsed to one space
// (`const seal::KeyGenerator &` for `const seal::KeyGenerator &kg`,
// `int (*)(int)` for `int (*cb)(int)`, `Args&&...` for `Args&&... args`);
// Name is the parameter's name, "" for an unnamed one. Line, StartCol,
// EndCol and EndLine locate the parameter declaration, default value
// included (columns 1-based, end exclusive; EndLine set only when it spans
// lines).
type WrittenParameter struct {
	Type, Name                      string
	Line, StartCol, EndCol, EndLine int
}

// cppUsingOf reads a using directive (`using namespace a::b;`) or using
// declaration (`using a::b::n;`) as an include entry: no header, Using set,
// Text the directive as written with its whitespace runs collapsed to one
// space, and the span of the statement. ok is false for a using written in
// a class body, which names a member, not a namespace's name, for the file.
func cppUsingOf(node *sitter.Node, src []byte) (CInclude, bool) {
	for parent := node.Parent(); parent != nil && parent.Type() != cppNodeFunctionDefinition; parent = parent.Parent() {
		if parent.Type() == cppNodeFieldDeclarationList {
			return CInclude{}, false
		}
	}
	start, end := node.StartPoint(), node.EndPoint()
	return CInclude{
		Line: int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
		Text: strings.Join(strings.Fields(node.Content(src)), " "), Using: true,
	}, true
}

// cppBodyUsings lists the using directives and declarations written inside
// a function body, InFunction set, in source order.
func cppBodyUsings(body *sitter.Node, src []byte) []CInclude {
	var out []CInclude
	walkCNodes(body, func(n *sitter.Node) {
		if n.Type() != cppNodeUsingDeclaration {
			return
		}
		if using, ok := cppUsingOf(n, src); ok {
			using.InFunction = true
			out = append(out, using)
		}
	})
	return out
}

// cppDeclarations lists the local declarations of a C++ function body as
// cDeclarations lists C's, one per declared name: the type's words joined by
// one space, qualifiers kept, and a suffix per declarator (`*` per pointer,
// `&` or `&&` per reference, `[]` per array), so `const T *p = e;` declares p
// of type `const T*` and `auto &r = e;` r of type `auto&`. The span is the
// whole declaration, type to semicolon. A declaration tree-sitter reads as a
// function's because every argument is a name (`QSslKey key(data,
// QSsl::Rsa)`) declares the variable; `T v();` declares a function and is
// not listed. Init is the initializer's kind (VarInit*): a constructor's
// argument list (`T v(args)`, `T v{args}`), `new T(...)` and `T{...}` are
// calls; "" is a declaration without an initializer (`T v;`).
func cppDeclarations(body *sitter.Node, src []byte) []VarDecl {
	var out []VarDecl
	walkCNodes(body, func(n *sitter.Node) {
		if n.Type() != cppNodeDeclaration {
			return
		}
		base := cDeclaredType(n, src)
		if base == "" {
			return
		}
		constructs := cppConstructedName(n.ChildByFieldName("type"), src) != ""
		start, end := n.StartPoint(), n.EndPoint()
		for i := 0; i < int(n.ChildCount()); i++ {
			if n.FieldNameForChild(i) != "declarator" {
				continue
			}
			name, suffix, init := cppDeclaredVariable(n.Child(i), constructs, src)
			if name == "" {
				continue
			}
			d := VarDecl{
				Type: base + suffix, Name: name, Init: init,
				Line: int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
			}
			if end.Row != start.Row {
				d.EndLine = int(end.Row) + 1
			}
			out = append(out, d)
		}
	})
	return out
}

// cppDeclaredVariable reads one declarator of a declaration: the variable,
// the type suffix the declarator adds and the initializer's kind; name is ""
// for a declarator that declares no variable.
func cppDeclaredVariable(declarator *sitter.Node, constructs bool, src []byte) (name, suffix, init string) {
	switch declarator.Type() {
	case cppNodeInitDeclarator:
		value := declarator.ChildByFieldName("value")
		init = cppVarInit(value, src)
		if value != nil && (value.Type() == "argument_list" || value.Type() == "initializer_list") && !cppHasChild(declarator, "=") {
			init = VarInitOther
			if constructs {
				init = VarInitCall
			}
		}
		declarator = declarator.ChildByFieldName("declarator")
	case cppNodeFunctionDeclarator:
		inner := declarator.ChildByFieldName("declarator")
		if inner == nil || inner.Type() != cNodeIdentifier || !constructs || !cppParametersReadAsArguments(declarator, declarator.ChildByFieldName("parameters")) {
			return "", "", ""
		}
		return inner.Content(src), "", VarInitCall
	}
	name, suffix = cppDeclaredName(declarator, src)
	return name, suffix, init
}

// cppDeclaredName is cDeclaredName that also reads a reference declarator.
func cppDeclaredName(n *sitter.Node, src []byte) (string, string) {
	suffix := ""
	for n != nil {
		switch n.Type() {
		case cNodeIdentifier:
			return n.Content(src), suffix
		case "pointer_declarator":
			suffix = "*" + suffix
		case "array_declarator":
			suffix += "[]"
		case cppNodeReferenceDeclarator:
			ref, inner := "&", (*sitter.Node)(nil)
			for i := 0; i < int(n.ChildCount()); i++ {
				child := n.Child(i)
				switch {
				case child.Type() == "&&":
					ref = "&&"
				case child.IsNamed() && inner == nil:
					inner = child
				}
			}
			suffix = ref + suffix
			n = inner
			continue
		case "parenthesized_declarator":
			n = n.NamedChild(0)
			continue
		default:
			return "", ""
		}
		n = n.ChildByFieldName("declarator")
	}
	return "", ""
}

// cppVarInit is cVarInit with C++'s constructions read as calls: `new T(...)`
// and `T{...}`, and nullptr as null.
func cppVarInit(v *sitter.Node, src []byte) string {
	for v != nil && v.Type() == "parenthesized_expression" && v.NamedChildCount() == 1 {
		v = v.NamedChild(0)
	}
	if v == nil {
		return ""
	}
	switch v.Type() {
	case cppNodeNewExpression, cppNodeCompoundLiteral:
		return VarInitCall
	case "nullptr":
		return VarInitNull
	case "raw_string_literal":
		return VarInitLiteral
	}
	return cVarInit(v, src)
}

// cppWrittenParameters lists a function declarator's parameters as written
// (WrittenParameter), every one in order: also those with a default value
// and a variadic pack, which Parameters leaves out. `f(void)` has none.
func cppWrittenParameters(declarator *sitter.Node, src []byte) []WrittenParameter {
	parameters := cDescendantByType(declarator, cNodeParameterList)
	if parameters == nil {
		return nil
	}
	var out []WrittenParameter
	for i := 0; i < int(parameters.NamedChildCount()); i++ {
		parameter := parameters.NamedChild(i)
		switch parameter.Type() {
		case cppNodeParameterDeclaration, cppNodeOptionalParameterDecl, cppNodeVariadicParameterDecl:
		default:
			continue
		}
		text := cppParameterTypeText(parameter, src)
		name := ""
		if ident := cppDeclaratorIdentifier(parameter.ChildByFieldName("declarator")); ident != nil {
			name = ident.Content(src)
		}
		if text == "void" && name == "" && parameters.NamedChildCount() == 1 {
			return nil
		}
		start, end := parameter.StartPoint(), parameter.EndPoint()
		p := WrittenParameter{
			Type: text, Name: name,
			Line: int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
		}
		if end.Row != start.Row {
			p.EndLine = int(end.Row) + 1
		}
		out = append(out, p)
	}
	return out
}

// cppParameterTypeText is a parameter declaration as written without its
// name and default value, whitespace runs collapsed to one space.
func cppParameterTypeText(parameter *sitter.Node, src []byte) string {
	from, to := parameter.StartByte(), parameter.EndByte()
	if parameter.Type() == cppNodeOptionalParameterDecl {
		if d := parameter.ChildByFieldName("declarator"); d != nil {
			to = d.EndByte()
		} else if t := parameter.ChildByFieldName("type"); t != nil {
			to = t.EndByte()
		}
	}
	text := string(src[from:to])
	if ident := cppDeclaratorIdentifier(parameter.ChildByFieldName("declarator")); ident != nil && ident.StartByte() >= from && ident.EndByte() <= to {
		text = string(src[from:ident.StartByte()]) + string(src[ident.EndByte():to])
	}
	return strings.Join(strings.Fields(text), " ")
}

// cppDeclaratorIdentifier is the identifier a parameter's declarator names,
// read through pointers, references, arrays, parentheses and function
// declarators; nil for an abstract declarator.
func cppDeclaratorIdentifier(n *sitter.Node) *sitter.Node {
	if n == nil {
		return nil
	}
	if n.Type() == cNodeIdentifier {
		return n
	}
	if d := n.ChildByFieldName("declarator"); d != nil {
		return cppDeclaratorIdentifier(d)
	}
	switch n.Type() {
	case cppNodeReferenceDeclarator, "parenthesized_declarator", "variadic_declarator":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if ident := cppDeclaratorIdentifier(n.NamedChild(i)); ident != nil {
				return ident
			}
		}
	}
	return nil
}
