// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// The scope facts of a C or C++ function body that a syntactic matcher
// reads beside its calls: the #include directives written in the body, its
// local declarations and its assignments to a field of an object. Each
// carries the span of the statement it is, so a reader with the fragment's
// source lines can read the statement as written.

// cBodyIncludes lists the #include directives written inside a function
// body, InFunction set, in source order.
func cBodyIncludes(body *sitter.Node, src []byte) []CInclude {
	var out []CInclude
	walkCNodes(body, func(n *sitter.Node) {
		if n.Type() != cNodePreprocInclude {
			return
		}
		if inc, ok := cIncludeOf(n, src); ok {
			inc.InFunction = true
			out = append(out, inc)
		}
	})
	return out
}

// cDeclarations lists the local declarations of a function body, one per
// declared name: `T a = v, *b;` declares a (Type T) and b (Type T*), the
// type's words joined by one space. The span is the whole declaration, type
// to semicolon. A declaration in a
// nested function-like scope (a block, a for initializer) is listed too.
func cDeclarations(body *sitter.Node, src []byte) []VarDecl {
	var out []VarDecl
	walkCNodes(body, func(n *sitter.Node) {
		if n.Type() != "declaration" {
			return
		}
		base := cDeclaredType(n, src)
		if base == "" {
			return
		}
		start, end := n.StartPoint(), n.EndPoint()
		for i := 0; i < int(n.ChildCount()); i++ {
			child := n.Child(i)
			if n.FieldNameForChild(i) != "declarator" {
				continue
			}
			declarator, init := child, ""
			if child.Type() == "init_declarator" {
				declarator = child.ChildByFieldName("declarator")
				init = cVarInit(child.ChildByFieldName("value"), src)
			}
			name, suffix := cDeclaredName(declarator, src)
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

// cDeclaredType is a declaration's type with its qualifiers (`const char`),
// words joined by one space; storage classes are left out.
func cDeclaredType(n *sitter.Node, src []byte) string {
	if n.ChildByFieldName("type") == nil {
		return ""
	}
	var words []string
	for i := 0; i < int(n.ChildCount()); i++ {
		child := n.Child(i)
		if child.Type() == "type_qualifier" || n.FieldNameForChild(i) == "type" {
			words = append(words, strings.Fields(child.Content(src))...)
		}
	}
	return strings.Join(words, " ")
}

// cDeclaredName reads a declarator's name and the type suffix it adds: `*`
// per pointer, `[]` per array.
func cDeclaredName(n *sitter.Node, src []byte) (string, string) {
	suffix := ""
	for n != nil {
		switch n.Type() {
		case cNodeIdentifier:
			return n.Content(src), suffix
		case "pointer_declarator":
			suffix = "*" + suffix
		case "array_declarator":
			suffix += "[]"
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

// cVarInit is the kind of a declaration's initializer (VarInit*), read
// through parentheses.
func cVarInit(v *sitter.Node, src []byte) string {
	for v != nil && v.Type() == "parenthesized_expression" && v.NamedChildCount() == 1 {
		v = v.NamedChild(0)
	}
	if v == nil {
		return ""
	}
	switch v.Type() {
	case cNodeCallExpression:
		return VarInitCall
	case "cast_expression":
		return VarInitCast
	case "null":
		return VarInitNull
	case cNodeIdentifier:
		if v.Content(src) == "NULL" {
			return VarInitNull
		}
	case cNodeStringLiteral, "concatenated_string", "number_literal", "char_literal", "true", "false":
		return VarInitLiteral
	}
	return VarInitOther
}

// cFieldStores lists a function body's assignments to a field of an object,
// `job->cipher_mode = X` or `cfg.alg |= Y`: the receiver as written and the
// field, without whitespace, the operator, and the span of the assignment.
func cFieldStores(body *sitter.Node, src []byte) []AttributeStore {
	var out []AttributeStore
	walkCNodes(body, func(n *sitter.Node) {
		if n.Type() != "assignment_expression" {
			return
		}
		left, right, op := n.ChildByFieldName("left"), n.ChildByFieldName("right"), n.ChildByFieldName("operator")
		if left == nil || right == nil || op == nil || left.Type() != fieldExpressionNode {
			return
		}
		receiver, field := left.ChildByFieldName("argument"), left.ChildByFieldName("field")
		if receiver == nil || field == nil {
			return
		}
		start, end := n.StartPoint(), n.EndPoint()
		s := AttributeStore{
			Receiver: cNoSpace(receiver.Content(src)), Attribute: field.Content(src), Operator: op.Content(src),
			Line: int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
			Value: ComparedOperand{Text: strings.TrimSpace(right.Content(src))},
		}
		if end.Row != start.Row {
			s.EndLine = int(end.Row) + 1
		}
		out = append(out, s)
	})
	return out
}

// cNoSpace drops the whitespace of text.
func cNoSpace(text string) string {
	return strings.Join(strings.Fields(text), "")
}
