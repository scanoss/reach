// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// pythonDeclaredTypeRecorded: an annotated assignment of this type is a
// recorded declaration (VarDecl). Builtin scalars, str, bytes, object and Any
// are left out, as Java leaves out primitives, String and Object: no rule
// names them.
func pythonDeclaredTypeRecorded(declType string) bool {
	switch declType {
	case "", "int", "float", "bool", "complex", "str", "bytes", "object", "None", "Any", "typing.Any":
		return false
	}
	return true
}

// resolvePythonDeclarations turns a scope's annotated assignments (`x: T =
// v`, `self.key: T = v`, a class body's `field: T`) into declarations, and
// its `typing.cast(T, f(..))` calls into casts. The span of a declaration is
// the assignment, of a cast the cast call; a cast is recorded only around a
// call, as Java's.
func resolvePythonDeclarations(scope *pythonScope, src []byte, analysis *FileAnalysis) ([]VarDecl, []CastExpr) {
	if scope == nil {
		return nil, nil
	}
	var declarations []VarDecl
	var casts []CastExpr
	for _, fact := range scope.facts {
		n := fact.node
		start, end := n.StartPoint(), n.EndPoint()
		endLine := 0
		if end.Row != start.Row {
			endLine = int(end.Row) + 1
		}
		switch fact.kind {
		case pythonFactDeclaration:
			typeNode, left := n.ChildByFieldName("type"), n.ChildByFieldName("left")
			declType := strings.Join(strings.Fields(typeNode.Content(src)), "")
			if !pythonDeclaredTypeRecorded(declType) {
				continue
			}
			declarations = append(declarations, VarDecl{
				Type: declType, Name: strings.Join(strings.Fields(left.Content(src)), ""),
				Line: int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1, EndLine: endLine,
				Init: pythonVarInitKind(n.ChildByFieldName("right"), src, analysis),
			})
		case pythonFactCast:
			if pythonCastType(n, src, analysis) == "" {
				continue
			}
			args := pythonArgumentListChild(n)
			inner := pythonUnparenthesized(args.NamedChild(1))
			if inner.Symbol() != pythonSyms.call {
				continue
			}
			casts = append(casts, CastExpr{
				Type: strings.Join(strings.Fields(args.NamedChild(0).Content(src)), ""),
				Line: int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1, EndLine: endLine,
				InnerLine: int(inner.StartPoint().Row) + 1, InnerCol: int(inner.StartPoint().Column) + 1,
			})
		}
	}
	return declarations, casts
}

// pythonCastCandidate reports a call spelled as typing's cast, `cast(..)` or
// `<name>.cast(..)`; resolvePythonDeclarations checks the import.
func pythonCastCandidate(call *sitter.Node, src []byte) bool {
	fn := call.ChildByFieldName("function")
	if fn == nil {
		return false
	}
	switch fn.Symbol() {
	case pythonSyms.identifier:
		return fn.Content(src) == "cast"
	case pythonSyms.attribute:
		attr := fn.ChildByFieldName("attribute")
		return attr != nil && attr.Content(src) == "cast"
	}
	return false
}

func pythonUnparenthesized(n *sitter.Node) *sitter.Node {
	for n != nil && n.Type() == "parenthesized_expression" && n.NamedChildCount() == 1 {
		n = n.NamedChild(0)
	}
	return n
}

// pythonVarInitKind is the kind of an annotated assignment's value (VarInit*),
// read through parentheses; "" for a declaration without one.
func pythonVarInitKind(value *sitter.Node, src []byte, analysis *FileAnalysis) string {
	value = pythonUnparenthesized(value)
	if value == nil {
		return ""
	}
	switch value.Type() {
	case "call":
		if pythonCastType(value, src, analysis) != "" {
			return VarInitCast
		}
		return VarInitCall
	case "none":
		return VarInitNull
	case "string", "concatenated_string", "integer", "float", "true", "false":
		return VarInitLiteral
	}
	return VarInitOther
}

// pythonAbstractMethod reports a method a call on its class may not run:
// one decorated `@abstractmethod` (or abc's abstractproperty,
// abstractclassmethod, abstractstaticmethod), a stub (a docstring, `...`,
// `pass`) of a Protocol class, or one whose body only raises
// NotImplementedError.
func pythonAbstractMethod(node, body *sitter.Node, src []byte) bool {
	if decorated := node.Parent(); decorated != nil && decorated.Symbol() == pythonSyms.decoratedDefinition {
		for i := 0; i < int(decorated.NamedChildCount()); i++ {
			decorator := decorated.NamedChild(i)
			if decorator.Symbol() != pythonSyms.decorator || decorator.NamedChildCount() == 0 {
				continue
			}
			name := decorator.NamedChild(0).Content(src)
			switch name[strings.LastIndexByte(name, '.')+1:] {
			case "abstractmethod", "abstractproperty", "abstractclassmethod", "abstractstaticmethod":
				return true
			}
		}
	}
	if body == nil {
		return false
	}
	stub, raises := true, false
	for i := 0; i < int(body.NamedChildCount()); i++ {
		stmt := body.NamedChild(i)
		switch stmt.Type() {
		case pythonNodeComment, "pass_statement":
			continue
		case "expression_statement":
			if stmt.NamedChildCount() == 1 {
				if t := stmt.NamedChild(0).Type(); t == "string" || t == "ellipsis" {
					continue
				}
			}
		case "raise_statement":
			if stmt.NamedChildCount() >= 1 && pythonRaisesNotImplemented(stmt.NamedChild(0), src) {
				raises = true
				continue
			}
		}
		stub = false
		break
	}
	if !stub {
		return false
	}
	if raises {
		return true
	}
	return pythonInProtocolClass(node, src)
}

// pythonInProtocolClass reports a method of a class one of whose bases is
// Protocol (`Protocol`, `typing.Protocol`, `Protocol[T]`).
func pythonInProtocolClass(method *sitter.Node, src []byte) bool {
	class := method.Parent()
	for class != nil && class.Symbol() != pythonSyms.classDefinition {
		class = class.Parent()
	}
	if class == nil {
		return false
	}
	supers := class.ChildByFieldName("superclasses")
	if supers == nil {
		return false
	}
	for i := 0; i < int(supers.NamedChildCount()); i++ {
		base := supers.NamedChild(i)
		if base.Symbol() == pythonSyms.subscript {
			base = base.ChildByFieldName("value")
		}
		if base == nil {
			continue
		}
		if name := base.Content(src); name == "Protocol" || strings.HasSuffix(name, ".Protocol") {
			return true
		}
	}
	return false
}

// pythonRaisesNotImplemented reports `NotImplementedError` or
// `NotImplementedError(..)`.
func pythonRaisesNotImplemented(exc *sitter.Node, src []byte) bool {
	if exc.Symbol() == pythonSyms.call {
		exc = exc.ChildByFieldName("function")
	}
	return exc != nil && exc.Content(src) == "NotImplementedError"
}
