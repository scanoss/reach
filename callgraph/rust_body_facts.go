// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"cmp"
	"slices"

	sitter "github.com/smacker/go-tree-sitter"
)

// rustBodyFacts collects, during the call walk of a function body, the paths
// it reads outside a call's callee (constant references) and its `let`
// declarations.
type rustBodyFacts struct {
	refs  []ConstantRef
	decls []VarDecl
}

// visit records what node contributes. It reports false for a node whose
// subtree holds no expression the walk should read: a use declaration.
func (f *rustBodyFacts) visit(node *sitter.Node, src []byte) bool {
	switch node.Type() {
	case rustNodeUseDeclaration, rustNodeExternCrate:
		return false
	case rustNodeScopedIdentifier:
		if parent := node.Parent(); parent != nil && parent.Type() != rustNodeScopedIdentifier && !rustIsCallee(node, parent) {
			f.addRef(node, src, rustRefContext(node, parent, src))
		}
	case rustNodeLetDeclaration:
		f.addLet(node, src)
	case "match_block":
		// The walk binds an arm's pattern but does not visit it: a path
		// written as a pattern is a case label.
		for i := 0; i < int(node.NamedChildCount()); i++ {
			if pattern := node.NamedChild(i).ChildByFieldName("pattern"); pattern != nil {
				f.addCaseRefs(pattern, src)
			}
		}
	}
	return true
}

// rustIsCallee reports whether a path is what a call calls: `a::f(..)`,
// `a::f::<T>(..)`.
func rustIsCallee(node, parent *sitter.Node) bool {
	if parent.Type() == rustNodeGenericFunction {
		node, parent = parent, parent.Parent()
		if parent == nil {
			return false
		}
	}
	return parent.Type() == rustNodeCallExpression && sameSyntaxNode(parent.ChildByFieldName("function"), node)
}

// rustRefContext is the position kind of a path whose parent is parent,
// read through parentheses.
func rustRefContext(node, parent *sitter.Node, src []byte) string {
	for parent.Type() == rustNodeParenthesizedExpression {
		node, parent = parent, parent.Parent()
		if parent == nil {
			return ConstantRefOther
		}
	}
	switch parent.Type() {
	case "binary_expression":
		if op := parent.ChildByFieldName("operator"); op != nil && (op.Content(src) == "==" || op.Content(src) == "!=") {
			return ConstantRefCompare
		}
	case rustNodeReturnExpression:
		return ConstantRefReturn
	case rustNodeAssignmentExpression, "compound_assignment_expr":
		if sameSyntaxNode(parent.ChildByFieldName("right"), node) {
			return ConstantRefAssign
		}
	case rustNodeLetDeclaration, rustNodeConstItem, rustNodeStaticItem:
		if sameSyntaxNode(parent.ChildByFieldName("value"), node) {
			return ConstantRefInit
		}
	case "array_expression":
		return ConstantRefArray
	case "arguments":
		return ConstantRefArg
	}
	return ConstantRefOther
}

// addCaseRefs records the paths a match arm's pattern names, also as an
// alternative of an or-pattern.
func (f *rustBodyFacts) addCaseRefs(pattern *sitter.Node, src []byte) {
	for i := 0; i < int(pattern.NamedChildCount()); i++ {
		switch child := pattern.NamedChild(i); child.Type() {
		case rustNodeScopedIdentifier:
			f.addRef(child, src, ConstantRefCase)
		case "or_pattern":
			f.addCaseRefs(child, src)
		}
	}
}

func (f *rustBodyFacts) addRef(node *sitter.Node, src []byte, context string) {
	ref := ConstantRef{Text: rustTokenText(node.Content(src)), Context: context}
	ref.Line, ref.StartCol, ref.EndCol, ref.EndLine = rustSpan(node)
	f.refs = append(f.refs, ref)
}

// addLet records one declaration per name a `let` binds through identifier,
// `mut`, `ref` and tuple patterns; a let whose pattern names a type
// (`Some(x)`, `Point { .. }`) or is `_` declares none here.
func (f *rustBodyFacts) addLet(node *sitter.Node, src []byte) {
	decl := VarDecl{Type: rustTokenText(nodeFieldText(node, "type", src)), Init: rustLetInit(node.ChildByFieldName("value"))}
	decl.Line, decl.StartCol, decl.EndCol, decl.EndLine = rustSpan(node)
	var bind func(pattern *sitter.Node)
	bind = func(pattern *sitter.Node) {
		if pattern == nil {
			return
		}
		switch pattern.Type() {
		case rustNodeIdentifier:
			d := decl
			d.Name = pattern.Content(src)
			f.decls = append(f.decls, d)
		case rustNodeMutPattern, rustNodeRefPattern, "tuple_pattern":
			for i := 0; i < int(pattern.NamedChildCount()); i++ {
				bind(pattern.NamedChild(i))
			}
		}
	}
	bind(node.ChildByFieldName("pattern"))
}

// rustLetInit is the kind of a let's initializer (VarInit*), read through
// parentheses, `?` and `.await`; "" when there is none.
func rustLetInit(value *sitter.Node) string {
	if value == nil {
		return ""
	}
	for {
		switch value.Type() {
		case rustNodeParenthesizedExpression, rustNodeTryExpression, rustNodeAwaitExpression:
			if inner := value.NamedChild(0); inner != nil {
				value = inner
				continue
			}
		case rustNodeCallExpression:
			return VarInitCall
		case "type_cast_expression":
			return VarInitCast
		case rustNodeStringLiteral, rustNodeRawStringLiteral, "integer_literal", "float_literal", "boolean_literal", "char_literal":
			return VarInitLiteral
		}
		return VarInitOther
	}
}

// sorted returns the references and declarations ordered by position.
func (f *rustBodyFacts) sorted() ([]ConstantRef, []VarDecl) {
	slices.SortStableFunc(f.refs, func(a, b ConstantRef) int {
		return cmp.Or(cmp.Compare(a.Line, b.Line), cmp.Compare(a.StartCol, b.StartCol))
	})
	slices.SortStableFunc(f.decls, func(a, b VarDecl) int {
		return cmp.Or(cmp.Compare(a.Line, b.Line), cmp.Compare(a.StartCol, b.StartCol))
	})
	return f.refs, f.decls
}
