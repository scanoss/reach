// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ruby_attribute_stores.go records `ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE`:
// an assignment whose target is a setter call on an object. Ruby spells the
// write as a call (`verify_mode=`), but what a rule says about it is what it
// says about a Python attribute store -- an attribute, an operator and the
// value written -- so it is recorded as one.

// rubyAttributeStores is every attribute written in body.
func rubyAttributeStores(body *sitter.Node, src []byte) []AttributeStore {
	var stores []AttributeStore
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case rubyNodeMethod, rubyNodeSingletonMethod:
			return // a nested def owns its own body
		case rubyNodeAssignment, rubyNodeOperatorAssignment:
			if store, ok := rubyAttributeStore(n, src); ok {
				stores = append(stores, store)
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(body)
	return stores
}

// rubyAttributeStore reads one assignment whose target is `receiver.attribute`.
func rubyAttributeStore(node *sitter.Node, src []byte) (AttributeStore, bool) {
	left, right := node.ChildByFieldName("left"), node.ChildByFieldName("right")
	if left == nil || right == nil || left.Type() != rubyNodeCall {
		return AttributeStore{}, false
	}
	receiver, method := left.ChildByFieldName("receiver"), left.ChildByFieldName("method")
	if receiver == nil || method == nil {
		return AttributeStore{}, false
	}
	// A call with arguments on the left is not a target: `a.b(c) = d` does
	// not parse, but `a.b[c] = d` reaches here as an element write.
	if left.ChildByFieldName("arguments") != nil {
		return AttributeStore{}, false
	}
	operator := "="
	if node.Type() == rubyNodeOperatorAssignment {
		if op := node.ChildByFieldName("operator"); op != nil {
			operator = op.Content(src)
		}
	}
	start, end := node.StartPoint(), node.EndPoint()
	store := AttributeStore{
		Receiver:  strings.Join(strings.Fields(receiver.Content(src)), ""),
		Attribute: method.Content(src),
		Operator:  operator,
		Line:      int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
		Value: ComparedOperand{Text: strings.TrimSpace(right.Content(src))},
	}
	if end.Row != start.Row {
		store.EndLine = int(end.Row) + 1
	}
	return store, true
}

// rubyModuleAttributeStores is every attribute written outside a method: the
// file's own statements, which its module init owns.
func rubyModuleAttributeStores(root *sitter.Node, src []byte) []AttributeStore {
	var stores []AttributeStore
	for i := 0; i < int(root.ChildCount()); i++ {
		stores = append(stores, rubyAttributeStores(root.Child(i), src)...)
	}
	return stores
}
