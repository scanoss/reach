// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// csharp_attribute_stores.go records `aes.KeySize = 256`: a write to a
// property of an object. A C# property write is an assignment whose left
// side is a member access, and what a rule says about it is what it says
// about a Python attribute store -- a receiver, an attribute, an operator and
// the value written -- so it is recorded as one.

// csharpAttributeStores is every property written in body.
func csharpAttributeStores(body *sitter.Node, src []byte) []AttributeStore {
	var stores []AttributeStore
	csharpWalk(body, func(node *sitter.Node) {
		if node.Type() != csharpNodeAssignment {
			return
		}
		if store, ok := csharpAttributeStore(node, src); ok {
			stores = append(stores, store)
		}
	})
	return stores
}

// csharpAttributeStore reads one assignment whose target is `receiver.name`.
func csharpAttributeStore(node *sitter.Node, src []byte) (AttributeStore, bool) {
	left, right := node.ChildByFieldName("left"), node.ChildByFieldName("right")
	if left == nil || right == nil || left.Type() != csharpNodeMemberAccess {
		return AttributeStore{}, false
	}
	receiver, name := left.ChildByFieldName("expression"), left.ChildByFieldName("name")
	if receiver == nil || name == nil {
		return AttributeStore{}, false
	}
	operator := "="
	if op := node.ChildByFieldName("operator"); op != nil {
		operator = op.Content(src)
	}
	start, end := node.StartPoint(), node.EndPoint()
	store := AttributeStore{
		Receiver:  strings.Join(strings.Fields(receiver.Content(src)), ""),
		Attribute: name.Content(src),
		Operator:  operator,
		Line:      int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
		Value: ComparedOperand{Text: strings.TrimSpace(right.Content(src))},
	}
	if end.Row != start.Row {
		store.EndLine = int(end.Row) + 1
	}
	return store, true
}
