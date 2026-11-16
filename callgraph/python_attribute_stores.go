// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// AttributeStore is an assignment to an attribute of an object written in a
// function body, `ctx.verify_mode = ssl.CERT_NONE` or `ctx.options |=
// ssl.OP_NO_TLSv1`. A detector reports a rule that names the store at it, as
// OpenGrep does, without the source.
type AttributeStore struct {
	// Receiver is the object written (`ctx`, `self._ctx`) and Attribute the
	// name assigned, both without whitespace; Operator is `=` or the
	// augmented operator (`|=`).
	Receiver, Attribute, Operator string
	// Line, StartCol and EndCol locate the whole assignment (columns 1-based,
	// end exclusive); EndLine is set only when it spans lines.
	Line, StartCol, EndCol, EndLine int
	// Value is the value assigned (the last right side of a chained
	// assignment), traced as a call argument is.
	Value ComparedOperand
}

// pythonAttributeStoreTarget reports an assignment or augmented assignment
// whose target is an attribute of an object.
func pythonAttributeStoreTarget(node *sitter.Node) bool {
	left := node.ChildByFieldName("left")
	return left != nil && left.Symbol() == pythonSyms.attribute
}

// resolvePythonAttributeStores turns a scope's store facts into the stores of
// the function that scope builds.
func (p *PythonParser) resolvePythonAttributeStores(scope *pythonScope, attrs map[string]bool, src []byte, filePath string, analysis *FileAnalysis, fw *pythonFileWalk) []AttributeStore {
	if scope == nil {
		return nil
	}
	var stores []AttributeStore
	for _, fact := range scope.facts {
		if fact.kind != pythonFactStore {
			continue
		}
		n := fact.node
		left := n.ChildByFieldName("left")
		object, attribute := left.ChildByFieldName("object"), left.ChildByFieldName("attribute")
		value := n.ChildByFieldName("right")
		for value != nil && value.Symbol() == pythonSyms.assignment {
			value = value.ChildByFieldName("right")
		}
		if object == nil || attribute == nil || value == nil || pythonFieldStoreOfCall(n, object, value, src) {
			continue
		}
		start, end := n.StartPoint(), n.EndPoint()
		store := AttributeStore{
			Receiver:  strings.Join(strings.Fields(object.Content(src)), ""),
			Attribute: attribute.Content(src),
			Operator:  "=",
			Line:      int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
			Value: ComparedOperand{Text: strings.TrimSpace(value.Content(src))},
		}
		if n.Symbol() == pythonSyms.augmentedAssignment {
			if op := n.ChildByFieldName("operator"); op != nil {
				store.Operator = op.Content(src)
			}
		}
		if end.Row != start.Row {
			store.EndLine = int(end.Row) + 1
		}
		switch value.Type() {
		case "true", "false", "none":
			// The parser traces no source for a keyword constant an
			// argument passes; a store's value is often one.
			store.Value.Sources = []SourceNode{{Type: "VALUE", Value: store.Value.Text}}
		default:
			bindings := pythonBindings{
				layer: fact.layer, attrs: attrs, staticMethod: scope.staticMethod, selfAlias: scope.selfAlias,
				bases: scope.bases, className: scope.className, varTypes: scope.varTypes, locals: &scope.sources,
				classNames: fw.classNames,
			}
			store.Value.Sources = p.pythonArgumentSourceFor(value, src, filePath, analysis, bindings, fw, 0)
		}
		stores = append(stores, store)
	}
	return stores
}

// pythonFieldStoreOfCall reports `self.f = g(..)` (or cls): the call's own
// site names the field it is assigned to (assigned_var `self.f`), so the
// store would repeat it, with the call's text and provenance, for most of a
// class's fields.
func pythonFieldStoreOfCall(store, object, value *sitter.Node, src []byte) bool {
	if store.Symbol() != pythonSyms.assignment || value.Symbol() != pythonSyms.call || !sameSyntaxNode(store.ChildByFieldName("right"), value) {
		return false
	}
	receiver := object.Content(src)
	return receiver == pythonSelfObjectName || receiver == pythonClsObjectName
}
