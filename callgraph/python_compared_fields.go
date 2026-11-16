// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"

	sitter "github.com/smacker/go-tree-sitter"
)

// pythonComparedFieldWrites is the source of a compared field (`self.f` or
// `cls.f` read in a method): a FIELD holding, as VALUE nodes, the fixed
// values its class assigns to it anywhere in its body (`f = X` in the class
// body, `self.f = X` / `cls.f = X` in a method), where X is a plain string,
// an integer or a name rooted in an import. A field set to one constant by
// one method and to another by a second can be either (withFieldWrites'
// Python reading, E2.6c3). nil for any other operand, and when the class
// assigns the field no fixed value. Nested classes and defs are left out,
// and so are the classes the class derives from.
func pythonComparedFieldWrites(operand *sitter.Node, src []byte, analysis *FileAnalysis, bindings pythonBindings, fw *pythonFileWalk) []SourceNode {
	operand = pythonUnparenthesized(operand)
	field, ok := pythonSelfOrClsAttrTarget(operand, src)
	if !ok {
		return nil
	}
	var class *sitter.Node
	for up := operand.Parent(); up != nil; up = up.Parent() {
		if up.Symbol() == pythonSyms.classDefinition {
			class = up
			break
		}
	}
	if class == nil {
		return nil
	}
	// The names of a value are read as the module binds them: the writing
	// method's own bindings are not the comparing one's.
	module := pythonBindings{layer: bindings.layer}
	if fw.moduleScope != nil {
		module.layer = fw.moduleScope.locals
	}
	var values []SourceNode
	add := func(value *sitter.Node) {
		if value == nil {
			return
		}
		node, fixed := pythonFixedValue(value, false, src, analysis, module, fw)
		if fixed && !slices.ContainsFunc(values, func(n SourceNode) bool { return n.Value == node.Value }) {
			values = append(values, node)
		}
	}
	var walk func(node *sitter.Node, method bool)
	walk = func(node *sitter.Node, method bool) {
		for i := 0; i < int(node.NamedChildCount()); i++ {
			child := node.NamedChild(i)
			switch child.Symbol() {
			case pythonSyms.classDefinition:
				continue // a nested class: fields of its own
			case pythonSyms.functionDefinition:
				if method {
					continue // a nested def: its self is another
				}
				walk(child, true)
				continue
			case pythonSyms.assignment:
				left := child.ChildByFieldName("left")
				switch {
				case left == nil:
				case method:
					if name, ok := pythonSelfOrClsAttrTarget(left, src); ok && name == field {
						add(child.ChildByFieldName("right"))
					}
				case left.Symbol() == pythonSyms.identifier && left.Content(src) == field:
					add(child.ChildByFieldName("right"))
				}
			}
			walk(child, method)
		}
	}
	if body := class.ChildByFieldName("body"); body != nil {
		walk(body, false)
	}
	if len(values) == 0 {
		return nil
	}
	return []SourceNode{{Type: sourceNodeField, Name: operand.Content(src), SourceNodes: values}}
}
