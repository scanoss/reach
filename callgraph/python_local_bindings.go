// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"cmp"
	"slices"

	sitter "github.com/smacker/go-tree-sitter"
)

// LocalBinding is a statement of a Python function (or module or class
// body) that gives one of its local names a value, written for the names a
// function binds more than once with at least one call among the values,
// so a reader can tell which assignment of a local reaches a use without
// the source (reaching definitions): `e = EVP.Cipher("aes_128_cbc", ..);
// e.update(x); e = EVP.Cipher("bf_cbc", ..); e.update(y)` gives each update
// its own cipher. Lines and columns are 1-based.
type LocalBinding struct {
	Name string
	// Line, Col start the binding statement (the assignment, the with item,
	// the for or except clause, the del, import or def statement): a call
	// written between it and the effect point is the value it binds.
	Line, Col int
	// EffectLine, EffectCol are where the name holds the new value: the end
	// of the assignment, with item, del, import or def; the start of the
	// body of a for loop or an except clause.
	EffectLine, EffectCol int
	// BlockEndLine, BlockEndCol end (exclusive) the innermost block that runs
	// the binding whenever it runs: every later use inside that block reads
	// the new value. 0 for a binding that may not run when its block runs
	// (none is written so far).
	BlockEndLine, BlockEndCol int
	// LoopLine, LoopCol start the outermost loop of the function around the
	// binding (a for loop's own target included), whose next iteration
	// reads the value at a use written before the binding; 0 for none.
	LoopLine, LoopCol int
	// Unpacked marks a target of a tuple or list pattern assigned a call
	// (`pub, priv = rsa.newkeys(..)`): the name holds element Element (from
	// 0) of the value of the call that starts at ValueLine, ValueCol.
	Unpacked            bool
	Element             int
	ValueLine, ValueCol int
}

// pythonLocalBindings lists the bindings of the names scope binds more than
// once with at least one call among the values (a parameter counts as one:
// the value a caller passes), and every target of a tuple or list pattern
// assigned a call (with its element), in source order. scope is a
// function body, a class body or a module; its nested functions, classes,
// lambdas and comprehensions bind in their own scopes and are not entered.
// params are the function's parameters, each one more binding of its name.
// A name a `global` or `nonlocal` statement names anywhere in scope (nested
// functions included; the whole file for a module) has no bindings: another
// function may give it a value. A binding a reader cannot place (an
// augmented assignment, an assignment expression, a match capture) is not
// written, but counts toward "more than once": a reader that misses a
// binding keeps more assignments, never fewer.
func pythonLocalBindings(scope *sitter.Node, src []byte, params []string) []LocalBinding {
	if scope == nil {
		return nil
	}
	c := pythonBindingCollector{src: src, count: map[string]int{}, calls: map[string]bool{}, skip: map[string]bool{}}
	for _, p := range params {
		c.count[p]++
		c.calls[p] = true // a parameter rebound in the body: its caller's value may not reach a use
	}
	pythonGlobalNames(scope, src, c.skip)
	c.walk(scope, scope, nil)
	var out []LocalBinding
	for _, b := range c.bindings {
		if (b.Unpacked || c.count[b.Name] >= 2 && c.calls[b.Name]) && !c.skip[b.Name] {
			out = append(out, b)
		}
	}
	slices.SortStableFunc(out, func(a, b LocalBinding) int {
		return cmp.Or(cmp.Compare(a.Line, b.Line), cmp.Compare(a.Col, b.Col), cmp.Compare(a.Name, b.Name))
	})
	return out
}

// pythonGlobalNames adds to names every name a `global` or `nonlocal`
// statement under node names.
func pythonGlobalNames(node *sitter.Node, src []byte, names map[string]bool) {
	switch node.Type() {
	case "global_statement", "nonlocal_statement":
		for i := 0; i < int(node.NamedChildCount()); i++ {
			if child := node.NamedChild(i); child.Symbol() == pythonSyms.identifier {
				names[child.Content(src)] = true
			}
		}
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		pythonGlobalNames(node.NamedChild(i), src, names)
	}
}

type pythonBindingCollector struct {
	src      []byte
	bindings []LocalBinding
	// count is the number of bindings of each name, calls the names some
	// binding assigns a call, skip the names that get no binding.
	count map[string]int
	calls map[string]bool
	skip  map[string]bool
}

// walk visits node, the innermost block around it being block and the
// outermost loop around it loop (nil: none).
func (c *pythonBindingCollector) walk(node, block, loop *sitter.Node) {
	switch node.Type() {
	case "block", "module":
		block = node
	case "function_definition", "class_definition":
		if name := node.ChildByFieldName("name"); name != nil {
			c.add(name.Content(c.src), node, pointAfter(node), block, loop, nil)
		}
		return
	case "lambda", "list_comprehension", "set_comprehension", "dictionary_comprehension", "generator_expression":
		return
	case "for_statement", "while_statement":
		if loop == nil {
			loop = node
		}
		if node.Type() == "for_statement" {
			if body := node.ChildByFieldName("body"); body != nil {
				c.targets(node.ChildByFieldName("left"), node, body.StartPoint(), body, loop, nil)
			}
		}
	case "assignment":
		// The chain's inner assignments are this one's targets: only its
		// value is walked on.
		if value := c.assignment(node, block, loop); value != nil {
			c.walk(value, block, loop)
		}
		return
	case "augmented_assignment":
		c.counts(node.ChildByFieldName("left"))
	case "named_expression":
		c.counts(node.ChildByFieldName("name"))
	case "with_item":
		if value := node.ChildByFieldName("value"); value != nil && value.Type() == "as_pattern" {
			c.targets(value.ChildByFieldName("alias"), node, pointAfter(node), block, loop, pythonCallValue(value.NamedChild(0)))
		}
	case "except_clause":
		var handler *sitter.Node
		for i := 0; i < int(node.NamedChildCount()); i++ {
			if child := node.NamedChild(i); child.Type() == "block" {
				handler = child
			}
		}
		for i := 0; handler != nil && i < int(node.NamedChildCount()); i++ {
			if child := node.NamedChild(i); child.Type() == "as_pattern" {
				c.targets(child.ChildByFieldName("alias"), node, handler.StartPoint(), handler, loop, nil)
			}
		}
	case "delete_statement":
		for i := 0; i < int(node.NamedChildCount()); i++ {
			c.targets(node.NamedChild(i), node, pointAfter(node), block, loop, nil)
		}
	case "import_statement", "import_from_statement":
		c.imports(node, block, loop)
	case "case_pattern":
		c.counts(node)
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		c.walk(node.NamedChild(i), block, loop)
	}
}

// assignment records `a = f()`, `a = b = f()`, `a: T = f()` and the targets
// of a tuple or list pattern (`a, b = f()`, bound to no call).
// It returns the value assigned.
func (c *pythonBindingCollector) assignment(node, block, loop *sitter.Node) *sitter.Node {
	value := node.ChildByFieldName("right")
	for value != nil && value.Symbol() == pythonSyms.assignment {
		value = value.ChildByFieldName("right")
	}
	if value == nil {
		return nil // `a: T` binds nothing
	}
	call := pythonCallValue(value)
	for n := node; n != nil && n.Symbol() == pythonSyms.assignment; n = n.ChildByFieldName("right") {
		left := n.ChildByFieldName("left")
		if call != nil && left != nil && (left.Type() == "pattern_list" || left.Type() == "tuple_pattern" || left.Type() == "list_pattern") {
			c.elements(left, node, block, loop, call)
			continue
		}
		c.targets(left, node, pointAfter(node), block, loop, call)
	}
	return value
}

// elements records each name of a tuple or list pattern assigned a call
// with its position in the pattern, the element of the call's value it
// holds. A name after a starred target (`a, *rest, b`) holds no fixed
// element, nor does one in a nested pattern: each counts, unplaced.
func (c *pythonBindingCollector) elements(pattern, stmt, block, loop, call *sitter.Node) {
	fixed := true
	for i := 0; i < int(pattern.NamedChildCount()); i++ {
		target := pattern.NamedChild(i)
		if target.Type() != "identifier" || !fixed {
			fixed = fixed && target.Type() != "list_splat_pattern"
			c.counts(target)
			continue
		}
		c.add(target.Content(c.src), stmt, pointAfter(stmt), block, loop, call)
		b := &c.bindings[len(c.bindings)-1]
		at := call.StartPoint()
		b.Unpacked, b.Element, b.ValueLine, b.ValueCol = true, i, int(at.Row)+1, int(at.Column)+1
	}
}

// targets records the names target binds: a name, or each name of a tuple
// or list pattern (bound to an element, so to no call); an attribute or a
// subscript binds no local.
func (c *pythonBindingCollector) targets(target, stmt *sitter.Node, effect sitter.Point, block, loop, call *sitter.Node) {
	if target == nil {
		return
	}
	switch target.Type() {
	case "identifier":
		c.add(target.Content(c.src), stmt, effect, block, loop, call)
	case "attribute", "subscript":
	default:
		for i := 0; i < int(target.NamedChildCount()); i++ {
			c.targets(target.NamedChild(i), stmt, effect, block, loop, nil)
		}
	}
}

// imports records the names an import statement inside the scope binds.
func (c *pythonBindingCollector) imports(node, block, loop *sitter.Node) {
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if node.FieldNameForChild(i) != "name" {
			continue
		}
		name := child
		if child.Type() == "aliased_import" {
			name = child.ChildByFieldName("alias")
		} else if child.Type() == "dotted_name" && node.Type() == "import_statement" && child.NamedChildCount() > 0 {
			name = child.NamedChild(0)
		} else if child.Type() == "dotted_name" && child.NamedChildCount() > 0 {
			name = child.NamedChild(int(child.NamedChildCount()) - 1)
		}
		if name != nil {
			c.add(name.Content(c.src), node, pointAfter(node), block, loop, nil)
		}
	}
}

// counts counts the names bound under node without recording a binding.
func (c *pythonBindingCollector) counts(node *sitter.Node) {
	if node == nil {
		return
	}
	if node.Type() == "identifier" {
		c.count[node.Content(c.src)]++
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		c.counts(node.NamedChild(i))
	}
}

func (c *pythonBindingCollector) add(name string, stmt *sitter.Node, effect sitter.Point, block, loop, call *sitter.Node) {
	c.count[name]++
	if call != nil {
		c.calls[name] = true
	}
	start := stmt.StartPoint()
	b := LocalBinding{Name: name, Line: int(start.Row) + 1, Col: int(start.Column) + 1,
		EffectLine: int(effect.Row) + 1, EffectCol: int(effect.Column) + 1}
	if block != nil {
		end := block.EndPoint()
		b.BlockEndLine, b.BlockEndCol = int(end.Row)+1, int(end.Column)+1
	}
	if loop != nil {
		at := loop.StartPoint()
		b.LoopLine, b.LoopCol = int(at.Row)+1, int(at.Column)+1
	}
	c.bindings = append(c.bindings, b)
}

// pythonCallValue is value when it is a call, also in parentheses; nil
// otherwise.
func pythonCallValue(value *sitter.Node) *sitter.Node {
	for value != nil && value.Type() == "parenthesized_expression" && value.NamedChildCount() == 1 {
		value = value.NamedChild(0)
	}
	if value != nil && value.Symbol() == pythonSyms.call {
		return value
	}
	return nil
}

// pointAfter is the position just past node.
func pointAfter(node *sitter.Node) sitter.Point { return node.EndPoint() }
