// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// pythonBranchRefinement is the source of name at use when a guard around
// the use fixes its value (javaBranchRefinement's Python reading), nil when
// none does. Inside the body of `if v == X:` / `elif X == v:` (also as one
// `and` conjunct), of `if v in (X, Y):` (a tuple, list or set display) and
// of `case X:` / `case X | Y:` of `match v:` (with or without a guard), v is
// X, or one of X and Y. X is a plain string or integer literal, or a dotted
// name rooted in an import or a class of the module (`hashes.SHA256`,
// compared with `==` or `is`).
//
// One value is the VALUE of a VARIABLE, as an assigned literal traces;
// several strings are its may-values, exhaustive (E1.3a); several values of
// which one is no string are VALUE nodes side by side. The innermost guard
// that names the variable decides. Nothing is refined by an else branch, a
// negated or `or` condition, `!=` / `not in`, a pattern that captures,
// destructures or matches a class, a value that is no fixed one, a body
// that binds v again, or across a nested def or class.
func pythonBranchRefinement(use *sitter.Node, name string, src []byte, analysis *FileAnalysis, bindings pythonBindings, fw *pythonFileWalk) []SourceNode {
	child := use
	for parent := use.Parent(); parent != nil; child, parent = parent, parent.Parent() {
		var values []*sitter.Node
		identity := false
		switch parent.Symbol() {
		case pythonSyms.functionDefinition, pythonSyms.classDefinition:
			return nil
		case pythonSyms.ifStatement, pythonSyms.elifClause:
			if !sameSyntaxNode(parent.ChildByFieldName("consequence"), child) {
				continue
			}
			values, identity = pythonGuardValues(parent.ChildByFieldName("condition"), name, src)
		case pythonSyms.caseClause:
			// The body, or the guard: both run once the pattern matched.
			values = pythonCaseValues(parent, name, src)
		default:
			continue
		}
		if len(values) == 0 || pythonBindsName(child, name, src) {
			continue
		}
		if nodes := pythonFixedValueSources(values, identity, name, src, analysis, bindings, fw); nodes != nil {
			return nodes
		}
	}
	return nil
}

// pythonGuardValues are the values a condition that holds leaves name: the
// other side of `name == X`, the elements of `name in (X, Y)`, read from the
// condition itself or from its first `and` conjunct that names one.
// identity reports an `is` test, which fixes a value only for a dotted name.
func pythonGuardValues(cond *sitter.Node, name string, src []byte) (values []*sitter.Node, identity bool) {
	cond = pythonUnparenthesized(cond)
	if cond == nil {
		return nil, false
	}
	switch cond.Type() {
	case "boolean_operator":
		if op := cond.ChildByFieldName("operator"); op == nil || op.Content(src) != "and" {
			return nil, false
		}
		if values, identity = pythonGuardValues(cond.ChildByFieldName("left"), name, src); len(values) > 0 {
			return values, identity
		}
		return pythonGuardValues(cond.ChildByFieldName("right"), name, src)
	case "comparison_operator":
		var operands []*sitter.Node
		operator := ""
		for i := 0; i < int(cond.ChildCount()); i++ {
			switch c := cond.Child(i); {
			case !c.IsNamed():
				operator = strings.TrimSpace(operator + " " + c.Content(src))
			case c.Type() != pythonNodeComment:
				operands = append(operands, c)
			}
		}
		if len(operands) != 2 {
			return nil, false // a chained comparison
		}
		left, right := pythonUnparenthesized(operands[0]), pythonUnparenthesized(operands[1])
		named := func(n *sitter.Node) bool {
			return n.Symbol() == pythonSyms.identifier && n.Content(src) == name
		}
		switch operator {
		case "==", "is":
			switch {
			case named(left):
				return []*sitter.Node{right}, operator == "is"
			case named(right):
				return []*sitter.Node{left}, operator == "is"
			}
		case "in":
			if !named(left) {
				return nil, false
			}
			switch right.Type() {
			case "tuple", "list", "set":
				for i := 0; i < int(right.NamedChildCount()); i++ {
					if c := right.NamedChild(i); c.Type() != pythonNodeComment {
						values = append(values, c)
					}
				}
				return values, false
			}
		}
	}
	return nil, false
}

// pythonCaseValues are the values the one pattern of a case clause of
// `match name:` matches: a literal, a dotted name, or alternatives of those.
func pythonCaseValues(clause *sitter.Node, name string, src []byte) []*sitter.Node {
	subject := pythonMatchSubject(clause)
	if subject == nil || subject.Symbol() != pythonSyms.identifier || subject.Content(src) != name {
		return nil
	}
	var pattern *sitter.Node
	for i := 0; i < int(clause.NamedChildCount()); i++ {
		if c := clause.NamedChild(i); c.Symbol() == pythonSyms.casePattern {
			if pattern != nil {
				return nil // `case a, b:` matches a sequence
			}
			pattern = c
		}
	}
	if pattern == nil || pattern.NamedChildCount() != 1 {
		return nil // the wildcard
	}
	value := pattern.NamedChild(0)
	if value.Type() != "union_pattern" {
		return []*sitter.Node{value}
	}
	var values []*sitter.Node
	for i := 0; i < int(value.NamedChildCount()); i++ {
		values = append(values, value.NamedChild(i))
	}
	return values
}

// pythonFixedValueSources is the source of name holding one of values, nil
// when a value is not fixed (pythonFixedValue).
func pythonFixedValueSources(values []*sitter.Node, identity bool, name string, src []byte, analysis *FileAnalysis, bindings pythonBindings, fw *pythonFileWalk) []SourceNode {
	var nodes []SourceNode
	for _, value := range values {
		node, ok := pythonFixedValue(value, identity, src, analysis, bindings, fw)
		if !ok {
			return nil
		}
		nodes = append(nodes, node)
	}
	return pythonVariableHolding(name, nodes)
}

// pythonFixedValue is the VALUE node of an expression whose value does not
// depend on the program's state: a plain string, an integer, or a name the
// module binds once to an import or a class (dotted, or from-imported),
// which stays as written unless it is a str enum member, folded into its
// string. identity admits names only.
func pythonFixedValue(value *sitter.Node, identity bool, src []byte, analysis *FileAnalysis, bindings pythonBindings, fw *pythonFileWalk) (node SourceNode, ok bool) {
	text := strings.Join(strings.Fields(value.Content(src)), "")
	node = SourceNode{Type: sourceNodeValue, Value: text}
	switch value.Symbol() {
	case pythonSyms.string:
		node.Value = value.Content(src)
		return node, !identity && pythonPlainString(value, src)
	case pythonSyms.integer:
		return node, !identity
	case pythonSyms.attribute, pythonSyms.dottedName, pythonSyms.identifier:
		ref := pythonNamedValueRef(text, analysis, bindings, fw)
		if ref == nil {
			return node, false
		}
		ref.placeholder = false
		node.nameRef = ref
		return node, true
	}
	return node, false
}

// pythonPlainStringValue reports a VALUE node that is a plain string literal.
func pythonPlainStringValue(node *SourceNode) bool {
	return node.Type == sourceNodeValue && (strings.HasPrefix(node.Value, `"`) || strings.HasPrefix(node.Value, "'"))
}

// pythonVariableHolding is the VARIABLE name holding one of values: one
// value is its source; several plain strings are its exhaustive may-values
// (E1.3a); several values of which one is no plain string are sources side
// by side. A value written twice counts once.
func pythonVariableHolding(name string, values []SourceNode) []SourceNode {
	var nodes []SourceNode
	plain := true
	for _, value := range values {
		if !slices.ContainsFunc(nodes, func(n SourceNode) bool { return n.Value == value.Value }) {
			nodes = append(nodes, value)
			plain = plain && pythonPlainStringValue(&value)
		}
	}
	if len(nodes) == 0 {
		return nil
	}
	if len(nodes) > 1 && plain {
		literals := make([]string, len(nodes))
		for i := range nodes {
			literals[i] = nodes[i].Value
		}
		return []SourceNode{{Type: sourceNodeVariable, Name: name, MayValues: literals, MayValuesExhaustive: true}}
	}
	return []SourceNode{{Type: sourceNodeVariable, Name: name, SourceNodes: nodes}}
}

// pythonBindsName reports that node binds name somewhere inside it: an
// assignment, augmented assignment, loop, comprehension, walrus, `as`
// target, import, def, class, lambda parameter, global / nonlocal / del
// statement or a case pattern names it.
func pythonBindsName(node *sitter.Node, name string, src []byte) bool {
	var target *sitter.Node
	switch node.Symbol() {
	case pythonSyms.assignment, pythonSyms.augmentedAssignment, pythonSyms.forStatement, pythonSyms.forInClause:
		target = node.ChildByFieldName("left")
	case pythonSyms.namedExpression, pythonSyms.classDefinition:
		target = node.ChildByFieldName(pythonFieldName)
	case pythonSyms.asPattern:
		target = node.ChildByFieldName("alias")
	case pythonSyms.functionDefinition:
		if pythonNamesIdentifier(node.ChildByFieldName(pythonFieldName), name, src) {
			return true
		}
		target = node.ChildByFieldName("parameters")
	case pythonSyms.lambdaParameters, pythonSyms.importStatement, pythonSyms.importFromStatement, pythonSyms.globalStatement,
		pythonSyms.nonlocalStatement, pythonSyms.deleteStatement, pythonSyms.casePattern:
		target = node
	}
	if target != nil && pythonNamesIdentifier(target, name, src) {
		return true
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if pythonBindsName(node.NamedChild(i), name, src) {
			return true
		}
	}
	return false
}

// pythonNamesIdentifier reports an identifier name inside a binding target.
// An attribute or subscript target binds no name.
func pythonNamesIdentifier(target *sitter.Node, name string, src []byte) bool {
	if target == nil {
		return false
	}
	switch target.Symbol() {
	case pythonSyms.identifier:
		return target.Content(src) == name
	case pythonSyms.attribute, pythonSyms.subscript:
		return false
	}
	for i := 0; i < int(target.NamedChildCount()); i++ {
		if pythonNamesIdentifier(target.NamedChild(i), name, src) {
			return true
		}
	}
	return false
}
