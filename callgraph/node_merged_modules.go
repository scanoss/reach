// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"sort"

	sitter "github.com/smacker/go-tree-sitter"
)

// nodeMergedModules lists the module specifiers a receiver name may hold a
// member from when it is bound to an object merging several modules:
//
//	const H = Object.assign({}, require('acme-h/sha256'), require('acme-h/sha3'));
//	const K = { ...require('acme-k/a'), ...b };   // b a module binding
//
// The binding follows the rules a module alias does (nameModuleBinding): the
// declaration the use reads, at module level or in the use's function, holding
// its initializer at the use. An object literal argument of Object.assign and a
// non-spread member of the spread form add nothing and spoil nothing; any other
// argument or spread that is not a module (a require, an awaited import(), or a
// name holding a module binding, the module itself and not a member of it)
// leaves the receiver with no candidates. The result is sorted and unique, nil
// when there are none.
func (p *NodeParser) nodeMergedModules(receiver *sitter.Node) []string {
	x := p.values
	if x == nil || receiver == nil || receiver.Type() != goNodeIdentifier {
		return nil
	}
	d := x.resolve(receiver.Content(x.src), receiver)
	if d == nil || d.writes != 0 || d.value == nil || !x.holdsInitializer(d, receiver) {
		return nil
	}
	parts, ok := p.nodeMergedParts(unwrapNodeValue(d.value))
	if !ok {
		return nil
	}
	seen := make(map[string]bool)
	var modules []string
	for _, part := range parts {
		held, ok := p.valueModuleBinding(part, 0)
		if !ok || held.pending || held.binding.member != "" || held.binding.module == "" {
			return nil
		}
		if !seen[held.binding.module] {
			seen[held.binding.module] = true
			modules = append(modules, held.binding.module)
		}
	}
	sort.Strings(modules)
	return modules
}

// nodeMergedParts returns the values a merging expression combines, object
// literal arguments of Object.assign and non-spread members left out: the
// arguments of `Object.assign(...)`, or the spread operands of an object
// expression. ok is false for any other expression, or one combining nothing.
func (p *NodeParser) nodeMergedParts(value *sitter.Node) (parts []*sitter.Node, ok bool) {
	if value == nil {
		return nil, false
	}
	switch value.Type() {
	case nodeCallExpression:
		if !p.isNodeObjectAssign(value.ChildByFieldName("function")) {
			return nil, false
		}
		for _, arg := range nodeArgumentNodes(value) {
			if arg = unwrapNodeValue(arg); arg != nil && arg.Type() != nodeObjectLiteral {
				parts = append(parts, arg)
			}
		}
	case nodeObjectLiteral:
		for i := 0; i < int(value.NamedChildCount()); i++ {
			member := value.NamedChild(i)
			if member.Type() == "spread_element" && member.NamedChildCount() == 1 {
				parts = append(parts, member.NamedChild(0))
			}
		}
	default:
		return nil, false
	}
	return parts, len(parts) > 0
}

// isNodeObjectAssign reports a callee spelled `Object.assign` where the file
// declares no `Object` of its own.
func (p *NodeParser) isNodeObjectAssign(function *sitter.Node) bool {
	function = unwrapNodeCallee(function)
	if function == nil || function.Type() != nodeMemberExpression {
		return false
	}
	object, property := function.ChildByFieldName("object"), function.ChildByFieldName("property")
	if object == nil || property == nil || object.Type() != goNodeIdentifier {
		return false
	}
	src := p.values.src
	return object.Content(src) == "Object" && property.Content(src) == "assign" && p.values.resolve("Object", object) == nil
}
