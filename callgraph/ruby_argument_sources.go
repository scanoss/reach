// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ruby_argument_sources.go says where each argument of a Ruby call came
// from. A rule asks what an algorithm argument holds, and the answer is
// rarely written at the call: `digest = "SHA256"` three lines up, a
// parameter the caller passed, an instance variable the constructor set.
// The classification is the same six kinds every other language reports,
// so the export, the conditioned catalog and the taint reading all work on
// Ruby the moment the parser fills them.

// rubyArgumentSources classifies each argument of a call. locals maps a
// local the enclosing body binds to the literal it holds, and params the
// enclosing method's parameter names to their position.
func rubyArgumentSources(node *sitter.Node, src []byte, locals map[string]string, params map[string]int) [][]SourceNode {
	args := node.ChildByFieldName("arguments")
	if args == nil {
		return nil
	}
	out := make([][]SourceNode, 0, args.NamedChildCount())
	for i := 0; i < int(args.NamedChildCount()); i++ {
		child := args.NamedChild(i)
		if child.Type() == rubyNodeComment {
			continue // not an argument; rubyCallArguments skips it too
		}
		out = append(out, []SourceNode{rubyArgumentSource(child, src, locals, params)})
	}
	return out
}

// rubyArgumentSource classifies one argument expression.
func rubyArgumentSource(node *sitter.Node, src []byte, locals map[string]string, params map[string]int) SourceNode {
	text := strings.TrimSpace(node.Content(src))
	switch node.Type() {
	case "string", "symbol", "simple_symbol", "integer", "float", "true", "false", "nil":
		return SourceNode{Type: sourceNodeValue, Value: text}
	case rubyNodeConstant, rubyNodeScopeResolution:
		// A constant is a name whose value the file may state elsewhere;
		// what a rule reads is the name as written.
		return SourceNode{Type: sourceNodeVariable, Name: text}
	case rubyNodeInstanceVariable:
		return SourceNode{Type: sourceNodeField, Name: text}
	case rubyNodeIdentifier:
		if index, ok := params[text]; ok {
			return SourceNode{Type: sourceNodeParameter, Name: text, ParameterIndex: index}
		}
		node := SourceNode{Type: sourceNodeVariable, Name: text}
		if value, ok := locals[text]; ok {
			node.SourceNodes = []SourceNode{{Type: sourceNodeValue, Value: value}}
		}
		return node
	case rubyNodeCall:
		return SourceNode{Type: sourceNodeCallResult, Name: text}
	case "pair":
		// `digest_algorithm: "SHA256"`: what the rule reads is the value.
		if value := node.ChildByFieldName("value"); value != nil {
			return rubyArgumentSource(value, src, locals, params)
		}
	}
	return SourceNode{Type: sourceNodeExpression, Name: text}
}

// rubyBoundLiterals maps each local the body binds exactly once to a literal
// to that literal. Bound twice is two values, which is no single source --
// the same rule the receiver typing follows.
func rubyBoundLiterals(body *sitter.Node, src []byte) map[string]string {
	values, counts := map[string]string{}, map[string]int{}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case rubyNodeMethod, rubyNodeSingletonMethod:
			return
		case rubyNodeAssignment, rubyNodeOperatorAssignment:
			left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
			if left != nil && right != nil && left.Type() == rubyNodeIdentifier {
				name := left.Content(src)
				counts[name]++
				if rubyIsLiteral(right.Type()) {
					values[name] = strings.TrimSpace(right.Content(src))
				}
			}
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(body)
	for name, n := range counts {
		if n != 1 {
			delete(values, name)
		}
	}
	return values
}

// rubyIsLiteral reports a node that is a literal value written in place.
func rubyIsLiteral(typ string) bool {
	switch typ {
	case "string", "symbol", "simple_symbol", "integer", "float", "true", "false", "nil":
		return true
	}
	return false
}

// rubyParameterIndices maps a declaration's parameter names to their order.
func rubyParameterIndices(params []FunctionParameter) map[string]int {
	if len(params) == 0 {
		return nil
	}
	out := make(map[string]int, len(params))
	for i, p := range params {
		name := strings.TrimSpace(p.Name)
		// A keyword or optional parameter is written with its default or
		// colon; the name is what an argument is compared against.
		if cut := strings.IndexAny(name, ":="); cut > 0 {
			name = strings.TrimSpace(name[:cut])
		}
		name = strings.TrimLeft(name, "*&")
		if name != "" {
			out[name] = i
		}
	}
	return out
}
