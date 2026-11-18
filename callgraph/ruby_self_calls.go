// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// ruby_self_calls.go records the calls Ruby spells as a bare word. `def
// segments; validate_claims!; combine(encoded_header_and_payload,
// encoded_signature); end` runs three methods of its own class, and only
// the two written with parentheses or arguments are call nodes: a
// receiverless, argumentless call is an identifier, indistinguishable in
// the grammar from a local read. The two are told apart by what the body
// binds — a name the body never binds is not a local — and by what the
// class declares, which only the whole component knows, so the candidate
// carries a mark and resolveRubyLocalCalls drops the ones that bind
// nothing.

// rubyBareSelfCalls is every identifier in body that names no local the
// body binds, as a candidate call on self.
func rubyBareSelfCalls(body *sitter.Node, src []byte, filePath, packagePath string,
	params []FunctionParameter) []FunctionCall {
	bound := rubyBoundLocals(body, src)
	for _, p := range params {
		bound[p.Name] = true
	}
	var calls []FunctionCall
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case rubyNodeMethod, rubyNodeSingletonMethod:
			return // a nested def owns its own body
		case rubyNodeIdentifier:
			if rubyIsBareReference(n) && !bound[n.Content(src)] {
				calls = append(calls, FunctionCall{
					Callee:            FunctionID{Package: packagePath, Name: n.Content(src) + "#0"},
					Raw:               n.Content(src),
					FilePath:          filePath,
					Line:              int(n.StartPoint().Row) + 1,
					StartCol:          int(n.StartPoint().Column) + 1,
					EndLine:           int(n.EndPoint().Row) + 1,
					EndCol:            int(n.EndPoint().Column) + 1,
					ASTKind:           n.Type(),
					RubySelfCandidate: true,
				})
			}
			return
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(body)
	return calls
}

// rubyIsBareReference reports an identifier read on its own: not the method
// or receiver of a call, not a name being bound, and not a parameter.
func rubyIsBareReference(n *sitter.Node) bool {
	parent := n.Parent()
	if parent == nil {
		return false
	}
	switch parent.Type() {
	case rubyNodeCall:
		// The method name and the receiver are read as part of the call.
		return false
	case rubyNodeAssignment, rubyNodeOperatorAssignment:
		return !nodesEqual(parent.ChildByFieldName("left"), n)
	}
	switch {
	case isRubyParameterNode(parent.Type()):
		return false
	case parent.Type() == "block_parameters", parent.Type() == "method_parameters":
		return false
	}
	return true
}

// isRubyParameterNode reports a node type that declares a name rather than
// reading one.
func isRubyParameterNode(typ string) bool {
	switch typ {
	case "optional_parameter", "keyword_parameter", "splat_parameter",
		"hash_splat_parameter", "block_parameter", "destructured_parameter":
		return true
	}
	return false
}

// nodesEqual compares two nodes by span, which identifies a node within one
// tree.
func nodesEqual(a, b *sitter.Node) bool {
	if a == nil || b == nil {
		return false
	}
	return a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte()
}

// rubyBoundLocals is every name the body binds: an assignment target, a
// block parameter, or a `for` variable. A name in this set is a local read,
// never a call.
func rubyBoundLocals(body *sitter.Node, src []byte) map[string]bool {
	bound := make(map[string]bool)
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case rubyNodeAssignment, rubyNodeOperatorAssignment:
			rubyBindNames(n.ChildByFieldName("left"), src, bound)
		case "block_parameters", "method_parameters", "lambda_parameters":
			rubyBindNames(n, src, bound)
		case "for":
			rubyBindNames(n.ChildByFieldName("pattern"), src, bound)
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			walk(n.Child(i))
		}
	}
	walk(body)
	return bound
}

// rubyBindNames records every identifier under node as bound.
func rubyBindNames(node *sitter.Node, src []byte, bound map[string]bool) {
	if node == nil {
		return
	}
	if node.Type() == rubyNodeIdentifier {
		bound[node.Content(src)] = true
		return
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		rubyBindNames(node.Child(i), src, bound)
	}
}
