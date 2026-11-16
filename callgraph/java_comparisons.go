// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// ComparedOperand is what a constant is compared with: the other operand of
// `==` / `!=`, the receiver or argument of `equals` on the other side, or the
// subject of the `switch` whose `case` label names the constant. Sources
// traces its value like a call argument's, so a detector reports the constant
// only when that value can be the constant.
type ComparedOperand struct {
	// Text is the operand as written, without surrounding whitespace.
	Text    string
	Sources []SourceNode
}

// comparedSide maps the byte span of one side of a comparison to the operand
// it is compared with: a constant reference inside the span is compared with
// operand.
type comparedSide struct {
	start, end uint32
	operand    ComparedOperand
}

// recordComparedOperands notes, for a comparison node, each side's operand
// traced with the scope's origins, for collectJavaConstantRefs to attach to
// the constant references written on that side.
func (p *JavaParser) recordComparedOperands(node *sitter.Node, src []byte, analysis *FileAnalysis, currentClass string, varTypes map[string]string, varOrigins map[string]varOrigin) {
	pair := func(side, other *sitter.Node) {
		if side == nil || other == nil {
			return
		}
		text := strings.TrimSpace(other.Content(src))
		sources := withFieldWrites(p.traceExpression(text, analysis, currentClass, varTypes, varOrigins, 0), other, node, src)
		p.comparedSides = append(p.comparedSides, comparedSide{
			start: side.StartByte(), end: side.EndByte(),
			operand: ComparedOperand{Text: text, Sources: sources},
		})
	}
	switch node.Type() {
	case "binary_expression":
		if !javaEqualityOperator(node, src) {
			return
		}
		left, right := node.ChildByFieldName("left"), node.ChildByFieldName("right")
		pair(left, right)
		pair(right, left)
	case "method_invocation":
		if !javaEqualsCall(node, src) {
			return
		}
		args := node.ChildByFieldName("arguments")
		object := node.ChildByFieldName("object")
		if args == nil || args.NamedChildCount() != 1 || object == nil {
			return
		}
		pair(object, args.NamedChild(0))
		pair(args.NamedChild(0), object)
	case "switch_expression", "switch_statement":
		subject := unwrapJavaParenthesizedExpression(node.ChildByFieldName("condition"))
		body := node.ChildByFieldName("body")
		if subject == nil || body == nil {
			return
		}
		for _, label := range javaSwitchLabels(body) {
			pair(label, subject)
		}
	}
}

func javaEqualityOperator(node *sitter.Node, src []byte) bool {
	op := node.ChildByFieldName("operator")
	return op != nil && (op.Type() == "==" || op.Type() == "!=")
}

// javaSwitchLabels lists the case labels of a switch body, in both the
// statement-group and the arrow form.
func javaSwitchLabels(body *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	for i := 0; i < int(body.NamedChildCount()); i++ {
		group := body.NamedChild(i)
		for j := 0; j < int(group.NamedChildCount()); j++ {
			if label := group.NamedChild(j); label.Type() == "switch_label" {
				out = append(out, label)
			}
		}
	}
	return out
}

// comparedOperandAt is the operand compared with the constant reference at
// [start, end), if a recorded comparison side contains it.
func comparedOperandAt(sides []comparedSide, start, end uint32) *ComparedOperand {
	var best *comparedSide
	for i := range sides {
		s := &sides[i]
		if s.start <= start && end <= s.end && (best == nil || s.end-s.start < best.end-best.start) {
			best = s
		}
	}
	if best == nil {
		return nil
	}
	operand := best.operand
	return &operand
}

// withFieldWrites adds to a compared field (`f` or `this.f` tracing to a
// FIELD node) the literals and qualified constants its class assigns to it
// anywhere in its body (an initializer, `this.f = X`, or `f = X` in a member
// that declares no local or parameter f), as VALUE nodes: a field set to
// one constant by one constructor and to another by a second can be either.
func withFieldWrites(sources []SourceNode, operand, at *sitter.Node, src []byte) []SourceNode {
	if len(sources) != 1 || sources[0].Type != sourceNodeField {
		return sources
	}
	name := strings.TrimPrefix(strings.TrimSpace(operand.Content(src)), "this.")
	body := at
	for body != nil && body.Type() != javaNodeClassBody && body.Type() != javaNodeEnumBody {
		body = body.Parent()
	}
	if body == nil || !javaIsName(name) {
		return sources
	}
	values := javaFieldFixedWrites(body, src, name, nil)
	if len(values) == 0 {
		return sources
	}
	out := append([]SourceNode(nil), sources...)
	field := out[0]
	field.SourceNodes = append(append([]SourceNode(nil), field.SourceNodes...), values...)
	out[0] = field
	return out
}

// javaFieldFixedWrites walks a class body, not its nested or anonymous types, for the
// fixed values written to field name. member is the method, constructor or
// field declaration being walked.
func javaFieldFixedWrites(node *sitter.Node, src []byte, name string, member *sitter.Node) []SourceNode {
	var out []SourceNode
	add := func(value *sitter.Node) {
		if value == nil {
			return
		}
		if text := strings.TrimSpace(value.Content(src)); javaFixedValue(text) {
			out = append(out, SourceNode{Type: "VALUE", Name: text, Value: text})
		}
	}
	switch node.Type() {
	case "method_declaration", "constructor_declaration":
		member = node
	case javaNodeFieldDeclaration:
		for i := 0; i < int(node.NamedChildCount()); i++ {
			d := node.NamedChild(i)
			if d.Type() == javaNodeVariableDeclarator && javaDeclaredName(d, src) == name {
				add(d.ChildByFieldName("value"))
			}
		}
		return out
	case javaNodeAssignmentExpression:
		left := node.ChildByFieldName("left")
		if left != nil {
			target := strings.TrimSpace(left.Content(src))
			if target == "this."+name || (target == name && member != nil && !javaDeclaresLocal(member, src, name)) {
				add(node.ChildByFieldName("right"))
			}
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		switch child.Type() {
		case javaNodeClassDeclaration, javaNodeInterfaceDeclaration, "enum_declaration", "record_declaration", javaNodeClassBody:
			continue // a nested type, or an anonymous class body: fields of their own
		}
		out = append(out, javaFieldFixedWrites(child, src, name, member)...)
	}
	return out
}

func javaDeclaredName(declarator *sitter.Node, src []byte) string {
	if n := declarator.ChildByFieldName("name"); n != nil {
		return n.Content(src)
	}
	return ""
}

// javaDeclaresLocal: member has a parameter or a local variable named name,
// so a bare `name = ...` in it may not write the field.
func javaDeclaresLocal(member *sitter.Node, src []byte, name string) bool {
	found := false
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if found {
			return
		}
		switch n.Type() {
		case javaNodeFormalParameter, "spread_parameter", "catch_formal_parameter", javaNodeVariableDeclarator:
			if javaDeclaredName(n, src) == name {
				found = true
				return
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(member)
	return found
}
