// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// javaBranchRefinement: the origins a branch of parent sees when child is
// that branch and parent's guard fixes the value of a local or a parameter
// in it. Inside `if (v == X)` / `if (X.equals(v))` / `if (v.equals(X))` (also
// as one `&&` conjunct) the then-branch, and inside `case X:` / `case X ->`
// of `switch (v)` the case body, v is X: the result maps v to a local whose
// initializer is X, so the calls of the branch trace v to X as they trace an
// assigned literal. Nothing is refined (nil) when the guard is anything else,
// a label names more than one value or is `default`, a statement group can be
// entered by falling through from the one before it, X is not a literal or a
// qualified constant, or the branch writes v.
func javaBranchRefinement(parent, child *sitter.Node, src []byte, origins map[string]varOrigin) map[string]varOrigin {
	var guards map[string]string
	switch parent.Type() {
	case "if_statement":
		if !javaSameNode(parent.ChildByFieldName("consequence"), child) {
			return nil
		}
		guards = map[string]string{}
		javaEqualityGuards(unwrapJavaParenthesizedExpression(parent.ChildByFieldName("condition")), src, guards)
	case javaNodeSwitchBlock:
		switchNode := parent.Parent()
		if switchNode == nil || (child.Type() != javaNodeSwitchBlockStmtGroup && child.Type() != javaNodeSwitchRule) {
			return nil
		}
		subject := unwrapJavaParenthesizedExpression(switchNode.ChildByFieldName("condition"))
		value, ok := javaSingleCaseValue(child, src)
		if subject == nil || !ok || (child.Type() == javaNodeSwitchBlockStmtGroup && javaFallsInto(child)) {
			return nil
		}
		guards = map[string]string{strings.TrimSpace(subject.Content(src)): value}
	default:
		return nil
	}
	var refined map[string]varOrigin
	for name, value := range guards {
		origin, ok := origins[name]
		if !ok || origin.kind == javaVarOriginKindField || !javaFixedValue(value) || javaWrites(child, src, name) {
			continue
		}
		if refined == nil {
			refined = make(map[string]varOrigin, len(origins))
			for k, v := range origins {
				refined[k] = v
			}
		}
		refined[name] = varOrigin{typeName: origin.typeName, kind: "local_variable", initializer: value, line: origin.line,
			filePath: origin.filePath, paramIndex: -1}
	}
	return refined
}

// javaEqualityGuards collects name -> value for each `name == value`,
// `value.equals(name)` or `name.equals(value)` conjunct of a condition.
func javaEqualityGuards(cond *sitter.Node, src []byte, out map[string]string) {
	cond = unwrapJavaParenthesizedExpression(cond)
	if cond == nil {
		return
	}
	add := func(a, b *sitter.Node) {
		a, b = unwrapJavaParenthesizedExpression(a), unwrapJavaParenthesizedExpression(b)
		if a == nil || b == nil {
			return
		}
		if a.Type() == javaNodeIdentifier {
			out[a.Content(src)] = strings.TrimSpace(b.Content(src))
		} else if b.Type() == javaNodeIdentifier {
			out[b.Content(src)] = strings.TrimSpace(a.Content(src))
		}
	}
	switch cond.Type() {
	case "binary_expression":
		op := cond.ChildByFieldName("operator")
		switch {
		case op != nil && op.Type() == "&&":
			javaEqualityGuards(cond.ChildByFieldName("left"), src, out)
			javaEqualityGuards(cond.ChildByFieldName("right"), src, out)
		case op != nil && op.Type() == "==":
			add(cond.ChildByFieldName("left"), cond.ChildByFieldName("right"))
		}
	case "method_invocation":
		// equalsIgnoreCase does not fix the value: only equals.
		name := cond.ChildByFieldName("name")
		args := cond.ChildByFieldName("arguments")
		if name != nil && name.Content(src) == "equals" && args != nil && args.NamedChildCount() == 1 {
			add(cond.ChildByFieldName("object"), args.NamedChild(0))
		}
	}
}

// javaSingleCaseValue is the one value a case group or rule is entered with:
// it has one label, naming one value.
func javaSingleCaseValue(group *sitter.Node, src []byte) (string, bool) {
	var label *sitter.Node
	for i := 0; i < int(group.NamedChildCount()); i++ {
		if c := group.NamedChild(i); c.Type() == "switch_label" {
			if label != nil {
				return "", false
			}
			label = c
		}
	}
	if label == nil || label.NamedChildCount() != 1 {
		return "", false // default, or several values
	}
	return strings.TrimSpace(label.NamedChild(0).Content(src)), true
}

// javaFallsInto: the statement group before group (if any) can complete
// normally, so it falls through into group. Only a last statement that is
// a break, return, throw, continue or yield is known not to.
func javaFallsInto(group *sitter.Node) bool {
	prev := group.PrevNamedSibling()
	for prev != nil && (prev.Type() == javaNodeLineComment || prev.Type() == javaNodeBlockComment) {
		prev = prev.PrevNamedSibling()
	}
	if prev == nil {
		return false
	}
	if prev.Type() != javaNodeSwitchBlockStmtGroup {
		return true
	}
	var last *sitter.Node
	for i := 0; i < int(prev.NamedChildCount()); i++ {
		if c := prev.NamedChild(i); c.Type() != "switch_label" && c.Type() != javaNodeLineComment && c.Type() != javaNodeBlockComment {
			last = c
		}
	}
	if last == nil {
		return true // `case A: case B:` written as groups of their own
	}
	switch last.Type() {
	case "break_statement", "return_statement", "throw_statement", "continue_statement", "yield_statement":
		return false
	}
	return true
}

// javaFixedValue: a literal or a qualified constant, whose value does not
// depend on the program's state.
func javaFixedValue(text string) bool {
	if traceLiteralExpression(text) != nil {
		return text != "null"
	}
	dot := strings.LastIndexByte(text, '.')
	if dot <= 0 {
		return false
	}
	for _, segment := range strings.Split(text, ".") {
		if !javaIsName(segment) {
			return false
		}
	}
	return javaTypeLike(text[:dot])
}

// javaWrites: node assigns or increments name somewhere inside it.
func javaWrites(node *sitter.Node, src []byte, name string) bool {
	switch node.Type() {
	case javaNodeAssignmentExpression:
		if left := node.ChildByFieldName("left"); left != nil && strings.TrimSpace(left.Content(src)) == name {
			return true
		}
	case "update_expression":
		for i := 0; i < int(node.NamedChildCount()); i++ {
			if strings.TrimSpace(node.NamedChild(i).Content(src)) == name {
				return true
			}
		}
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if javaWrites(node.NamedChild(i), src, name) {
			return true
		}
	}
	return false
}
