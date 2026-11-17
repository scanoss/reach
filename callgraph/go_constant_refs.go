// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// collectGoConstantRefs records every value read through an import
// (`tls.VersionTLS13`, `crypto.SHA256`) that is not called or written, in the
// function whose span holds it most tightly; a package-level one goes to the
// file's <varinit>. Its text is the import path and the name
// (`crypto/tls.VersionTLS13`), as a Python reference names its module.
func collectGoConstantRefs(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	locals := map[uint32]map[string]bool{}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "import_declaration", "package_clause", "comment":
			return
		case goNodeSelectorExpression:
			if text, ok := goConstantRefText(n, src, analysis, locals); ok {
				addGoConstantRef(analysis, n, src, text, filePath, packagePath, int(root.EndPoint().Row)+1)
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
}

// goConstantRefText is the text of a selector `alias.Name` whose alias is an
// import the enclosing functions do not shadow, read as a value: not the
// callee of a call and not the left side of an assignment.
func goConstantRefText(n *sitter.Node, src []byte, analysis *FileAnalysis, locals map[uint32]map[string]bool) (string, bool) {
	operand := n.ChildByFieldName(goFieldOperand)
	field := n.ChildByFieldName(goFieldField)
	if operand == nil || field == nil || operand.Type() != goNodeIdentifier {
		return "", false
	}
	alias := operand.Content(src)
	path, ok := analysis.Imports[alias]
	if !ok || alias == "_" || alias == "." {
		return "", false
	}
	parent := n.Parent()
	if parent != nil {
		switch parent.Type() {
		case goNodeCallExpression:
			if goSameNode(parent.ChildByFieldName("function"), n) {
				return "", false
			}
		case "assignment_statement", "inc_statement", "dec_statement":
			if parent.Type() != "assignment_statement" || goWithin(n, parent.ChildByFieldName("left")) {
				return "", false
			}
		case "expression_list":
			if gp := parent.Parent(); gp != nil && gp.Type() == "assignment_statement" && goSameNode(gp.ChildByFieldName("left"), parent) {
				return "", false
			}
		}
	}
	if goShadowedName(n, alias, src, locals) {
		return "", false
	}
	return path + "." + field.Content(src), true
}

func addGoConstantRef(analysis *FileAnalysis, n *sitter.Node, src []byte, text, filePath, packagePath string, endLine int) {
	start, end := n.StartPoint(), n.EndPoint()
	ref := ConstantRef{
		Text:     text,
		Line:     int(start.Row) + 1,
		StartCol: int(start.Column) + 1,
		EndCol:   int(end.Column) + 1,
	}
	if end.Row != start.Row {
		ref.EndLine = int(end.Row) + 1
	}
	var operand *sitter.Node
	ref.Context, operand = goConstantRefContext(n)
	if operand != nil {
		ref.Operand = &ComparedOperand{Text: strings.TrimSpace(operand.Content(src))}
	}
	fn := tightestGoFunction(analysis, ref.Line, ref.StartCol)
	if fn == nil {
		fn = goVarinitDecl(analysis, filePath, packagePath, endLine)
	}
	fn.ConstantRefs = append(fn.ConstantRefs, ref)
}

// goConstantRefContext classifies where the reference stands, looking through
// parentheses and expression lists, and returns what a comparison or a case
// compares it with.
func goConstantRefContext(n *sitter.Node) (string, *sitter.Node) {
	for {
		parent := n.Parent()
		if parent == nil {
			return ConstantRefOther, nil
		}
		switch parent.Type() {
		case goNodeParenExpr, goNodeExpressionList, "literal_element":
			n = parent
			continue
		case "binary_expression":
			op := parent.ChildByFieldName("operator")
			if op == nil || (op.Type() != "==" && op.Type() != "!=") {
				return ConstantRefOther, nil
			}
			other := parent.ChildByFieldName("right")
			if goSameNode(other, n) {
				other = parent.ChildByFieldName("left")
			}
			return ConstantRefCompare, other
		case "expression_case":
			if sw := parent.Parent(); sw != nil && sw.Type() == "expression_switch_statement" {
				return ConstantRefCase, sw.ChildByFieldName("value")
			}
			return ConstantRefCase, nil
		case goNodeReturnStatement:
			return ConstantRefReturn, nil
		case "assignment_statement":
			return ConstantRefAssign, nil
		case "short_var_declaration", "var_spec", "const_spec":
			return ConstantRefInit, nil
		case "keyed_element", "literal_value":
			return goLiteralElementContext(parent), nil
		case goNodeArgumentList:
			return ConstantRefArg, nil
		}
		return ConstantRefOther, nil
	}
}

// goLiteralElementContext is the kind of an element of a composite literal:
// a map entry (dict), a slice or array element (array), else a struct field
// value (init).
func goLiteralElementContext(n *sitter.Node) string {
	for n != nil && n.Type() != goNodeCompositeLiteral {
		n = n.Parent()
	}
	if n == nil {
		return ConstantRefOther
	}
	typ := n.ChildByFieldName(goFieldType)
	if typ == nil {
		return ConstantRefOther
	}
	switch typ.Type() {
	case "map_type":
		return ConstantRefDict
	case "slice_type", "array_type", "implicit_length_array_type":
		return ConstantRefArray
	}
	return ConstantRefInit
}

// tightestGoFunction is the function of analysis, other than an interface
// method or the file's <varinit>, whose span holds the position most tightly.
func tightestGoFunction(analysis *FileAnalysis, line, col int) *FunctionDecl {
	var best *FunctionDecl
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		if fn.OwnerType == goOwnerInterface || strings.HasPrefix(fn.ID.Name, goVarinitPrefix) {
			continue
		}
		if !spanContains(fn.StartLine, fn.StartCol, fn.EndLine, fn.EndCol, line, col) {
			continue
		}
		if best == nil || spanContains(best.StartLine, best.StartCol, best.EndLine, best.EndCol, fn.StartLine, max(fn.StartCol, 1)) {
			best = fn
		}
	}
	return best
}

// goShadowedName reports whether a function enclosing n binds name (a
// parameter, a receiver, a result or a local), so the selector reads that
// binding, not the import.
func goShadowedName(n *sitter.Node, name string, src []byte, cache map[uint32]map[string]bool) bool {
	for p := n.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case goNodeFunctionDecl, goNodeMethodDecl, goNodeFuncLiteral:
			names, ok := cache[p.StartByte()]
			if !ok {
				names = map[string]bool{}
				goCollectShadowingNames(p, src, names)
				cache[p.StartByte()] = names
			}
			if names[name] {
				return true
			}
		}
	}
	return false
}

// goCollectShadowingNames adds every name the function node binds in its
// signature or body, nested function literals included (a coarse scope: a
// binding anywhere in the function shadows the import throughout it).
func goCollectShadowingNames(n *sitter.Node, src []byte, names map[string]bool) {
	switch n.Type() {
	case goNodeParameterDecl, "variadic_parameter_declaration", "var_spec", "const_spec":
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if c := n.NamedChild(i); c.Type() == goNodeIdentifier {
				names[c.Content(src)] = true
			}
		}
	case "short_var_declaration", "range_clause":
		if left := n.ChildByFieldName("left"); left != nil {
			for i := 0; i < int(left.NamedChildCount()); i++ {
				if c := left.NamedChild(i); c.Type() == goNodeIdentifier {
					names[c.Content(src)] = true
				}
			}
		}
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		goCollectShadowingNames(n.NamedChild(i), src, names)
	}
}

func goSameNode(a, b *sitter.Node) bool {
	return a != nil && b != nil && a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte() && a.Type() == b.Type()
}

func goWithin(n, outer *sitter.Node) bool {
	return n != nil && outer != nil && n.StartByte() >= outer.StartByte() && n.EndByte() <= outer.EndByte()
}
