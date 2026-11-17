// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"cmp"
	"slices"

	sitter "github.com/smacker/go-tree-sitter"
)

// RustBinaryExpr is one binary expression of a Rust function body, as
// written: `s * base`, `&s * &p`, `a == b`, `x && y`. Every one is listed, an
// operand of another included, so `a * b + c` gives `a * b + c` and `a * b`.
// An expression in the arguments of an expression macro (`assert_eq!(a * b,
// c)`) is one too; one in a parameter's type, outside the body, is none.
//
// The left operand starts where the expression starts and the right one ends
// where it ends, so their spans need only the two inner ends.
type RustBinaryExpr struct {
	// Op is the operator as written: `*`, `+`, `==`, `&&`, `<<`, ...
	Op string
	// Left and Right are the operands' source text as written, whitespace
	// and parentheses kept.
	Left, Right string
	// Line, StartCol and EndCol locate the expression (columns 1-based, end
	// exclusive); EndLine is set only when it spans lines.
	Line, StartCol, EndCol, EndLine int
	// LeftEndCol is the column the left operand ends at (exclusive), on
	// LeftEndLine, or on Line when LeftEndLine is 0.
	LeftEndCol, LeftEndLine int
	// RightStartCol is the column the right operand starts at, on RightLine,
	// or on Line when RightLine is 0.
	RightStartCol, RightLine int
	// Function is the key of the innermost function whose span holds the
	// expression, the key its call sites carry: a fn nested in a body or a
	// closure has none of its own, so it is the enclosing function's ("" when
	// no function the graph lists holds it).
	Function string
}

const rustNodeBinaryExpression = "binary_expression"

// collectRustBinaryExprs records the binary expressions of every function
// body of the file, into analysis.RustBinaryExprs in source order. It skips
// what the declaration walk skips: a test-only inline module in a scan
// without tests. It runs after the declarations are extracted, for the keys.
func (p *RustParser) collectRustBinaryExprs(root *sitter.Node, src []byte, analysis *FileAnalysis) {
	var out []RustBinaryExpr
	var walk func(node *sitter.Node, body bool)
	walk = func(node *sitter.Node, body bool) {
		switch node.Type() {
		case rustNodeModItem:
			if !p.includeTests && rustModuleIsTestOnly(node, src) {
				return
			}
		case rustNodeFunctionItem:
			if b := node.ChildByFieldName("body"); b != nil {
				walk(b, true)
			}
			return
		case rustNodeBinaryExpression:
			if body {
				if expr, ok := rustBinaryExpr(node, src); ok {
					expr.Function = rustEnclosingFunctionKey(analysis.Functions, expr)
					out = append(out, expr)
				}
			}
		case "macro_invocation":
			if body {
				// The arguments are a token tree; parsed again in place,
				// their nodes keep the file's offsets and positions.
				if tree := p.parseRustMacroArguments(node, src); tree != nil {
					walk(tree.RootNode(), true)
					tree.Close()
				}
			}
			return
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i), body)
		}
	}
	walk(root, false)
	slices.SortStableFunc(out, func(a, b RustBinaryExpr) int {
		return cmp.Or(cmp.Compare(a.Line, b.Line), cmp.Compare(a.StartCol, b.StartCol))
	})
	analysis.RustBinaryExprs = out
}

// rustBinaryExpr reads one binary expression node.
func rustBinaryExpr(node *sitter.Node, src []byte) (RustBinaryExpr, bool) {
	left, op, right := node.ChildByFieldName("left"), node.ChildByFieldName("operator"), node.ChildByFieldName("right")
	if left == nil || op == nil || right == nil {
		return RustBinaryExpr{}, false
	}
	expr := RustBinaryExpr{Op: op.Content(src), Left: left.Content(src), Right: right.Content(src)}
	expr.Line, expr.StartCol, expr.EndCol, expr.EndLine = rustSpan(node)
	expr.LeftEndCol = int(left.EndPoint().Column) + 1
	if line := int(left.EndPoint().Row) + 1; line != expr.Line {
		expr.LeftEndLine = line
	}
	expr.RightStartCol = int(right.StartPoint().Column) + 1
	if line := int(right.StartPoint().Row) + 1; line != expr.Line {
		expr.RightLine = line
	}
	return expr, true
}

// rustEnclosingFunctionKey is the key of the innermost function whose span
// holds the expression, "" when none does.
func rustEnclosingFunctionKey(functions []FunctionDecl, expr RustBinaryExpr) string {
	endLine := expr.EndLine
	if endLine == 0 {
		endLine = expr.Line
	}
	key, bestLine, bestCol := "", 0, 0
	for i := range functions {
		fn := &functions[i]
		startsBefore := fn.StartLine < expr.Line || (fn.StartLine == expr.Line && fn.StartCol <= expr.StartCol)
		endsAfter := fn.EndLine > endLine || (fn.EndLine == endLine && fn.EndCol >= expr.EndCol)
		if !startsBefore || !endsAfter {
			continue
		}
		if fn.StartLine > bestLine || (fn.StartLine == bestLine && fn.StartCol > bestCol) {
			key, bestLine, bestCol = fn.ID.String(), fn.StartLine, fn.StartCol
		}
	}
	return key
}
