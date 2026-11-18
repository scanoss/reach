// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"
	"unicode"

	sitter "github.com/smacker/go-tree-sitter"
)

// ConstantRef is a reference to a qualified constant (`Owner.NAME`,
// `a.b.Owner.NAME`, or a name imported with `import static`) written in a
// function body, wherever it stands: a call argument, a comparison, a `case`
// label, a return, an assignment, an initializer or an array element. A
// detector reports a rule that names a constant at the reference, as OpenGrep
// does, without the source.
type ConstantRef struct {
	// Text is the reference as written, without whitespace; for a name
	// imported with `import static a.b.Owner.NAME` it is a.b.Owner.NAME.
	Text string
	// Line, StartCol and EndCol locate the reference (columns 1-based, end
	// exclusive); EndLine is set only when it spans lines.
	Line, StartCol, EndCol, EndLine int
	// Context is where the reference stands, one of the ConstantRef* kinds.
	Context string
	// Operand is what the constant is compared with, for a reference in a
	// comparison (compare, equals or case); nil when it was not traced.
	Operand *ComparedOperand
}

// Positions of a constant reference (ConstantRef.Context). The first three are
// comparisons: the constant is read there, not passed on.
const (
	ConstantRefCompare = "compare" // operand of == or !=
	ConstantRefEquals  = "equals"  // receiver or argument of equals / equalsIgnoreCase
	ConstantRefCase    = "case"    // switch case label
	ConstantRefReturn  = "return"  // returned value
	ConstantRefAssign  = "assign"  // right side of an assignment
	ConstantRefInit    = "init"    // initializer of a local or a field
	ConstantRefArray   = "array"   // element of an array initializer
	ConstantRefArg     = "arg"     // argument of a call, a constructor or an enum constant
	ConstantRefOther   = "other"   // anything else (a receiver, an operand, an annotation value)
	ConstantRefStruct  = "struct"  // path of a Rust struct literal (`acme::Key { .. }`)
	ConstantRefType    = "type"    // path written as a Rust type (`rng: SysRng`, `-> acme::Key`)
)

// collectJavaConstantRefs records every qualified constant reference of the
// file in the function whose span contains it most tightly. A reference in no
// function (an annotation of a class with no initializer) is dropped.
//
// A reference in a comparison gets the operand it is compared with from
// sides, the comparison sides the function walk recorded.
func collectJavaConstantRefs(root *sitter.Node, src []byte, analysis *FileAnalysis, sides []comparedSide) {
	if len(analysis.Functions) == 0 {
		return
	}
	staticImports := javaStaticImports(root, src)
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "import_declaration", "package_declaration", javaNodeLineComment, javaNodeBlockComment:
			return
		case javaNodeFieldAccess:
			if text, ok := javaConstantText(n, src); ok { // the outer access: the walk stops here
				addJavaConstantRef(analysis, n, src, text, sides)
				return
			}
		case javaNodeIdentifier:
			if owner, ok := staticImports[n.Content(src)]; ok && javaIdentifierIsValue(n) {
				addJavaConstantRef(analysis, n, src, owner+"."+n.Content(src), sides)
			}
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
}

// javaStaticImports maps each name an explicit `import static a.b.Owner.NAME;`
// brings in to a.b.Owner.
func javaStaticImports(root *sitter.Node, src []byte) map[string]string {
	out := map[string]string{}
	for i := 0; i < int(root.ChildCount()); i++ {
		child := root.Child(i)
		if child.Type() != "import_declaration" {
			continue
		}
		text := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(child.Content(src), "import"), ";"))
		rest, ok := strings.CutPrefix(text, "static")
		if !ok || strings.HasSuffix(rest, "*") {
			continue
		}
		rest = strings.Join(strings.Fields(rest), "")
		if dot := strings.LastIndexByte(rest, '.'); dot > 0 && javaTypeLike(rest[:dot]) {
			out[rest[dot+1:]] = rest[:dot]
		}
	}
	return out
}

// javaConstantText is the text of a field access whose owner names a type
// (its last segment starts with an upper-case letter) and whose every segment
// is a name: `Owner.NAME`, `a.b.Owner.NAME`, `Owner.Inner.NAME`.
func javaConstantText(n *sitter.Node, src []byte) (string, bool) {
	text := strings.Join(strings.Fields(n.Content(src)), "")
	dot := strings.LastIndexByte(text, '.')
	if dot <= 0 || dot == len(text)-1 {
		return "", false
	}
	for _, segment := range strings.Split(text, ".") {
		if !javaIsName(segment) {
			return "", false
		}
	}
	return text, javaTypeLike(text[:dot])
}

func javaTypeLike(owner string) bool {
	last := owner[strings.LastIndexByte(owner, '.')+1:]
	for _, r := range last {
		return unicode.IsUpper(r)
	}
	return false
}

func javaIsName(s string) bool {
	if s == "" || s == "this" || s == "super" || s == "class" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || r == '$' || unicode.IsLetter(r) || (i > 0 && unicode.IsDigit(r))) {
			return false
		}
	}
	return true
}

// javaIdentifierIsValue: a bare identifier stands as a value (not a declared
// name, a method name, a field of an access, a type or a label).
func javaIdentifierIsValue(n *sitter.Node) bool {
	parent := n.Parent()
	if parent == nil {
		return false
	}
	switch parent.Type() {
	case javaNodeArgumentList, "return_statement", "binary_expression", "array_initializer", "switch_label",
		"ternary_expression", javaNodeParenthesizedExpr, "element_value_array_initializer":
		return true
	case javaNodeVariableDeclarator:
		return javaSameNode(parent.ChildByFieldName("value"), n)
	case javaNodeAssignmentExpression:
		return javaSameNode(parent.ChildByFieldName("right"), n)
	case javaNodeCastExpression:
		return javaSameNode(parent.ChildByFieldName("value"), n)
	case javaNodeMethodInvocation:
		return javaSameNode(parent.ChildByFieldName("object"), n)
	}
	return false
}

func javaSameNode(a, b *sitter.Node) bool {
	return a != nil && b != nil && a.StartByte() == b.StartByte() && a.EndByte() == b.EndByte() && a.Type() == b.Type()
}

func addJavaConstantRef(analysis *FileAnalysis, n *sitter.Node, src []byte, text string, sides []comparedSide) {
	start, end := n.StartPoint(), n.EndPoint()
	ref := ConstantRef{
		Text:     text,
		Line:     int(start.Row) + 1,
		StartCol: int(start.Column) + 1,
		EndCol:   int(end.Column) + 1,
		Context:  javaConstantRefContext(n, src),
	}
	if end.Row != start.Row {
		ref.EndLine = int(end.Row) + 1
	}
	switch ref.Context {
	case ConstantRefCompare, ConstantRefEquals, ConstantRefCase:
		ref.Operand = comparedOperandAt(sides, n.StartByte(), n.EndByte())
	}
	if fn := tightestJavaFunction(analysis, ref.Line, ref.StartCol); fn != nil {
		fn.ConstantRefs = append(fn.ConstantRefs, ref)
	}
}

// javaConstantRefContext classifies where the reference stands, looking
// through parentheses, casts and the branches of a conditional.
func javaConstantRefContext(n *sitter.Node, src []byte) string {
	for {
		parent := n.Parent()
		if parent == nil {
			return ConstantRefOther
		}
		switch parent.Type() {
		case javaNodeParenthesizedExpr, javaNodeCastExpression:
			n = parent
			continue
		case "ternary_expression":
			if javaSameNode(parent.ChildByFieldName("condition"), n) {
				return ConstantRefOther
			}
			n = parent
			continue
		case "binary_expression":
			if op := parent.ChildByFieldName("operator"); op != nil && (op.Type() == "==" || op.Type() == "!=") {
				return ConstantRefCompare
			}
			return ConstantRefOther
		case "switch_label":
			return ConstantRefCase
		case "return_statement", "yield_statement":
			return ConstantRefReturn
		case javaNodeAssignmentExpression:
			if javaSameNode(parent.ChildByFieldName("right"), n) {
				return ConstantRefAssign
			}
			return ConstantRefOther
		case javaNodeVariableDeclarator:
			return ConstantRefInit
		case "array_initializer", "element_value_array_initializer":
			return ConstantRefArray
		case javaNodeArgumentList:
			if call := parent.Parent(); call != nil && call.Type() == javaNodeMethodInvocation && javaEqualsCall(call, src) {
				return ConstantRefEquals
			}
			return ConstantRefArg
		case javaNodeMethodInvocation:
			if javaSameNode(parent.ChildByFieldName("object"), n) && javaEqualsCall(parent, src) {
				return ConstantRefEquals
			}
			return ConstantRefOther
		}
		return ConstantRefOther
	}
}

func javaEqualsCall(call *sitter.Node, src []byte) bool {
	name := call.ChildByFieldName("name")
	if name == nil {
		return false
	}
	text := name.Content(src)
	return text == "equals" || text == "equalsIgnoreCase"
}

// tightestJavaFunction is the function of analysis whose span contains the
// position most tightly.
func tightestJavaFunction(analysis *FileAnalysis, line, col int) *FunctionDecl {
	var best *FunctionDecl
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		if !spanContains(fn.StartLine, fn.StartCol, fn.EndLine, fn.EndCol, line, col) {
			continue
		}
		if best == nil || spanContains(best.StartLine, best.StartCol, best.EndLine, best.EndCol, fn.StartLine, max(fn.StartCol, 1)) {
			best = fn
		}
	}
	return best
}

func spanContains(startLine, startCol, endLine, endCol, line, col int) bool {
	if line < startLine || line > endLine {
		return false
	}
	if line == startLine && startCol > 0 && col < startCol {
		return false
	}
	if line == endLine && endCol > 0 && col >= endCol {
		return false
	}
	return true
}
