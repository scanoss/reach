// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// VarDecl is a local variable or field declaration written in a function body
// (a field initializer belongs to the class's `<clinit>`), one per declared
// name. A detector reports a rule that names a declared type (`T $X = $E;`)
// at the declaration, as OpenGrep does, whatever the initializer is.
//
// Declarations of a primitive type, an array of one, `var`, String or Object
// are not recorded: no rule names them, and they are half of all
// declarations.
type VarDecl struct {
	// Type is the declared type as written, without whitespace; Name the
	// variable. `T a[] = ...` declares Type T[].
	Type, Name string
	// Line, StartCol and EndCol locate the whole declaration, modifiers to
	// semicolon (columns 1-based, end exclusive); EndLine is set only when it
	// spans lines.
	Line, StartCol, EndCol, EndLine int
	// Init is the kind of the initializer, one of the VarInit* kinds; ""
	// when the declaration has none.
	Init string
}

// Kinds of a declaration's initializer (VarDecl.Init), read through
// parentheses.
const (
	VarInitCall    = "call"    // a method call or `new T(...)`
	VarInitCast    = "cast"    // (T) expr
	VarInitNull    = "null"    // null
	VarInitLiteral = "literal" // a string, number, character or boolean literal
	VarInitOther   = "other"   // anything else (a variable, an array, a conditional)
)

// CastExpr is a cast expression `(T) $F.m(...)` or `(T) new C(...)` written in
// a function body. A detector reports a rule that names a cast of a call at
// the cast, as OpenGrep does, wherever the cast value goes. A cast of anything
// else is not recorded: a rule names a cast only around a call.
type CastExpr struct {
	// Type is the target type as written, without whitespace.
	Type string
	// Line, StartCol and EndCol locate the cast expression (columns 1-based,
	// end exclusive); EndLine is set only when it spans lines.
	Line, StartCol, EndCol, EndLine int
	// InnerLine and InnerCol are where the cast operand, a call read through
	// parentheses, starts: the position of that call's site.
	InnerLine, InnerCol int
}

// collectJavaDeclarations records every local variable and field declaration
// and every cast expression of the file in the function whose span contains
// it most tightly. One in no function (a field with no initializer in a class
// with no `<clinit>`) is dropped.
func collectJavaDeclarations(root *sitter.Node, src []byte, analysis *FileAnalysis) {
	if len(analysis.Functions) == 0 {
		return
	}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "import_declaration", "package_declaration", javaNodeLineComment, javaNodeBlockComment:
			return
		case javaNodeLocalVarDeclaration, javaNodeFieldDeclaration:
			addJavaVarDecls(analysis, n, src)
		case javaNodeCastExpression:
			addJavaCast(analysis, n, src)
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
}

func addJavaVarDecls(analysis *FileAnalysis, n *sitter.Node, src []byte) {
	typeNode := n.ChildByFieldName(javaFieldType)
	if typeNode == nil {
		return
	}
	declType := javaCompactText(typeNode, src)
	if !javaDeclaredTypeRecorded(declType) {
		return
	}
	start, end := n.StartPoint(), n.EndPoint()
	fn := tightestJavaFunction(analysis, int(start.Row)+1, int(start.Column)+1)
	if fn == nil {
		return
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		declarator := n.NamedChild(i)
		if declarator.Type() != javaNodeVariableDeclarator {
			continue
		}
		name := declarator.ChildByFieldName(javaFieldName)
		if name == nil {
			continue
		}
		decl := VarDecl{
			Type:     declType,
			Name:     name.Content(src),
			Line:     int(start.Row) + 1,
			StartCol: int(start.Column) + 1,
			EndCol:   int(end.Column) + 1,
			Init:     javaVarInitKind(declarator.ChildByFieldName(javaFieldValue)),
		}
		if dims := declarator.ChildByFieldName("dimensions"); dims != nil {
			decl.Type += javaCompactText(dims, src)
		}
		if end.Row != start.Row {
			decl.EndLine = int(end.Row) + 1
		}
		fn.Declarations = append(fn.Declarations, decl)
	}
}

func addJavaCast(analysis *FileAnalysis, n *sitter.Node, src []byte) {
	typeNode := n.ChildByFieldName(javaFieldType)
	if typeNode == nil {
		return
	}
	inner := javaUnparenthesized(n.ChildByFieldName(javaFieldValue))
	if inner == nil || (inner.Type() != javaNodeMethodInvocation && inner.Type() != javaNodeObjectCreation) {
		return
	}
	start, end := n.StartPoint(), n.EndPoint()
	cast := CastExpr{
		Type:      javaCompactText(typeNode, src),
		Line:      int(start.Row) + 1,
		StartCol:  int(start.Column) + 1,
		EndCol:    int(end.Column) + 1,
		InnerLine: int(inner.StartPoint().Row) + 1,
		InnerCol:  int(inner.StartPoint().Column) + 1,
	}
	if end.Row != start.Row {
		cast.EndLine = int(end.Row) + 1
	}
	if fn := tightestJavaFunction(analysis, cast.Line, cast.StartCol); fn != nil {
		fn.Casts = append(fn.Casts, cast)
	}
}

func javaUnparenthesized(n *sitter.Node) *sitter.Node {
	for n != nil && n.Type() == javaNodeParenthesizedExpr && n.NamedChildCount() == 1 {
		n = n.NamedChild(0)
	}
	return n
}

func javaVarInitKind(value *sitter.Node) string {
	value = javaUnparenthesized(value)
	if value == nil {
		return ""
	}
	switch value.Type() {
	case javaNodeMethodInvocation, javaNodeObjectCreation:
		return VarInitCall
	case javaNodeCastExpression:
		return VarInitCast
	case "null_literal":
		return VarInitNull
	case "string_literal", "character_literal", "true", "false", "decimal_integer_literal", "hex_integer_literal",
		"octal_integer_literal", "binary_integer_literal", "decimal_floating_point_literal",
		"hex_floating_point_literal", "text_block":
		return VarInitLiteral
	}
	return VarInitOther
}

// javaDeclaredTypeRecorded: a declaration of this type is recorded (VarDecl).
func javaDeclaredTypeRecorded(declType string) bool {
	switch strings.TrimRight(declType, "[]") {
	case "", "var", "boolean", "byte", "char", "short", "int", "long", "float", "double",
		"String", "java.lang.String", "Object", "java.lang.Object":
		return false
	}
	return true
}

// javaCompactText is the node's text without whitespace or comments.
func javaCompactText(n *sitter.Node, src []byte) string {
	return strings.Join(strings.Fields(n.Content(src)), "")
}
