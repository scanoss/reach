// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// Kinds of a GoValue.
const (
	GoValueComposite = "composite" // T{...}, &T{...}
	GoValueNew       = "new"       // new(T)
	GoValueStore     = "store"     // x.f = v
	GoValueAssign    = "assign"    // x := e, x, err = f(), var x T = e
)

// goAssignOpVar is the Op of an assignment a `var` spec makes.
const goAssignOpVar = "var"

// GoValue is a Go expression that builds or configures a value without a
// call the graph records: a composite literal (`tls.Config{MinVersion: v}`,
// `&rsa.PSSOptions{...}`), a `new(T)`, a store to a field
// (`cfg.CipherSuites = v`), or an assignment to plain names in a function
// body (`c := acme.New()`, `x, err = f()`, `var k T = e`). A detector matches
// a rule written as such an expression against these facts, without the
// source.
type GoValue struct {
	// Kind is one of the GoValue* kinds.
	Kind string
	// Function is the key of the function that holds the expression; for a
	// package-level var initializer, the file's <varinit> declaration.
	Function string
	// Line, StartCol and EndCol locate the expression (columns 1-based, end
	// exclusive); EndLine is set only when it spans lines. A composite
	// literal's span leaves out a leading `&`, which AddrCol locates (0 when
	// there is none); a store's or an assignment's span is the whole
	// statement (for an ungrouped `var`, the declaration from `var`).
	Line, StartCol, EndCol, EndLine int
	AddrCol                         int
	// TypeText is the type as written (`tls.Config`, `*tls.Config` for a
	// store's receiver, `T` for `var x T = e`); Package and Type qualify it as method keys do
	// (crypto/tls, Config or *Config), empty when it cannot be named.
	TypeText, Package, Type string
	// Receiver is a store's receiver as written (`cfg`, `s.cfg`).
	Receiver string
	// Fields are a composite literal's elements in order, or a store's one
	// field and value.
	Fields []GoValueField
	// Names are an assignment's left-hand names in order, `_` as written.
	Names []string
	// Op is an assignment's operator: ":=", "=" or "var".
	Op string
	// Value is an assignment's right-hand expression as written when there
	// is exactly one, "" otherwise.
	Value string
}

// GoValueField is one element of a composite literal (`Name: value`, or a
// bare value with no Name) or the field and value of a store.
type GoValueField struct {
	Name, Value string
	// Line, StartCol and EndCol locate the value; EndLine only when it spans
	// lines.
	Line, StartCol, EndCol, EndLine int
}

// goValueAt reads node as a GoValue, nil when it is none.
func goValueAt(node *sitter.Node, src []byte, analysis *FileAnalysis, varTypes map[string]string) *GoValue {
	switch node.Type() {
	case goNodeCompositeLiteral:
		return goCompositeValue(node, src, analysis)
	case goNodeCallExpression:
		fn := node.ChildByFieldName("function")
		args := node.ChildByFieldName("arguments")
		if fn == nil || args == nil || fn.Type() != goNodeIdentifier || fn.Content(src) != goBuiltinNew || args.NamedChildCount() != 1 {
			return nil
		}
		v := &GoValue{Kind: GoValueNew, TypeText: strings.TrimSpace(args.NamedChild(0).Content(src))}
		goSpan(node, &v.Line, &v.StartCol, &v.EndCol, &v.EndLine)
		v.Package, v.Type, _ = goQualifyTypeText(v.TypeText, analysis)
		return v
	case goNodeAssignmentStmt:
		if v := goStoreValue(node, src, analysis, varTypes); v != nil {
			return v
		}
		return goAssignValue(node, node.ChildByFieldName(goFieldLeft), node.ChildByFieldName(goFieldRight), "=", src)
	case goNodeShortVarDeclaration:
		return goAssignValue(node, node.ChildByFieldName(goFieldLeft), node.ChildByFieldName(goFieldRight), ":=", src)
	case goNodeVarSpec:
		return goVarAssignValue(node, src, analysis)
	}
	return nil
}

// goAssignValue reads `left op right` as an assign GoValue when every name
// on the left is a plain identifier and the operator is a bare `=` or `:=`
// (a compound `+=` is no assignment of a value, a field or index target is
// a store or nothing).
func goAssignValue(stmt, left, right *sitter.Node, op string, src []byte) *GoValue {
	if left == nil || right == nil || !goHasToken(stmt, op) {
		return nil
	}
	names := goPlainNames(goListItems(left), src)
	if names == nil {
		return nil
	}
	v := &GoValue{Kind: GoValueAssign, Names: names, Op: op, Value: goSoleExpression(right, src)}
	goSpan(stmt, &v.Line, &v.StartCol, &v.EndCol, &v.EndLine)
	return v
}

// goVarAssignValue reads a `var` spec of a function body that gives its
// names a value as an assign GoValue; a package-level var is no assignment
// of a function, and `var x T` assigns nothing.
func goVarAssignValue(spec *sitter.Node, src []byte, analysis *FileAnalysis) *GoValue {
	value := spec.ChildByFieldName("value")
	decl := spec.Parent()
	if value == nil || decl == nil {
		return nil
	}
	stmt := spec
	if decl.Type() == goNodeVarDeclaration {
		stmt = decl
	} else if decl = decl.Parent(); decl == nil {
		return nil
	}
	if parent := decl.Parent(); parent == nil || parent.Type() == goNodeSourceFile {
		return nil
	}
	var nameNodes []*sitter.Node
	for i := 0; i < int(spec.ChildCount()); i++ {
		if spec.FieldNameForChild(i) == goFieldName {
			nameNodes = append(nameNodes, spec.Child(i))
		}
	}
	names := goPlainNames(nameNodes, src)
	if names == nil {
		return nil
	}
	v := &GoValue{Kind: GoValueAssign, Names: names, Op: goAssignOpVar, Value: goSoleExpression(value, src)}
	goSpan(stmt, &v.Line, &v.StartCol, &v.EndCol, &v.EndLine)
	if t := spec.ChildByFieldName(goFieldType); t != nil {
		v.TypeText = strings.TrimSpace(t.Content(src))
		v.Package, v.Type, _ = goQualifyTypeText(v.TypeText, analysis)
	}
	return v
}

// goPlainNames is the text of nodes when every one is an identifier, nil
// otherwise.
func goPlainNames(nodes []*sitter.Node, src []byte) []string {
	if len(nodes) == 0 {
		return nil
	}
	names := make([]string, len(nodes))
	for i, n := range nodes {
		if n.Type() != goNodeIdentifier {
			return nil
		}
		names[i] = n.Content(src)
	}
	return names
}

// goSoleExpression is the text of a list holding one expression, "" for
// several.
func goSoleExpression(list *sitter.Node, src []byte) string {
	if items := goListItems(list); len(items) == 1 {
		return items[0].Content(src)
	}
	return ""
}

func goCompositeValue(node *sitter.Node, src []byte, analysis *FileAnalysis) *GoValue {
	typeNode := node.ChildByFieldName(goFieldType)
	body := node.ChildByFieldName("body")
	if typeNode == nil || body == nil {
		return nil
	}
	v := &GoValue{Kind: GoValueComposite, TypeText: strings.TrimSpace(typeNode.Content(src))}
	goSpan(node, &v.Line, &v.StartCol, &v.EndCol, &v.EndLine)
	if parent := node.Parent(); parent != nil && parent.Type() == goNodeUnaryExpression {
		if op := parent.ChildByFieldName("operator"); op != nil && strings.TrimSpace(op.Content(src)) == "&" {
			v.AddrCol = int(parent.StartPoint().Column) + 1
		}
	}
	v.Package, v.Type, _ = goQualifyTypeText(v.TypeText, analysis)
	for i := 0; i < int(body.NamedChildCount()); i++ {
		el := body.NamedChild(i)
		var f GoValueField
		value := el
		if el.Type() == "keyed_element" && el.NamedChildCount() == 2 {
			f.Name = strings.TrimSpace(el.NamedChild(0).Content(src))
			value = el.NamedChild(1)
		}
		if value.Type() == "literal_element" && value.NamedChildCount() == 1 {
			value = value.NamedChild(0)
		}
		f.Value = value.Content(src)
		goSpan(value, &f.Line, &f.StartCol, &f.EndCol, &f.EndLine)
		v.Fields = append(v.Fields, f)
	}
	return v
}

func goStoreValue(node *sitter.Node, src []byte, analysis *FileAnalysis, varTypes map[string]string) *GoValue {
	left, right := node.ChildByFieldName("left"), node.ChildByFieldName("right")
	op := node.ChildByFieldName("operator")
	if left == nil || right == nil || left.NamedChildCount() != 1 || right.NamedChildCount() != 1 ||
		(op != nil && strings.TrimSpace(op.Content(src)) != "=") {
		return nil
	}
	sel := left.NamedChild(0)
	if sel.Type() != goNodeSelectorExpression {
		return nil
	}
	operand, field := sel.ChildByFieldName("operand"), sel.ChildByFieldName("field")
	if operand == nil || field == nil {
		return nil
	}
	v := &GoValue{Kind: GoValueStore, Receiver: operand.Content(src)}
	goSpan(node, &v.Line, &v.StartCol, &v.EndCol, &v.EndLine)
	if operand.Type() == goNodeIdentifier {
		v.TypeText = varTypes[v.Receiver]
		if v.TypeText != "" && v.TypeText != "func" {
			v.Package, v.Type, _ = goQualifyTypeText(v.TypeText, analysis)
		}
	}
	value := right.NamedChild(0)
	f := GoValueField{Name: field.Content(src), Value: value.Content(src)}
	goSpan(value, &f.Line, &f.StartCol, &f.EndCol, &f.EndLine)
	v.Fields = []GoValueField{f}
	return v
}

// goSpan writes a node's span: columns 1-based, end exclusive, endLine only
// when the node spans lines.
func goSpan(node *sitter.Node, line, startCol, endCol, endLine *int) {
	start, end := node.StartPoint(), node.EndPoint()
	*line, *startCol, *endCol = int(start.Row)+1, int(start.Column)+1, int(end.Column)+1
	if end.Row != start.Row {
		*endLine = int(end.Row) + 1
	}
}
