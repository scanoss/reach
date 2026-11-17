// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// collectGoDeclarations records every `var` declaration whose stated type is
// an imported one (`var p dsa.Parameters`, `var k *rsa.PrivateKey`), one per
// name, in the function whose span holds it most tightly; a package-level one
// goes to the file's <varinit>. The type is written with its import path
// (`crypto/dsa.Parameters`). Declarations of builtin or file-local types are
// not recorded: no rule names them.
func collectGoDeclarations(root *sitter.Node, src []byte, filePath, packagePath string, analysis *FileAnalysis) {
	endLine := int(root.EndPoint().Row) + 1
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		switch n.Type() {
		case "import_declaration", "package_clause", "comment":
			return
		case "var_declaration":
			specs := goVarSpecs(n)
			for _, spec := range specs {
				span := spec
				if len(specs) == 1 {
					span = n
				}
				addGoVarDecls(analysis, spec, span, src, filePath, packagePath, endLine)
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
}

// goVarSpecs are the specs of a var declaration, grouped or not.
func goVarSpecs(n *sitter.Node) []*sitter.Node {
	var out []*sitter.Node
	for i := 0; i < int(n.NamedChildCount()); i++ {
		switch c := n.NamedChild(i); c.Type() {
		case goNodeVarSpec:
			out = append(out, c)
		case "var_spec_list":
			out = append(out, goVarSpecs(c)...)
		}
	}
	return out
}

func addGoVarDecls(analysis *FileAnalysis, spec, span *sitter.Node, src []byte, filePath, packagePath string, endLine int) {
	declType := goImportedTypeText(spec.ChildByFieldName(goFieldType), src, analysis)
	if declType == "" {
		return
	}
	var values []*sitter.Node
	if v := spec.ChildByFieldName("value"); v != nil {
		for i := 0; i < int(v.NamedChildCount()); i++ {
			values = append(values, v.NamedChild(i))
		}
	}
	start, end := span.StartPoint(), span.EndPoint()
	fn := tightestGoFunction(analysis, int(start.Row)+1, int(start.Column)+1)
	if fn == nil {
		fn = goVarinitDecl(analysis, filePath, packagePath, endLine)
	}
	index := 0
	for i := 0; i < int(spec.NamedChildCount()); i++ {
		name := spec.NamedChild(i)
		if name.Type() != goNodeIdentifier {
			continue
		}
		decl := VarDecl{
			Type:     declType,
			Name:     name.Content(src),
			Line:     int(start.Row) + 1,
			StartCol: int(start.Column) + 1,
			EndCol:   int(end.Column) + 1,
		}
		if index < len(values) {
			decl.Init = goVarInitKind(values[index])
		}
		if end.Row != start.Row {
			decl.EndLine = int(end.Row) + 1
		}
		fn.Declarations = append(fn.Declarations, decl)
		index++
	}
}

// goImportedTypeText writes a type through pointers, slices, arrays and type
// arguments with its import path (`*crypto/rsa.PrivateKey`), or "" when the
// named type is not an imported one.
func goImportedTypeText(n *sitter.Node, src []byte, analysis *FileAnalysis) string {
	if n == nil {
		return ""
	}
	switch n.Type() {
	case goNodeQualifiedType:
		alias, name := n.ChildByFieldName("package"), n.ChildByFieldName("name")
		if alias == nil || name == nil {
			return ""
		}
		if path, ok := analysis.Imports[alias.Content(src)]; ok {
			return path + "." + name.Content(src)
		}
	case "pointer_type":
		if inner := goImportedTypeText(n.NamedChild(0), src, analysis); inner != "" {
			return "*" + inner
		}
	case "slice_type":
		if inner := goImportedTypeText(n.ChildByFieldName("element"), src, analysis); inner != "" {
			return "[]" + inner
		}
	case "array_type":
		length := n.ChildByFieldName("length")
		if inner := goImportedTypeText(n.ChildByFieldName("element"), src, analysis); inner != "" && length != nil {
			return "[" + strings.TrimSpace(length.Content(src)) + "]" + inner
		}
	case goNodeGenericType:
		return goImportedTypeText(n.ChildByFieldName(goFieldType), src, analysis)
	}
	return ""
}

// goVarInitKind is the VarInit* kind of a declaration's value.
func goVarInitKind(v *sitter.Node) string {
	for v != nil && v.Type() == goNodeParenExpr && v.NamedChildCount() == 1 {
		v = v.NamedChild(0)
	}
	if v == nil {
		return ""
	}
	switch v.Type() {
	case goNodeCallExpression:
		return VarInitCall
	case goLiteralNil:
		return VarInitNull
	case goNodeInterpretedString, "raw_string_literal", "int_literal", "float_literal", "imaginary_literal", "rune_literal", "true", "false":
		return VarInitLiteral
	}
	return VarInitOther
}
