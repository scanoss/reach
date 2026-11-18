// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// c_references.go gives a C function handed out as a value an edge from where
// it is handed out. C runs much of its code through function pointers: a
// callback registered with a library (`TS_RESP_CTX_set_serial_cb(ctx,
// serial_cb, NULL)`), a pointer stored in a struct (`ops->hash = sha_hash`),
// or a table of handlers written at file scope (`static const struct ops
// ops = { .init = sha_init, .final = sha_final };`). None of them is a call
// expression, so the function had no caller in the graph, and crypto it holds
// read unreachable in an application with a main even when main runs it.
//
// A function name read as a value is an implicit reference call
// (FunctionCall.Reference) from the function that reads it; the builder
// keeps it only when the name is a declared function, as an exact edge. A
// value written in a file-scope initializer belongs to the file's synthetic
// <varinit:file> declaration, which, like Go's, is always a root: a table
// counts as used, so every function it names is reachable (the reference
// holds whether or not code reads the table, as a rapid type analysis
// would). Values are read where C code hands a function out: a call
// argument, the right side of an assignment, an initializer, an element or
// designated value of an initializer list, and a return value; each through
// `&f`, casts, parentheses and both branches of `?:`. A name a parameter or
// a local declaration of the function shadows is not read.

// cVarinitPrefix starts the name of a C file's synthetic file-scope
// declaration.
const cVarinitPrefix = "<varinit:"

// cValueReferences lists the reference calls a function body makes: every
// function name it reads as a value.
func cValueReferences(fn, body *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool) []FunctionCall {
	locals := cLocalNames(fn, body, src)
	var out []FunctionCall
	walkCNodes(body, func(n *sitter.Node) {
		for _, value := range cValueOperands(n) {
			for _, ident := range cValueIdentifiers(value) {
				name := ident.Content(src)
				if locals[name] {
					continue
				}
				out = appendCallbackReference(out, cReference(ident, name, filePath, packagePath, staticFunctions))
			}
		}
	})
	return out
}

// cFileVarinit returns the file's synthetic <varinit:file> declaration holding
// the references of its file-scope initializers, or nil when they name no
// identifier.
func cFileVarinit(root *sitter.Node, src []byte, filePath, packagePath string, staticFunctions map[string]bool) *FunctionDecl {
	var refs []FunctionCall
	var visit func(n *sitter.Node)
	visit = func(n *sitter.Node) {
		switch n.Type() {
		case cNodeFunctionDefinition:
			// Only the body is the function's. What stands between its
			// declarator and its body is file scope that tree-sitter read as
			// K&R parameter declarations: after a macro line it takes for a
			// declarator (`ASN1_SEQUENCE_END(T)` then
			// `IMPLEMENT_ASN1_FUNCTIONS(T)`), the declarations and tables that
			// follow, up to the next body.
			body := n.ChildByFieldName("body")
			for i := 0; i < int(n.ChildCount()); i++ {
				if child := n.Child(i); child.Type() == "declaration" && (body == nil || child.StartByte() < body.StartByte()) {
					visit(child)
				}
			}
			return
		case "init_declarator":
			if value := n.ChildByFieldName("value"); value != nil {
				for _, ident := range cValueIdentifiers(value) {
					refs = appendCallbackReference(refs, cReference(ident, ident.Content(src), filePath, packagePath, staticFunctions))
				}
			}
			return
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			visit(n.Child(i))
		}
	}
	visit(root)
	if len(refs) == 0 {
		return nil
	}
	file := filepath.Base(filePath)
	pkg := file
	if packagePath != "" {
		pkg = packagePath + "/" + file
	}
	return &FunctionDecl{
		ID:            FunctionID{Package: pkg, Name: cVarinitPrefix + strings.TrimSuffix(file, filepath.Ext(file)) + ">", Linkage: LinkageInternal},
		FilePath:      filePath,
		StartLine:     1,
		EndLine:       int(root.EndPoint().Row) + 1,
		OwnerType:     "module",
		OwnerName:     packagePath,
		FunctionType:  "function",
		ImplicitCalls: refs,
	}
}

func cReference(ident *sitter.Node, name, filePath, packagePath string, staticFunctions map[string]bool) *FunctionCall {
	return &FunctionCall{
		Callee:    cFunctionID(packagePath, filePath, name, staticFunctions),
		Raw:       name,
		FilePath:  filePath,
		Line:      int(ident.StartPoint().Row) + 1,
		StartCol:  int(ident.StartPoint().Column) + 1,
		EndCol:    int(ident.EndPoint().Column) + 1,
		EndLine:   int(ident.EndPoint().Row) + 1,
		Reference: true,
	}
}

// cValueOperands returns the expressions n hands out as values: the
// arguments of a call, the right side of an assignment, the value of an
// initializer, the expression of a return.
func cValueOperands(n *sitter.Node) []*sitter.Node {
	switch n.Type() {
	case cNodeCallExpression:
		args := n.ChildByFieldName("arguments")
		if args == nil {
			return nil
		}
		out := make([]*sitter.Node, 0, args.NamedChildCount())
		for i := 0; i < int(args.NamedChildCount()); i++ {
			out = append(out, args.NamedChild(i))
		}
		return out
	case "assignment_expression":
		if right := n.ChildByFieldName("right"); right != nil {
			return []*sitter.Node{right}
		}
	case "init_declarator":
		if value := n.ChildByFieldName("value"); value != nil {
			return []*sitter.Node{value}
		}
	case "return_statement":
		if n.NamedChildCount() > 0 {
			return []*sitter.Node{n.NamedChild(0)}
		}
	}
	return nil
}

// cValueIdentifiers returns the identifiers a value expression stands for:
// itself, through `&`, a cast, parentheses, both branches of `?:`, and every
// element and designated value of an initializer list.
func cValueIdentifiers(n *sitter.Node) []*sitter.Node {
	if n == nil {
		return nil
	}
	switch n.Type() {
	case cNodeIdentifier:
		return []*sitter.Node{n}
	case "parenthesized_expression":
		if n.NamedChildCount() == 1 {
			return cValueIdentifiers(n.NamedChild(0))
		}
	case "cast_expression":
		return cValueIdentifiers(n.ChildByFieldName("value"))
	case "pointer_expression":
		if op := n.ChildByFieldName("operator"); op != nil && op.Type() == "&" {
			return cValueIdentifiers(n.ChildByFieldName("argument"))
		}
	case "conditional_expression":
		return append(cValueIdentifiers(n.ChildByFieldName("consequence")), cValueIdentifiers(n.ChildByFieldName("alternative"))...)
	case "initializer_list":
		var out []*sitter.Node
		for i := 0; i < int(n.NamedChildCount()); i++ {
			out = append(out, cValueIdentifiers(n.NamedChild(i))...)
		}
		return out
	case "initializer_pair":
		return cValueIdentifiers(n.ChildByFieldName("value"))
	}
	return nil
}

// cLocalNames returns the names a function's parameters (fn's declarator;
// none for a function a macro declares, fn nil) and its body's local
// declarations bind.
func cLocalNames(fn, body *sitter.Node, src []byte) map[string]bool {
	names := map[string]bool{}
	if fn != nil {
		for _, p := range cParameters(fn.ChildByFieldName("declarator"), src) {
			if p.Name != "" {
				names[p.Name] = true
			}
		}
	}
	walkCNodes(body, func(n *sitter.Node) {
		if n.Type() != "declaration" {
			return
		}
		for i := 0; i < int(n.ChildCount()); i++ {
			if n.FieldNameForChild(i) != "declarator" {
				continue
			}
			child := n.Child(i)
			if child.Type() == "init_declarator" {
				child = child.ChildByFieldName("declarator")
			}
			if name, _ := cDeclaredName(child, src); name != "" {
				names[name] = true
			}
		}
	})
	return names
}
