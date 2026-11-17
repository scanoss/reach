// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// RustImport is one binding of a Rust `use` declaration or `extern crate`
// item, as written: paths are not resolved (`crate::`, `self::` and `super::`
// stay), only the edition-2018 leading `::` is dropped. A grouped use gives
// one binding per leaf, each with the whole declaration's span and text.
//
//	use a::b::C;            Module a::b, Name C
//	use a::b::C as D;       Module a::b, Name C, Alias D
//	use a::{b::{self, C}};  Module a, Name b; Module a::b, Name C
//	use a::b::*;            Module a::b, Name *
//	use a;                  Module "", Name a
//	extern crate a as z;    Module a, Alias z (no Name, like Python's `import a as z`)
type RustImport struct {
	Module, Name, Alias string
	// Text is the declaration's use tree as written, `a::{b, c as d}` (for
	// `extern crate`, `a` or `a as z`), whitespace kept.
	Text string
	// Line, StartCol and EndCol locate the whole declaration, visibility to
	// semicolon (columns 1-based, end exclusive); EndLine is set only when it
	// spans lines.
	Line, StartCol, EndCol, EndLine int
	// Local marks a declaration inside a function body.
	Local bool
}

// RustItem is one item a Rust file declares, at any depth: an inline module,
// a function, an impl block, a trait, a const, a static, a struct, an
// `extern crate` or a type alias. A reader places a call, a use or a let in
// the items that enclose it from their spans.
type RustItem struct {
	// Kind is one of the RustItem* kinds.
	Kind string
	// Name is the item's name as written; for an impl block its self type,
	// without whitespace (`Kdf<H>`), and for an `extern crate` the crate.
	Name string
	// Line, StartCol and EndCol locate the item, visibility to its closing
	// brace or semicolon, attributes left out (columns 1-based, end
	// exclusive); EndLine is set only when it spans lines.
	Line, StartCol, EndCol, EndLine int
	// Type is a type alias's aliased type, the source text after `=` as
	// written, whitespace kept (`ctr::Ctr128BE<aes::Aes128>`); KeywordCol is
	// the 1-based column of its `type` keyword, which follows any visibility
	// (0 when the keyword is not on Line). Both are set only for a
	// RustItemType.
	Type       string
	KeywordCol int
	// Params are a function's parameters in order, self receiver included;
	// set only for a RustItemFn.
	Params []RustParam
}

// RustParam is one parameter of a Rust function, as written.
//
//	fn f(&self, mut key: &acme::Key, (a, b): (u8, u8), _: u8)
//
// gives Pattern `&self` (Self, no Type), Pattern `mut key` with Type
// `&acme::Key`, Pattern `(a, b)` with Type `(u8, u8)` and Pattern `_` with
// Type `u8`.
type RustParam struct {
	// Pattern is the text before the `:` as written (`key`, `mut key`, `(a,
	// b)`, `_`), or the whole receiver for a shorthand self (`self`, `mut
	// self`, `&self`, `&'a mut self`).
	Pattern string
	// Type is the text after the `:` as written, whitespace kept; "" for a
	// shorthand self.
	Type string
	// Self marks a receiver: a shorthand self or a typed `self: Box<Self>`.
	Self bool
	// Line, StartCol and EndCol locate the parameter, attributes left out
	// (columns 1-based, end exclusive); EndLine is set only when it spans
	// lines.
	Line, StartCol, EndCol, EndLine int
}

// Kinds of a Rust item (RustItem.Kind).
const (
	RustItemMod         = "mod" // an inline `mod m { .. }`; `mod m;` has no body here
	RustItemFn          = "fn"  // a function with a body
	RustItemImpl        = "impl"
	RustItemTrait       = "trait"
	RustItemConst       = "const"
	RustItemStatic      = "static"
	RustItemStruct      = "struct"
	RustItemExternCrate = "extern_crate"
	// RustItemType is a type alias, `[pub] type A<T> = X;`, in a module, a
	// function body or an impl block: an impl's associated type definition
	// (`type Output = X;`) is one too, so consumers see both. A trait's
	// associated type declaration (`type Output;`, `type Output: Bound;`) is
	// none.
	RustItemType = "type"
)

const (
	rustNodeConstItem  = "const_item"
	rustNodeStaticItem = "static_item"
	rustNodeStructItem = "struct_item"
	rustNodeUseList    = "use_list"
	rustNodeScopedUse  = "scoped_use_list"
	rustNodeParam      = "parameter"
	rustNodeSelfParam  = "self_parameter"
)

// collectRustScopeFacts records the imports and items of a whole file in
// source order, into analysis.RustImports and analysis.RustItems. It skips
// what the declaration walk skips: a test-only inline module in a scan
// without tests.
func (p *RustParser) collectRustScopeFacts(root *sitter.Node, src []byte, analysis *FileAnalysis) {
	var walk func(node *sitter.Node, local bool)
	walk = func(node *sitter.Node, local bool) {
		switch node.Type() {
		case rustNodeUseDeclaration:
			recordRustUse(node, src, analysis, local)
			return
		case rustNodeExternCrate:
			recordRustExternCrate(node, src, analysis, local)
			return
		case rustNodeModItem:
			if node.ChildByFieldName("body") == nil {
				return
			}
			if !p.includeTests && rustModuleIsTestOnly(node, src) {
				return
			}
			recordRustItem(node, src, analysis, RustItemMod, nodeFieldText(node, "name", src))
		case rustNodeFunctionItem:
			recordRustFn(node, src, analysis)
			local = true
		case rustNodeImplItem:
			recordRustItem(node, src, analysis, RustItemImpl, rustCompactText(node.ChildByFieldName("type"), src))
		case rustNodeTraitItem:
			recordRustItem(node, src, analysis, RustItemTrait, nodeFieldText(node, "name", src))
		case rustNodeConstItem:
			recordRustItem(node, src, analysis, RustItemConst, nodeFieldText(node, "name", src))
		case rustNodeStaticItem:
			recordRustItem(node, src, analysis, RustItemStatic, nodeFieldText(node, "name", src))
		case rustNodeStructItem:
			recordRustItem(node, src, analysis, RustItemStruct, nodeFieldText(node, "name", src))
		case rustNodeTypeItem:
			recordRustTypeAlias(node, src, analysis)
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i), local)
		}
	}
	walk(root, false)
}

// rustSpan is a node's span as the fragment writes it: 1-based columns, end
// exclusive, and an end line only when the node spans lines.
func rustSpan(node *sitter.Node) (line, startCol, endCol, endLine int) {
	line, endLine = int(node.StartPoint().Row)+1, int(node.EndPoint().Row)+1
	if endLine == line {
		endLine = 0
	}
	return line, int(node.StartPoint().Column) + 1, int(node.EndPoint().Column) + 1, endLine
}

func recordRustItem(node *sitter.Node, src []byte, analysis *FileAnalysis, kind, name string) {
	item := RustItem{Kind: kind, Name: name}
	item.Line, item.StartCol, item.EndCol, item.EndLine = rustSpan(node)
	analysis.RustItems = append(analysis.RustItems, item)
}

// recordRustFn records a function item with its parameters.
func recordRustFn(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	item := RustItem{Kind: RustItemFn, Name: nodeFieldText(node, "name", src), Params: rustParams(node.ChildByFieldName("parameters"), src)}
	item.Line, item.StartCol, item.EndCol, item.EndLine = rustSpan(node)
	analysis.RustItems = append(analysis.RustItems, item)
}

// rustParams lists the parameters of a parameter list as written; an
// attribute on a parameter is left out.
func rustParams(list *sitter.Node, src []byte) []RustParam {
	if list == nil {
		return nil
	}
	var params []RustParam
	for i := 0; i < int(list.NamedChildCount()); i++ {
		node := list.NamedChild(i)
		var param RustParam
		switch node.Type() {
		case rustNodeSelfParam:
			param = RustParam{Pattern: node.Content(src), Self: true}
		case rustNodeParam:
			typ := node.ChildByFieldName("type")
			if typ == nil {
				continue
			}
			param.Type = typ.Content(src)
			end := typ.StartByte()
			for j := 0; j < int(node.ChildCount()); j++ {
				if c := node.Child(j); c.Type() == ":" && !c.IsNamed() {
					end = c.StartByte()
					break
				}
			}
			param.Pattern = strings.TrimSpace(string(src[node.StartByte():end]))
			pattern := node.ChildByFieldName("pattern")
			param.Self = pattern != nil && pattern.Type() == rustNodeSelf
		default:
			continue
		}
		param.Line, param.StartCol, param.EndCol, param.EndLine = rustSpan(node)
		params = append(params, param)
	}
	return params
}

// recordRustTypeAlias records a `type A = X;` item with its aliased type as
// written and the column of its `type` keyword.
func recordRustTypeAlias(node *sitter.Node, src []byte, analysis *FileAnalysis) {
	aliased := node.ChildByFieldName("type")
	if aliased == nil {
		return
	}
	item := RustItem{Kind: RustItemType, Name: nodeFieldText(node, "name", src), Type: aliased.Content(src)}
	item.Line, item.StartCol, item.EndCol, item.EndLine = rustSpan(node)
	for i := 0; i < int(node.ChildCount()); i++ {
		if kw := node.Child(i); kw.Type() == "type" && !kw.IsNamed() {
			if int(kw.StartPoint().Row)+1 == item.Line {
				item.KeywordCol = int(kw.StartPoint().Column) + 1
			}
			break
		}
	}
	analysis.RustItems = append(analysis.RustItems, item)
}

// recordRustExternCrate records an `extern crate a [as z];` as an import and
// as an item.
func recordRustExternCrate(node *sitter.Node, src []byte, analysis *FileAnalysis, local bool) {
	name := node.ChildByFieldName("name")
	if name == nil {
		return
	}
	recordRustItem(node, src, analysis, RustItemExternCrate, name.Content(src))
	imp := RustImport{Module: name.Content(src), Local: local}
	end := name.EndByte()
	if alias := node.ChildByFieldName("alias"); alias != nil {
		imp.Alias = alias.Content(src)
		end = alias.EndByte()
	}
	imp.Text = string(src[name.StartByte():end])
	imp.Line, imp.StartCol, imp.EndCol, imp.EndLine = rustSpan(node)
	analysis.RustImports = append(analysis.RustImports, imp)
}

// recordRustUse records one binding per leaf of a use declaration's tree.
func recordRustUse(node *sitter.Node, src []byte, analysis *FileAnalysis, local bool) {
	argument := node.ChildByFieldName("argument")
	if argument == nil {
		return
	}
	base := RustImport{Text: argument.Content(src), Local: local}
	base.Line, base.StartCol, base.EndCol, base.EndLine = rustSpan(node)
	rustUseLeaves(argument, src, "", func(path, name, alias string) {
		imp := base
		imp.Module, imp.Name, imp.Alias = path, name, alias
		analysis.RustImports = append(analysis.RustImports, imp)
	})
}

// rustUseLeaves calls emit for each binding of a use tree under prefix: the
// module path, the bound name (or "*") and the alias.
func rustUseLeaves(node *sitter.Node, src []byte, prefix string, emit func(module, name, alias string)) {
	leaf := func(path, alias string) {
		if path == "" {
			return
		}
		module, name := "", path
		if i := strings.LastIndex(path, "::"); i >= 0 {
			module, name = path[:i], path[i+2:]
		}
		emit(module, name, alias)
	}
	switch node.Type() {
	case rustNodeUseList:
		for i := 0; i < int(node.NamedChildCount()); i++ {
			rustUseLeaves(node.NamedChild(i), src, prefix, emit)
		}
	case rustNodeScopedUse:
		path := joinRustPath(prefix, rustCompactText(node.ChildByFieldName("path"), src))
		if list := node.ChildByFieldName("list"); list != nil {
			rustUseLeaves(list, src, path, emit)
		}
	case rustNodeUseAsClause:
		path := node.ChildByFieldName("path")
		if path == nil {
			return
		}
		alias := nodeFieldText(node, "alias", src)
		if path.Type() == rustNodeSelf && prefix != "" {
			leaf(prefix, alias) // `{self as x}` renames the prefix
			return
		}
		leaf(joinRustPath(prefix, rustCompactText(path, src)), alias)
	case rustNodeUseWildcard:
		path := prefix
		if node.NamedChildCount() > 0 {
			path = joinRustPath(prefix, rustCompactText(node.NamedChild(0), src))
		}
		emit(path, "*", "")
	case rustNodeSelf:
		if prefix != "" {
			leaf(prefix, "") // `{self}` binds the prefix's last segment
			return
		}
		leaf("self", "")
	default:
		leaf(joinRustPath(prefix, rustCompactText(node, src)), "")
	}
}

// joinRustPath joins two path pieces with `::`.
func joinRustPath(prefix, path string) string {
	switch {
	case prefix == "":
		return path
	case path == "":
		return prefix
	}
	return prefix + "::" + path
}

// rustCompactText is a node's text without whitespace and without the
// edition-2018 leading `::`; "" for a nil node.
func rustCompactText(node *sitter.Node, src []byte) string {
	if node == nil {
		return ""
	}
	return strings.TrimPrefix(rustTokenText(node.Content(src)), "::")
}

// rustTokenText is text without whitespace, but for one space between two
// words (`<A as B>::X`, `dyn Signer`).
func rustTokenText(text string) string {
	fields := strings.Fields(text)
	var b strings.Builder
	for i, f := range fields {
		if i > 0 && rustWordByte(fields[i-1][len(fields[i-1])-1]) && rustWordByte(f[0]) {
			b.WriteByte(' ')
		}
		b.WriteString(f)
	}
	return b.String()
}

func rustWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= 0x80
}

// recordRustScopeFacts files a parsed file's imports, items and binary
// expressions under its path.
func recordRustScopeFacts(graph *CallGraph, analysis *FileAnalysis) {
	if len(analysis.RustBinaryExprs) > 0 {
		if graph.RustBinaryExprs == nil {
			graph.RustBinaryExprs = make(map[string][]RustBinaryExpr)
		}
		graph.RustBinaryExprs[analysis.FilePath] = analysis.RustBinaryExprs
	}
	if len(analysis.RustImports) > 0 {
		if graph.RustImports == nil {
			graph.RustImports = make(map[string][]RustImport)
		}
		graph.RustImports[analysis.FilePath] = analysis.RustImports
	}
	if len(analysis.RustItems) > 0 {
		if graph.RustItems == nil {
			graph.RustItems = make(map[string][]RustItem)
		}
		graph.RustItems[analysis.FilePath] = analysis.RustItems
	}
}
