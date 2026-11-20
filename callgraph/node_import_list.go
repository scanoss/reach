// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import sitter "github.com/smacker/go-tree-sitter"

// NodeImport is one binding a JavaScript or TypeScript file makes to another
// module, or one load of a module that binds nothing. Module is the specifier
// as written ('node:crypto', './util', '@scope/pkg/sub'). Name is the export
// imported ("default" for a default import, "*" for a namespace or star
// form, a dotted path for `const k = require('m').a.b`), empty when the
// module itself is bound or nothing is. Alias is the local name when it
// differs from Name, or the name a module binding gets. Kind tells the form:
//
//	""         import d from 'm'; import * as ns from 'm'; import { a as b } from 'm'; import 'm'
//	"type"     import type { T } from 'm' (TypeScript, loads nothing at run time)
//	"require"  const x = require('m'); const { a } = require('m'); require('m')(..);
//	           import x = require('m') (TypeScript)
//	"dynamic"  import('m')
//	"export"   export * from 'm'; export * as ns from 'm'; export { a as b } from 'm'
//
// Local marks one written inside a function or class body.
type NodeImport struct {
	Line   int
	Module string
	Name   string
	Alias  string
	Kind   string
	Local  bool
}

// Kinds of NodeImport.
const (
	NodeImportType    = "type"
	NodeImportRequire = "require"
	NodeImportDynamic = "dynamic"
	NodeImportExport  = "export"
)

// nodeImportAll is the Name of a namespace import or a star re-export.
const nodeImportAll = "*"

// collectNodeImports lists, in source order, every import, require, dynamic
// import and re-export the file makes, at module level or in any function.
func collectNodeImports(root *sitter.Node, src []byte) []NodeImport {
	var out []NodeImport
	var walk func(n *sitter.Node, local bool)
	walk = func(n *sitter.Node, local bool) {
		if n == nil {
			return
		}
		line := int(n.StartPoint().Row) + 1
		switch n.Type() {
		case "import_statement":
			out = append(out, nodeStatementImports(n, src, line, local)...)
			return
		case nodeExportKind:
			if source := n.ChildByFieldName("source"); source != nil {
				out = append(out, nodeReExports(n, src, unquoteNodeString(source.Content(src)), line, local)...)
				return
			}
		case nodeVariableDeclarator:
			if imports, ok := nodeRequireDeclaratorImports(n, src, line, local); ok {
				out = append(out, imports...)
				return
			}
		case nodeAssignmentExpression:
			if imp, ok := nodeRequireAssignmentImport(n, src, line, local); ok {
				out = append(out, imp)
				return
			}
		case nodeCallExpression:
			if imp, ok := nodeLoadCall(n, src, line, local); ok {
				out = append(out, imp)
			}
		}
		if isNodeNestedScope(n.Type()) || n.Type() == "generator_function" {
			local = true
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i), local)
		}
	}
	walk(root, false)
	return out
}

// nodeStatementImports reads one import statement.
func nodeStatementImports(n *sitter.Node, src []byte, line int, local bool) []NodeImport {
	if alias, module, ok := nodeImportRequireClause(n, src); ok {
		return []NodeImport{{Line: line, Module: module, Alias: alias, Kind: NodeImportRequire, Local: local}}
	}
	source := n.ChildByFieldName("source")
	if source == nil {
		return nil
	}
	base := NodeImport{Line: line, Module: unquoteNodeString(source.Content(src)), Local: local}
	for i := 0; i < int(n.ChildCount()); i++ {
		if n.Child(i).Type() == "type" {
			base.Kind = NodeImportType
		}
	}
	var out []NodeImport
	var clause func(c *sitter.Node)
	clause = func(c *sitter.Node) {
		for i := 0; i < int(c.NamedChildCount()); i++ {
			child := c.NamedChild(i)
			imp := base
			switch child.Type() {
			case goNodeIdentifier:
				imp.Name, imp.Alias = nodeDefaultKeyword, child.Content(src)
			case "namespace_import":
				imp.Name = nodeImportAll
				if child.NamedChildCount() > 0 {
					imp.Alias = child.NamedChild(0).Content(src)
				}
			case "named_imports":
				clause(child)
				continue
			case "import_specifier":
				imp.Name, imp.Alias = nodeSpecifierNames(child, src)
				if imp.Name == "" {
					continue
				}
				if nodeSpecifierIsType(child) {
					imp.Kind = NodeImportType
				}
			default:
				continue
			}
			out = append(out, imp)
		}
	}
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if c := n.NamedChild(i); c.Type() == "import_clause" {
			clause(c)
		}
	}
	if len(out) == 0 {
		out = append(out, base)
	}
	return out
}

// nodeReExports reads `export ... from 'm'`.
func nodeReExports(n *sitter.Node, src []byte, module string, line int, local bool) []NodeImport {
	base := NodeImport{Line: line, Module: module, Kind: NodeImportExport, Local: local}
	var out []NodeImport
	for i := 0; i < int(n.NamedChildCount()); i++ {
		child := n.NamedChild(i)
		switch child.Type() {
		case "namespace_export":
			imp := base
			imp.Name = nodeImportAll
			if child.NamedChildCount() > 0 {
				imp.Alias = unquoteNodeString(child.NamedChild(0).Content(src))
			}
			out = append(out, imp)
		case "export_clause":
			for j := 0; j < int(child.NamedChildCount()); j++ {
				spec := child.NamedChild(j)
				if spec.Type() != "export_specifier" {
					continue
				}
				imp := base
				imp.Name, imp.Alias = nodeSpecifierNames(spec, src)
				if imp.Name != "" {
					out = append(out, imp)
				}
			}
		}
	}
	if len(out) == 0 {
		base.Name = nodeImportAll
		out = append(out, base)
	}
	return out
}

// nodeSpecifierNames reads `name` or `name as alias` of an import or export
// specifier. A string name (`import { "a-b" as c }`) is unquoted.
func nodeSpecifierNames(spec *sitter.Node, src []byte) (name, alias string) {
	n := spec.ChildByFieldName("name")
	if n == nil {
		return "", ""
	}
	name = unquoteNodeString(n.Content(src))
	if a := spec.ChildByFieldName("alias"); a != nil {
		alias = unquoteNodeString(a.Content(src))
	}
	if alias == name {
		alias = ""
	}
	return name, alias
}

// nodeSpecifierIsType reports a TypeScript `import { type T }` specifier.
func nodeSpecifierIsType(spec *sitter.Node) bool {
	for i := 0; i < int(spec.ChildCount()); i++ {
		if spec.Child(i).Type() == "type" {
			return true
		}
	}
	return false
}

// nodeRequireDeclaratorImports reads a declarator bound to a require:
// `const x = require('m')`, `const k = require('m').a.b`, `const { a, b: c }
// = require('m')`, or any of them through an import interop helper.
func nodeRequireDeclaratorImports(n *sitter.Node, src []byte, line int, local bool) ([]NodeImport, bool) {
	name := n.ChildByFieldName("name")
	binding, ok := nodeRequireBinding(n.ChildByFieldName("value"), src)
	if !ok || name == nil {
		return nil, false
	}
	base := NodeImport{Line: line, Module: binding.module, Kind: NodeImportRequire, Local: local}
	switch name.Type() {
	case goNodeIdentifier:
		imp := base
		imp.Name, imp.Alias = binding.member, name.Content(src)
		if imp.Alias == imp.Name {
			imp.Alias = ""
		}
		return []NodeImport{imp}, true
	case nodeObjectPattern:
		var out []NodeImport
		for i := 0; i < int(name.NamedChildCount()); i++ {
			item := name.NamedChild(i)
			imp := base
			switch item.Type() {
			case nodeShorthandPattern:
				imp.Name = joinNodeMember(binding.member, item.Content(src))
			case nodePairPattern:
				key, value := item.ChildByFieldName("key"), item.ChildByFieldName("value")
				if key == nil || value == nil || value.Type() != goNodeIdentifier {
					continue
				}
				imp.Name = joinNodeMember(binding.member, unquoteNodeString(key.Content(src)))
				if alias := value.Content(src); alias != imp.Name {
					imp.Alias = alias
				}
			default:
				continue
			}
			out = append(out, imp)
		}
		if len(out) == 0 {
			out = append(out, base)
		}
		return out, true
	}
	return []NodeImport{base}, true
}

// nodeLoadCall reads a call that loads a module without binding it to a
// declared name: `require('m')` (inline, assigned, called) or `import('m')`.
func nodeLoadCall(n *sitter.Node, src []byte, line int, local bool) (NodeImport, bool) {
	function := n.ChildByFieldName("function")
	arguments := n.ChildByFieldName("arguments")
	if function == nil || arguments == nil || arguments.NamedChildCount() < 1 {
		return NodeImport{}, false
	}
	arg := arguments.NamedChild(0)
	if arg.Type() != nodeStringNode {
		return NodeImport{}, false
	}
	kind := ""
	switch {
	case function.Type() == "import":
		kind = NodeImportDynamic
	case function.Type() == goNodeIdentifier && function.Content(src) == nodeRequireFunction && arguments.NamedChildCount() == 1:
		kind = NodeImportRequire
	default:
		return NodeImport{}, false
	}
	module := unquoteNodeString(arg.Content(src))
	return NodeImport{Line: line, Module: module, Kind: kind, Local: local}, module != ""
}

// nodeRequireAssignmentImport reads `x = require('m')` (and `x = require('m').a`)
// where x is declared elsewhere, as Babel emits for a conditional require.
func nodeRequireAssignmentImport(n *sitter.Node, src []byte, line int, local bool) (NodeImport, bool) {
	left := n.ChildByFieldName("left")
	if left == nil || left.Type() != goNodeIdentifier {
		return NodeImport{}, false
	}
	binding, ok := nodeRequireBinding(n.ChildByFieldName("right"), src)
	if !ok {
		return NodeImport{}, false
	}
	imp := NodeImport{Line: line, Module: binding.module, Name: binding.member, Alias: left.Content(src), Kind: NodeImportRequire, Local: local}
	if imp.Alias == imp.Name {
		imp.Alias = ""
	}
	return imp, true
}
