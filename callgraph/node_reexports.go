// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// nodeReExportMaxHops bounds the chain of modules a re-exported name is
// followed through (a re-export of a re-export ...).
const nodeReExportMaxHops = 8

// nodeModuleReExports is what one module passes on from other modules under its
// own name: `export { createHash } from 'crypto'`, `import * as crypto from
// 'node:crypto'; export { crypto }`, `export * as ns from 'm'`, and the
// modules it re-exports whole (`export * from 'm'`, `module.exports =
// require('m')`, tsc's __exportStar). own holds the names the module exports
// itself, which a whole re-export never reaches.
type nodeModuleReExports struct {
	names map[string]nodeBinding
	star  []string
	own   map[string]bool
}

// collectNodeReExports reads the re-exports of a parsed file. Specifiers
// resolve as the file's imports do; bindings are its module-level imports.
func collectNodeReExports(root *sitter.Node, src []byte, filePath, packagePath string, bindings nodeBindings) *nodeModuleReExports {
	exports := &NodeExports{Lines: make(map[string]int), NamespaceOf: make(map[string]string), Returned: make(map[string]int)}
	out := &nodeModuleReExports{names: make(map[string]nodeBinding)}
	resolve := func(spec string) string {
		if module, relative := resolveNodeRelativeModule(filePath, packagePath, spec); relative {
			return module
		}
		return spec
	}
	for i := 0; i < int(root.NamedChildCount()); i++ {
		stmt := root.NamedChild(i)
		switch stmt.Type() {
		case nodeExportKind:
			nodeESExportLines(stmt, src, exports)
			collectNodeClauseReExports(stmt, src, bindings, resolve, out.names)
		case nodeExpressionStatement:
			if stmt.NamedChildCount() == 0 {
				continue
			}
			expr := stmt.NamedChild(0)
			nodeCommonJSExportLines(expr, src, exports.Lines)
			if from := nodeExportStarCall(expr, src); from != "" {
				exports.StarFrom = append(exports.StarFrom, from)
			}
			if expr.Type() == nodeAssignmentExpression {
				left := expr.ChildByFieldName("left")
				if from := nodeRequireSource(expr.ChildByFieldName("right"), src); left != nil && from != "" && left.Content(src) == nodeModuleExportsTarget {
					exports.StarFrom = append(exports.StarFrom, from)
				}
			}
		}
	}
	for ns, from := range exports.NamespaceOf {
		out.names[ns] = nodeBinding{module: resolve(from)}
	}
	for _, from := range exports.StarFrom {
		out.star = append(out.star, resolve(from))
	}
	out.own = make(map[string]bool, len(exports.Lines))
	for name := range exports.Lines {
		if _, reExported := out.names[name]; !reExported {
			out.own[name] = true
		}
	}
	if len(out.names) == 0 && len(out.star) == 0 {
		return nil
	}
	return out
}

// collectNodeClauseReExports reads `export { a, b as c } from 'm'`, and
// `export { x, y as z }` of names the module imports.
func collectNodeClauseReExports(stmt *sitter.Node, src []byte, bindings nodeBindings, resolve func(string) string, names map[string]nodeBinding) {
	source := stmt.ChildByFieldName("source")
	for i := 0; i < int(stmt.NamedChildCount()); i++ {
		clause := stmt.NamedChild(i)
		if clause.Type() != nodeExportClauseKind {
			continue
		}
		for j := 0; j < int(clause.NamedChildCount()); j++ {
			spec := clause.NamedChild(j)
			name := spec.ChildByFieldName("name")
			if spec.Type() != nodeExportSpecifier || name == nil {
				continue
			}
			local := unquoteNodeString(name.Content(src))
			exported := local
			if alias := spec.ChildByFieldName("alias"); alias != nil {
				exported = unquoteNodeString(alias.Content(src))
			}
			if source != nil {
				names[exported] = nodeBinding{module: resolve(unquoteNodeString(source.Content(src))), member: local}
				continue
			}
			if binding, ok := bindings[local]; ok && binding.module != "" {
				names[exported] = binding
			}
		}
	}
}

// mergeNodeReExports indexes a file's re-exports by its module path.
func mergeNodeReExports(graph *CallGraph, analysis *FileAnalysis) {
	if analysis.nodeReExports == nil {
		return
	}
	if graph.nodeReExports == nil {
		graph.nodeReExports = make(map[string]*nodeModuleReExports)
	}
	module := nodeModulePath(analysis.PackagePath, analysis.FilePath)
	if _, seen := graph.nodeReExports[module]; seen {
		// Two files of one module path (a .js and its .ts): neither decides.
		graph.nodeReExports[module] = &nodeModuleReExports{}
		return
	}
	graph.nodeReExports[module] = analysis.nodeReExports
}

// resolveNodeReExportedCalls keys a call made through a project module that
// re-exports another module's export as that export: `createHash()` imported
// from a './crypto.js' holding `export { createHash } from 'crypto'` calls
// crypto.createHash, as an import straight from 'crypto' does. A call whose
// key is a function of the graph, or whose name the module does not
// re-export, keeps its key.
func resolveNodeReExportedCalls(graph *CallGraph) {
	if len(graph.nodeReExports) == 0 {
		return
	}
	for _, decl := range graph.Functions {
		for i := range decl.Calls {
			graph.resolveNodeReExport(&decl.Calls[i].Callee)
		}
	}
	for _, read := range graph.nodePropertyReads {
		graph.resolveNodeReExport(&read.call.Callee)
	}
}

func (g *CallGraph) resolveNodeReExport(callee *FunctionID) {
	for hop := 0; hop < nodeReExportMaxHops; hop++ {
		if callee.Package == "" || g.Functions[callee.String()] != nil {
			return
		}
		next, ok := g.nodeReExportedCallee(*callee)
		if !ok {
			return
		}
		*callee = next
	}
}

// nodeReExportedCallee rewrites one hop: the callee's package is a module
// that re-exports, or a member path under one, and the first name read from
// the module is a re-export.
func (g *CallGraph) nodeReExportedCallee(callee FunctionID) (FunctionID, bool) {
	module, rest := g.nodeReExportingModule(callee.Package)
	if module == "" {
		return FunctionID{}, false
	}
	re := g.nodeReExports[module]
	// path is every name read from the module, the last one the callee's
	// type (a construction or a method of an exported class) or name.
	var path []string
	if rest != "" {
		path = strings.Split(rest, ".")
	}
	last := callee.Name
	if callee.Type != "" {
		last = callee.Type
	}
	path = append(path, last)
	binding, ok := re.names[path[0]]
	if !ok {
		if len(re.star) != 1 || re.own[path[0]] {
			return FunctionID{}, false
		}
		binding = nodeBinding{module: re.star[0], member: path[0]}
	}
	var pkg, name string
	if len(path) == 1 {
		pkg, name = binding.qualifyValue()
	} else {
		pkg, name = binding.qualify(path[1:]...)
	}
	out := callee
	out.Package = pkg
	if callee.Type != "" {
		out.Type = name
	} else {
		out.Name = name
	}
	return out, true
}

// nodeReExportingModule finds the module with re-exports that a callee
// package is, or is a member path under: the longest such module path, and
// the member path after it.
func (g *CallGraph) nodeReExportingModule(pkg string) (module, rest string) {
	if _, ok := g.nodeReExports[pkg]; ok {
		return pkg, ""
	}
	for i := len(pkg) - 1; i > 0; i-- {
		if pkg[i] != '.' {
			continue
		}
		if _, ok := g.nodeReExports[pkg[:i]]; ok {
			return pkg[:i], pkg[i+1:]
		}
	}
	return "", ""
}
