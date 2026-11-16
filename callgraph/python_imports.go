// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import sitter "github.com/smacker/go-tree-sitter"

// PythonImport is one binding a Python import statement makes: `import
// a.b` (Module "a.b"), `import a.b as z` (Alias "z"), `from m import n as a`
// (Module "m", Name "n", Alias "a") or `from m import *` (Name "*"). A
// relative module is resolved against the file's package (`from .core import
// Signer` in pkg/__init__.py names pkg.core). Local marks an import inside a
// function or class body.
type PythonImport struct {
	Line   int
	Module string
	Name   string
	Alias  string
	Local  bool
}

// pythonWildcardImport is the Name of a `from m import *` binding.
const pythonWildcardImport = "*"

// recordPythonImports appends the bindings of one import or from-import
// statement to analysis.PythonImports, in source order. A from-import whose
// relative module walks above the package root binds nothing.
func recordPythonImports(node *sitter.Node, src []byte, analysis *FileAnalysis, local bool) {
	line := int(node.StartPoint().Row) + 1
	module := ""
	from := node.Symbol() == pythonSyms.importFromStatement
	if from {
		var ok bool
		module, ok = pythonImportFromModulePath(node.ChildByFieldName("module_name"), src, pythonImportingPackage(analysis))
		if !ok {
			return
		}
	}
	for i := 0; i < int(node.ChildCount()); i++ {
		child := node.Child(i)
		if from && child.Type() == "wildcard_import" {
			analysis.PythonImports = append(analysis.PythonImports, PythonImport{Line: line, Module: module, Name: pythonWildcardImport, Local: local})
			continue
		}
		if node.FieldNameForChild(i) != pythonFieldName {
			continue
		}
		name, alias := child, (*sitter.Node)(nil)
		if child.Type() == pythonNodeAliasedImport {
			name, alias = child.ChildByFieldName("name"), child.ChildByFieldName("alias")
		}
		imp := PythonImport{Line: line, Module: name.Content(src), Local: local}
		if from {
			imp.Module, imp.Name = module, name.Content(src)
		}
		if alias != nil {
			imp.Alias = alias.Content(src)
		}
		analysis.PythonImports = append(analysis.PythonImports, imp)
	}
}

// qualifyPythonImports requalifies the project's own modules the imports of a
// project parsed under root name, as qualifyPythonProjectImports does for
// calls.
func qualifyPythonImports(imports []PythonImport, root string, modules map[string]bool) {
	for i := range imports {
		imports[i].Module = qualifyPythonProjectModule(imports[i].Module, root, modules)
	}
}
