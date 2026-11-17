// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"
	"reflect"
	"testing"
)

// nodeImportsOf builds a project of the given files and returns the import
// list the graph holds for name.
func nodeImportsOf(t *testing.T, files map[string]string, name string) []NodeImport {
	t.Helper()
	graph := buildNodeFiles(t, files)
	for path, imports := range graph.NodeImports {
		if filepath.Base(path) == name {
			return imports
		}
	}
	t.Fatalf("no imports for %s in %v", name, graph.NodeImports)
	return nil
}

func assertNodeImports(t *testing.T, got, want []NodeImport) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("imports:\n got  %+v\n want %+v", got, want)
	}
}

func TestNodeImportsESMForms(t *testing.T) {
	t.Parallel()

	src := `import zorkDefault, * as zorkNs from 'zork-lib';
import { plugh, xyzzy as xz, default as dflt } from 'plugh-lib';
import 'side-effect-lib';
import nodeCrypto from 'node:crypto';
import { frob } from './local-mod';
export * from 'star-lib';
export * as reNs from 'ns-lib';
export { grault as garply, default } from 'grault-lib';
export const kept = 1;
`
	got := nodeImportsOf(t, map[string]string{"mod.mjs": src}, "mod.mjs")
	assertNodeImports(t, got, []NodeImport{
		{Line: 1, Module: "zork-lib", Name: "default", Alias: "zorkDefault"},
		{Line: 1, Module: "zork-lib", Name: "*", Alias: "zorkNs"},
		{Line: 2, Module: "plugh-lib", Name: "plugh"},
		{Line: 2, Module: "plugh-lib", Name: "xyzzy", Alias: "xz"},
		{Line: 2, Module: "plugh-lib", Name: "default", Alias: "dflt"},
		{Line: 3, Module: "side-effect-lib"},
		{Line: 4, Module: "node:crypto", Name: "default", Alias: "nodeCrypto"},
		{Line: 5, Module: "./local-mod", Name: "frob"},
		{Line: 6, Module: "star-lib", Name: "*", Kind: NodeImportExport},
		{Line: 7, Module: "ns-lib", Name: "*", Alias: "reNs", Kind: NodeImportExport},
		{Line: 8, Module: "grault-lib", Name: "grault", Alias: "garply", Kind: NodeImportExport},
		{Line: 8, Module: "grault-lib", Name: "default", Kind: NodeImportExport},
	})
}

func TestNodeImportsRequireAndDynamicForms(t *testing.T) {
	t.Parallel()

	src := `const zork = require('zork-lib');
const { plugh, xyzzy: xz } = require('plugh-lib');
const EC = require('thud-lib').curves.ec;
const wrapped = _interopRequireDefault(require('wrap-lib'));
require('side-effect-lib');
function run() {
  const lazy = require('lazy-lib');
  require('call-lib')('x');
  new (require('ctor-lib'))();
  return import('dyn-lib');
}
class Holder {
  load() { return require('method-lib').f(); }
}
`
	got := nodeImportsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeImports(t, got, []NodeImport{
		{Line: 1, Module: "zork-lib", Alias: "zork", Kind: NodeImportRequire},
		{Line: 2, Module: "plugh-lib", Name: "plugh", Kind: NodeImportRequire},
		{Line: 2, Module: "plugh-lib", Name: "xyzzy", Alias: "xz", Kind: NodeImportRequire},
		{Line: 3, Module: "thud-lib", Name: "curves.ec", Alias: "EC", Kind: NodeImportRequire},
		{Line: 4, Module: "wrap-lib", Alias: "wrapped", Kind: NodeImportRequire},
		{Line: 5, Module: "side-effect-lib", Kind: NodeImportRequire},
		{Line: 7, Module: "lazy-lib", Alias: "lazy", Kind: NodeImportRequire, Local: true},
		{Line: 8, Module: "call-lib", Kind: NodeImportRequire, Local: true},
		{Line: 9, Module: "ctor-lib", Kind: NodeImportRequire, Local: true},
		{Line: 10, Module: "dyn-lib", Kind: NodeImportDynamic, Local: true},
		{Line: 13, Module: "method-lib", Kind: NodeImportRequire, Local: true},
	})
}

func TestNodeImportsTypeScriptForms(t *testing.T) {
	t.Parallel()

	src := `import fred = require('fred-lib');
import type { Shape } from 'shape-lib';
import { type Kind, value } from 'mixed-lib';
import Thud from 'thud-lib';
export function run(): Promise<unknown> {
  return import('dyn-lib');
}
`
	got := nodeImportsOf(t, map[string]string{"mod.ts": src}, "mod.ts")
	assertNodeImports(t, got, []NodeImport{
		{Line: 1, Module: "fred-lib", Alias: "fred", Kind: NodeImportRequire},
		{Line: 2, Module: "shape-lib", Name: "Shape", Kind: NodeImportType},
		{Line: 3, Module: "mixed-lib", Name: "Kind", Kind: NodeImportType},
		{Line: 3, Module: "mixed-lib", Name: "value"},
		{Line: 4, Module: "thud-lib", Name: "default", Alias: "Thud"},
		{Line: 6, Module: "dyn-lib", Kind: NodeImportDynamic, Local: true},
	})
}

// A file that imports nothing has no entry, and the list is the project's
// alone: a dependency's files are not listed.
func TestNodeImportsOnlyProjectFilesThatImport(t *testing.T) {
	t.Parallel()

	graph := buildNodeAppWithDependency(t, "zork-lib", map[string]string{
		"package.json": `{"name":"zork-lib","main":"index.js"}`,
		"index.js":     "const inner = require('inner-lib');\nmodule.exports = () => inner();\n",
		"quiet.js":     "module.exports = 1;\n",
	}, "const zork = require('zork-lib');\nfunction run() { zork(); }\n")
	if len(graph.NodeImports) != 1 {
		t.Fatalf("NodeImports = %v, want the app's index.js alone", graph.NodeImports)
	}
	for path, imports := range graph.NodeImports {
		if filepath.Base(path) != "index.js" || len(imports) != 1 || imports[0].Module != "zork-lib" {
			t.Errorf("NodeImports[%s] = %+v, want the app's require of zork-lib", path, imports)
		}
	}
}
