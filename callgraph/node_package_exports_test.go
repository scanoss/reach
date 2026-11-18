// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"maps"
	"path/filepath"
	"slices"
	"testing"
)

// buildNodePackage builds one Node package alone, as a dependency is mined.
func buildNodePackage(t *testing.T, importPath string, files map[string]string) *CallGraph {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "pkg")
	for name, body := range files {
		writeCallgraphFixture(t, filepath.Join(dir, filepath.FromSlash(name)), body)
	}
	graph, err := NewBuilderForEcosystem(ecosystemNode, NewNodeParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: importPath, Version: "1.0.0"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// A package's graph publishes, for each key a caller spells through one of
// its specifiers, the function the package declares under another key.
func TestNodePackageExports(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		pkg   string
		files map[string]string
		want  map[string]string
	}{
		{
			name: "CommonJS exports.f in the main module",
			pkg:  "acme-sign",
			files: map[string]string{
				"package.json": `{"name":"acme-sign"}`,
				"index.js":     "exports.sign = function sign(k) { return k; };\n",
			},
			want: map[string]string{"acme-sign.sign": "acme-sign/index.sign"},
		},
		{
			name: "module.exports object of functions and of objects with property functions",
			pkg:  "notp",
			files: map[string]string{
				"package.json": `{"name":"notp"}`,
				"index.js": `var hotp = {}, totp = {};
hotp.gen = function (key) { return key; };
totp.gen = function (key) { return hotp.gen(key); };
function verify(t) { return t; }
module.exports = { hotp, totp, verify };
`,
			},
			want: map[string]string{
				"notp.hotp.gen": "notp/index.(hotp).gen",
				"notp.totp.gen": "notp/index.(totp).gen",
				"notp.verify":   "notp/index.verify",
			},
		},
		{
			name: "module.exports = function, called as the module",
			pkg:  "dflt",
			files: map[string]string{
				"package.json": `{"name":"dflt","main":"lib/main.js"}`,
				"lib/main.js":  "module.exports = function (x) { return x; };\n",
			},
			want: map[string]string{"dflt.default": "dflt/lib/main.exports"},
		},
		{
			name: "ESM export function and export default, re-exported through export *, scoped",
			pkg:  "@acme/sign",
			files: map[string]string{
				"package.json":  `{"name":"@acme/sign","type":"module","exports":{".":{"import":"./esm/index.js"},"./package.json":"./package.json"}}`,
				"esm/index.js":  "export * from './sign.js';\nexport default function main() {}\n",
				"esm/sign.js":   "export function sign() {}\nexport const tools = { hash: function () {} };\n",
				"esm/unused.js": "export function unused() {}\n",
			},
			want: map[string]string{
				"@acme/sign.default":    "@acme/sign/esm/index.main",
				"@acme/sign.sign":       "@acme/sign/esm/sign.sign",
				"@acme/sign.tools.hash": "@acme/sign/esm/sign.(tools).hash",
			},
		},
		{
			name: "subpaths: exports map, pattern, directory index and a re-exporting file",
			pkg:  "acme-sign",
			files: map[string]string{
				"package.json":     `{"name":"acme-sign","exports":{".":"./index.js","./sub":{"default":"./lib/sub.js"},"./feature/*":"./src/feature/*.js"}}`,
				"index.js":         "exports.sign = function sign() {};\n",
				"lib/sub.js":       "exports.go = function go() {};\n",
				"src/feature/a.js": "exports.run = function run() {};\n",
			},
			want: map[string]string{
				"acme-sign.sign":          "acme-sign/index.sign",
				"acme-sign/sub.go":        "acme-sign/lib/sub.go",
				"acme-sign/feature/a.run": "acme-sign/src/feature/a.run",
			},
		},
		{
			name: "subpaths without an exports map",
			pkg:  "acme-sign",
			files: map[string]string{
				"package.json":  `{"name":"acme-sign"}`,
				"index.js":      "module.exports = require('./lib/x');\n",
				"lib/x.js":      "module.exports = require('./impl');\n",
				"lib/impl.js":   "exports.f = function (a) { return a; };\n",
				"util/index.js": "export function u() {}\n",
				"plain.js":      "exports.p = function p() {};\n",
			},
			want: map[string]string{
				"acme-sign.f":       "acme-sign/lib/impl.f",
				"acme-sign/lib/x.f": "acme-sign/lib/impl.f",
				"acme-sign/util.u":  "acme-sign/util/index.u",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildNodePackage(t, tc.pkg, tc.files)
			if !maps.Equal(graph.NodePackageExports, tc.want) {
				t.Errorf("NodePackageExports = %v, want %v; functions: %v", graph.NodePackageExports, tc.want, functionKeys(graph))
			}
			for public, key := range graph.NodePackageExports {
				if graph.Functions[key] == nil {
					t.Errorf("%s -> %s, which the graph does not declare", public, key)
				}
			}
		})
	}
}

// An export that is not a function's own definition, such as an object on
// the line of the function it holds, publishes nothing for the object.
func TestNodePackageExports_ObjectOnAFunctionLine(t *testing.T) {
	t.Parallel()
	graph := buildNodePackage(t, "acme", map[string]string{
		"package.json": `{"name":"acme"}`,
		"index.js":     "exports.tools = { hash: function () {} };\n",
	})
	if _, ok := graph.NodePackageExports["acme.tools"]; ok {
		t.Errorf("acme.tools published as %s", graph.NodePackageExports["acme.tools"])
	}
	if got := graph.NodePackageExports["acme.tools.hash"]; got != "acme/index.hash" {
		t.Errorf("acme.tools.hash -> %q, want acme/index.hash", got)
	}
}

// The application and the dependency, each built alone as their graphs are
// mined, meet through the dependency's exports: every call the application
// spells through the package names, in the dependency's table, the function
// that makes the dependency's call. This is the join the stitch makes.
func TestNodePackageExports_JoinApplicationCalls(t *testing.T) {
	t.Parallel()
	dep := buildNodePackage(t, "notp", map[string]string{
		"package.json": `{"name":"notp"}`,
		"index.js": `const crypto = require('crypto');
var hotp = {}, totp = {};
hotp.gen = function (key) { return crypto.createHmac('sha1', key); };
totp.gen = function (key) { return hotp.gen(key); };
module.exports = { hotp, totp };
`,
	})
	app := buildNodeFiles(t, map[string]string{
		"index.js": "const notp = require('notp');\nfunction run(k) { return notp.hotp.gen(k); }\n",
		"esm.mjs":  "import { totp } from 'notp';\nexport function run(k) { return totp.gen(k); }\n",
	})
	for caller, want := range map[string]string{"app/index.run": "notp/index.(hotp).gen", "app/esm.run": "notp/index.(totp).gen"} {
		fn := app.Functions[caller]
		if fn == nil {
			t.Fatalf("%s not declared; functions: %v", caller, functionKeys(app))
		}
		callees := calleesOf(fn)
		if len(callees) != 1 {
			t.Fatalf("%s calls %v, want one call", caller, callees)
		}
		if got := dep.NodePackageExports[callees[0]]; got != want {
			t.Errorf("%s calls %s, which the dependency exports as %q, want %s", caller, callees[0], got, want)
		}
	}
	hotp := dep.Functions["notp/index.(hotp).gen"]
	if hotp == nil || !slices.Contains(calleesOf(hotp), "crypto.createHmac") {
		t.Fatalf("notp/index.(hotp).gen = %+v, want it to call crypto.createHmac", hotp)
	}
}
