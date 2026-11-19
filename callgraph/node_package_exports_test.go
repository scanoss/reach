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
				"@acme/sign.<module>":   "@acme/sign/esm/index.<module>",
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
				"acme-sign.f":              "acme-sign/lib/impl.f",
				"acme-sign/lib/x.f":        "acme-sign/lib/impl.f",
				"acme-sign/util.u":         "acme-sign/util/index.u",
				"acme-sign.<module>":       "acme-sign/index.<module>",
				"acme-sign/lib/x.<module>": "acme-sign/lib/x.<module>",
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

// A module compiled to CommonJS exports through property definitions: tsc
// re-exports a binding with a getter, and esbuild collects a bundle's exports
// in one object of getters handed to __toCommonJS. Both name the functions
// they export.
func TestNodePackageExports_PropertyDefinedExports(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		files map[string]string
		want  map[string]string
	}{
		{
			name: "tsc getters over other modules",
			files: map[string]string{
				"package.json": `{"name":"acme","main":"./lib/index.js"}`,
				"lib/index.js": `"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Signer = exports.importKey = void 0;
var import_js_1 = require("./key/import.js");
Object.defineProperty(exports, "importKey", { enumerable: true, get: function () { return import_js_1.importKey; } });
var sign_js_1 = require("./sign.js");
Object.defineProperty(exports, "Signer", { enumerable: true, get: function () { return sign_js_1.Signer; } });
`,
				"lib/key/import.js": "\"use strict\";\nexports.importKey = void 0;\nasync function importKey(jwk) { return jwk; }\nexports.importKey = importKey;\n",
				"lib/sign.js":       "\"use strict\";\nexports.Signer = void 0;\nclass Signer { constructor(k) { this.k = k; } sign(d) { return d; } }\nexports.Signer = Signer;\n",
			},
			want: map[string]string{
				"acme.importKey":           "acme/lib/key/import.importKey",
				"acme.(Signer).<init>":     "acme/lib/sign.(Signer).constructor",
				"acme.(Signer).sign":       "acme/lib/sign.(Signer).sign",
				"acme.<module>":            "acme/lib/index.<module>",
				"acme/lib.importKey":       "acme/lib/key/import.importKey",
				"acme/lib.(Signer).<init>": "acme/lib/sign.(Signer).constructor",
				"acme/lib.(Signer).sign":   "acme/lib/sign.(Signer).sign",
				"acme/lib.<module>":        "acme/lib/index.<module>",
			},
		},
		{
			name: "esbuild export object",
			files: map[string]string{
				"package.json": `{"name":"acme","main":"./lib/index.cjs"}`,
				"lib/index.cjs": `"use strict";
var __defProp = Object.defineProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __toCommonJS = (mod) => mod;
var index_exports = {};
__export(index_exports, {
  MemoryStore: () => MemoryStore,
  default: () => index_default,
  nip59: () => nip59_exports,
  rateLimit: () => rate_limit_default
});
module.exports = __toCommonJS(index_exports);
var MemoryStore = class { hit(key) { return key; } };
var rateLimit = (options) => { return (req) => req; };
var rate_limit_default = rateLimit;
var index_default = rate_limit_default;
var nip59_exports = {};
__export(nip59_exports, { wrapEvent: () => wrapEvent2 });
function wrapEvent2(e) { return e; }
`,
			},
			want: map[string]string{
				"acme.rateLimit":                  "acme/lib/index.rateLimit",
				"acme.default":                    "acme/lib/index.rateLimit",
				"acme.(MemoryStore).hit":          "acme/lib/index.(MemoryStore).hit",
				"acme.MemoryStore.hit":            "acme/lib/index.(MemoryStore).hit",
				"acme.(rateLimit()).<result>":     "acme/lib/index.<anonymous>@17:39",
				"acme.(default()).<result>":       "acme/lib/index.<anonymous>@17:39",
				"acme.<module>":                   "acme/lib/index.<module>",
				"acme.nip59.wrapEvent":            "acme/lib/index.wrapEvent2",
				"acme/lib.nip59.wrapEvent":        "acme/lib/index.wrapEvent2",
				"acme/lib.rateLimit":              "acme/lib/index.rateLimit",
				"acme/lib.default":                "acme/lib/index.rateLimit",
				"acme/lib.(MemoryStore).hit":      "acme/lib/index.(MemoryStore).hit",
				"acme/lib.MemoryStore.hit":        "acme/lib/index.(MemoryStore).hit",
				"acme/lib.(rateLimit()).<result>": "acme/lib/index.<anonymous>@17:39",
				"acme/lib.(default()).<result>":   "acme/lib/index.<anonymous>@17:39",
				"acme/lib.<module>":               "acme/lib/index.<module>",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildNodePackage(t, "acme", tc.files)
			if !maps.Equal(graph.NodePackageExports, tc.want) {
				t.Errorf("NodePackageExports = %v, want %v; functions: %v", graph.NodePackageExports, tc.want, functionKeys(graph))
			}
		})
	}
}
