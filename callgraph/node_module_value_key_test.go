// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// nodeCalleesOf parses one file and returns the callees of fnName's calls by
// line.
func nodeCalleesOf(t *testing.T, name, src, fnName string) map[int]string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewNodeParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	fn := nodeFunction(t, analyses[0], fnName)
	got := map[int]string{}
	for i := range fn.Calls {
		got[fn.Calls[i].Line] = fn.Calls[i].Callee.String()
	}
	return got
}

func assertNodeCallees(t *testing.T, got, want map[int]string) {
	t.Helper()
	for line, callee := range want {
		if got[line] != callee {
			t.Errorf("line %d: callee %q, want %q", line, got[line], callee)
		}
	}
	if len(got) != len(want) {
		t.Errorf("calls by line = %v, want %v", got, want)
	}
}

// A call or `new` of a module binding itself is keyed by the module's default
// export, never by the local name: m.default for a call, m.(default).<init>
// for a construction, under every way of binding or reaching the module.
func TestNodeModuleValueKeyIgnoresLocalName(t *testing.T) {
	t.Parallel()

	src := `const kk = require('zork-hash');
const createZork = require('zork-hash');
const Hasher = require('quux-sha');
const viaDefault = require('plugh-lib').default;
const wrapped = _interopRequireDefault(require('xyzzy-lib'));
function run() {
  kk('x');
  createZork('x');
  new Hasher();
  viaDefault('w');
  kk.default('v');
  new kk.default();
  require('frob-lib')('z');
  new (require('frob-lib'))();
  new (require('frob-lib').Klass)();
  wrapped.default('u');
  require('frob-lib').default('t');
}
`
	got := nodeCalleesOf(t, "run.js", src, "run")
	assertNodeCallees(t, got, map[int]string{
		7:  "zork-hash.default",
		8:  "zork-hash.default",
		9:  "quux-sha.(default).<init>",
		10: "plugh-lib.default",
		11: "zork-hash.default",
		12: "zork-hash.(default).<init>",
		13: "frob-lib.default",
		14: "frob-lib.(default).<init>",
		15: "frob-lib.(Klass).<init>",
		16: "xyzzy-lib.default",
		17: "frob-lib.default",
	})
}

func TestNodeModuleValueKeyESMImports(t *testing.T) {
	t.Parallel()

	src := `import jw from 'grault-jwa';
import * as star from 'garply-lib';
import Foo from 'waldo-lib';
import { default as Bar } from 'waldo-lib';
function run() {
  jw('HS256');
  star('y');
  new Foo('x');
  new Bar('x');
  new star();
  star.default('q');
}
`
	got := nodeCalleesOf(t, "run.mjs", src, "run")
	assertNodeCallees(t, got, map[int]string{
		6:  "grault-jwa.default",
		7:  "garply-lib.default",
		8:  "waldo-lib.(default).<init>",
		9:  "waldo-lib.(default).<init>",
		10: "garply-lib.(default).<init>",
		11: "garply-lib.default",
	})
}

// TypeScript's `import x = require('m')` binds x as `const x = require('m')`
// does.
func TestNodeModuleValueKeyTypeScriptImportRequire(t *testing.T) {
	t.Parallel()

	src := `import fred = require('fred-lib');
import Thud from 'thud-lib';
function run(): void {
  fred('a');
  new fred.Cls();
  fred.hash('b');
  new Thud();
}
`
	got := nodeCalleesOf(t, "run.ts", src, "run")
	assertNodeCallees(t, got, map[int]string{
		4: "fred-lib.default",
		5: "fred-lib.(Cls).<init>",
		6: "fred-lib.hash",
		7: "thud-lib.(default).<init>",
	})
}
