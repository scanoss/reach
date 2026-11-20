// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// Babel compiles a conditional require to a name declared first and assigned
// later. The name binds to the module as `const AES = require(..)` does, so the
// call keys the library export, as the declared form does.
func TestNodeParser_AssignedRequireBindsTheModule(t *testing.T) {
	t.Parallel()

	src := `"use strict";
let AES;
let ENC;
let Utf8;
AES = require('frob-lib/aes');
if (process.env.TARGET === 'browser') {
  ENC = require('frob-lib/enc-utf8');
} else {
  ENC = require('frob-lib/enc-utf8');
}
Utf8 = require('frob-lib').enc.Utf8;
let Other;
Other = require('one-lib');
Other = require('two-lib');

function run(obj, key, text) {
  const e = AES.encrypt(JSON.stringify(obj), key);
  AES.decrypt(text, key).toString(ENC);
  Utf8.parse(text);
  Other.go();
  return e;
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.js"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewNodeParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	run := nodeFunction(t, analyses[0], "run")
	got := map[int][]string{}
	for i := range run.Calls {
		got[run.Calls[i].Line] = append(got[run.Calls[i].Line], run.Calls[i].Callee.String())
	}
	want := map[int]string{
		17: "frob-lib/aes.encrypt",
		18: "frob-lib/aes.decrypt",
		19: "frob-lib.enc.Utf8.parse",
		// A name assigned two different modules keeps the first one.
		20: "one-lib.go",
	}
	for line, callee := range want {
		if !slices.Contains(got[line], callee) {
			t.Errorf("line %d: callees %q, want one %q", line, got[line], callee)
		}
	}
}

func TestNodeImportsAssignedRequire(t *testing.T) {
	t.Parallel()

	src := `let AES;
AES = require('frob-lib/aes');
let Utf8;
Utf8 = require('frob-lib').enc.Utf8;
function load() { let lazy; lazy = require('lazy-lib'); return lazy; }
`
	got := nodeImportsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeImports(t, got, []NodeImport{
		{Line: 2, Module: "frob-lib/aes", Alias: "AES", Kind: NodeImportRequire},
		{Line: 4, Module: "frob-lib", Name: "enc.Utf8", Alias: "Utf8", Kind: NodeImportRequire},
		{Line: 5, Module: "lazy-lib", Alias: "lazy", Kind: NodeImportRequire, Local: true},
	})
}
