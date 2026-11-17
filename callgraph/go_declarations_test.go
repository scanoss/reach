// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

const goDeclarationsSource = `package p

import "example.com/keys"

var Shared keys.Params

type local struct{}

func use() {
	var params keys.Params
	var priv, pub *keys.Key = keys.New(), nil
	var list []keys.Key
	var n int
	var l local
	var (
		a keys.Params
		b = keys.Make()
	)
	_, _, _, _, _, _, _ = params, priv, pub, list, n, l, a
	_ = b
}
`

// TestGoDeclarations: a var declaration of an imported type is recorded per
// name with the type's import path and its initializer kind; builtin and
// file-local types and untyped vars are not.
func TestGoDeclarations(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.go")
	if err := os.WriteFile(path, []byte(goDeclarationsSource), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := NewGoParser().ParseFile(path, "example.com/p")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	type decl struct{ fn, typ, init string }
	got := map[string]decl{}
	for _, fn := range analysis.Functions {
		for _, d := range fn.Declarations {
			got[d.Name] = decl{fn.ID.Name, d.Type, d.Init}
		}
	}
	want := map[string]decl{
		"Shared": {"<varinit:p>", "example.com/keys.Params", ""},
		"params": {"use", "example.com/keys.Params", ""},
		"priv":   {"use", "*example.com/keys.Key", VarInitCall},
		"pub":    {"use", "*example.com/keys.Key", VarInitNull},
		"list":   {"use", "[]example.com/keys.Key", ""},
		"a":      {"use", "example.com/keys.Params", ""},
	}
	if len(got) != len(want) {
		t.Errorf("declarations %v, want %v", got, want)
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s = %+v, want %+v", name, got[name], w)
		}
	}
}
