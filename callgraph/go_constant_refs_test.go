// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

const goConstantRefsSource = `package p

import (
	"example.com/conf"
	alg "example.com/algs"
)

var Default = conf.Level2

var Suites = []int{conf.Level0}

type T struct{ M map[string]int }

func use(v int, conf2 string) int {
	set(conf.Level1)
	if v == conf.Level3 {
		return alg.Fast
	}
	switch v {
	case conf.Level4:
	}
	x := conf.Level5
	x = conf.Level6
	_ = []int{conf.Level7}
	_ = map[int]int{conf.Level8: 1}
	_ = T{M: nil}
	_ = struct{ L int }{L: conf.Level9}
	conf.Writable = 1
	_ = conf.Make()
	_ = conf.Holder.Value
	return x
}

func shadowed(conf int) int {
	return conf.Level1
}

func set(int) {}
`

// TestGoConstantRefs: a value read through an import is recorded once, with
// its import path text, the function that holds it (a package-level data
// var's initializer: the file's <varinit>; a var that may hold a function:
// its own declaration) and its position kind; a call, a write or a selector
// on a shadowing local is not a reference.
func TestGoConstantRefs(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.go")
	if err := os.WriteFile(path, []byte(goConstantRefsSource), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := NewGoParser().ParseFile(path, "example.com/p")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	type ref struct{ fn, context, operand string }
	got := map[string]ref{}
	for _, fn := range analysis.Functions {
		for _, r := range fn.ConstantRefs {
			if _, dup := got[r.Text]; dup {
				t.Errorf("%s recorded twice", r.Text)
			}
			op := ""
			if r.Operand != nil {
				op = r.Operand.Text
			}
			got[r.Text] = ref{fn.ID.Name, r.Context, op}
		}
	}
	want := map[string]ref{
		"example.com/conf.Level2": {"Default", ConstantRefInit, ""},
		"example.com/conf.Level0": {"<varinit:p>", ConstantRefArray, ""},
		"example.com/conf.Level1": {"use", ConstantRefArg, ""},
		"example.com/conf.Level3": {"use", ConstantRefCompare, "v"},
		"example.com/algs.Fast":   {"use", ConstantRefReturn, ""},
		"example.com/conf.Level4": {"use", ConstantRefCase, "v"},
		"example.com/conf.Level5": {"use", ConstantRefInit, ""},
		"example.com/conf.Level6": {"use", ConstantRefAssign, ""},
		"example.com/conf.Level7": {"use", ConstantRefArray, ""},
		"example.com/conf.Level8": {"use", ConstantRefDict, ""},
		"example.com/conf.Level9": {"use", ConstantRefInit, ""},
		"example.com/conf.Holder": {"use", ConstantRefOther, ""},
	}
	for text, w := range want {
		if g, ok := got[text]; !ok {
			t.Errorf("no reference %s (got %v)", text, got)
		} else if g != w {
			t.Errorf("%s = %+v, want %+v", text, g, w)
		}
	}
	for _, text := range []string{"example.com/conf.Writable", "example.com/conf.Make"} {
		if _, ok := got[text]; ok {
			t.Errorf("%s is a write or a call, not a reference", text)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d references, want %d: %v", len(got), len(want), got)
	}
}
