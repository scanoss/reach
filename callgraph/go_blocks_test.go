// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func parseGoFact(t *testing.T, source string) *FileAnalysis {
	t.Helper()
	path := filepath.Join(t.TempDir(), "main.go")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := NewGoParser().ParseFile(path, "example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	return analysis
}

func TestGoParser_Blocks(t *testing.T) {
	const source = `package main

func run(n int) {
	if n > 0 {
		a()
	} else {
		b()
	}
	switch n {
	case 1:
		a()
		b()
	default:
		{
			c()
		}
	}
	for i := 0; i < n; i++ {
		a()
	}
}

func a() {}
func b() {}
func c() {}
`
	analysis := parseGoFact(t, source)
	const fn = "example.com/app.run"
	want := []GoBlock{
		{Function: fn, StartLine: 3, StartCol: 17, EndLine: 21, EndCol: 2},  // body
		{Function: fn, StartLine: 4, StartCol: 11, EndLine: 6, EndCol: 3},   // if
		{Function: fn, StartLine: 6, StartCol: 9, EndLine: 8, EndCol: 3},    // else
		{Function: fn, StartLine: 10, StartCol: 2, EndLine: 12, EndCol: 6},  // case 1
		{Function: fn, StartLine: 13, StartCol: 2, EndLine: 16, EndCol: 4},  // default
		{Function: fn, StartLine: 14, StartCol: 3, EndLine: 16, EndCol: 4},  // bare block
		{Function: fn, StartLine: 18, StartCol: 25, EndLine: 20, EndCol: 3}, // for
		{Function: "example.com/app.a", StartLine: 23, StartCol: 10, EndLine: 23, EndCol: 12},
		{Function: "example.com/app.b", StartLine: 24, StartCol: 10, EndLine: 24, EndCol: 12},
		{Function: "example.com/app.c", StartLine: 25, StartCol: 10, EndLine: 25, EndCol: 12},
	}
	if !reflect.DeepEqual(analysis.GoBlocks, want) {
		t.Errorf("blocks:\n got %+v\nwant %+v", analysis.GoBlocks, want)
	}
}

func TestGoParser_AssignValues(t *testing.T) {
	const source = `package main

import "example.com/acme"

var pkg = acme.New()

func run(t acme.T) error {
	c := acme.New()
	u, err := acme.Open(c)
	u, err = acme.Open(c)
	u = t
	var k = acme.Key()
	var m acme.Mode = acme.CBC
	var x, y = acme.Pair()
	_, err = acme.Open(c)
	c.URL = "x"
	n := 1
	n += 2
	var z int
	_, _, _, _, _ = k, m, x, y, z
	return err
}
`
	analysis := parseGoFact(t, source)
	const fn = "example.com/app.run"
	assign := func(line, start, end int, op, value string, names ...string) GoValue {
		return GoValue{Kind: GoValueAssign, Function: fn, Line: line, StartCol: start, EndCol: end, Names: names, Op: op, Value: value}
	}
	typed := assign(13, 2, 28, "var", "acme.CBC", "m")
	typed.TypeText, typed.Package, typed.Type = "acme.Mode", "example.com/acme", "Mode"
	want := []GoValue{
		assign(8, 2, 17, ":=", "acme.New()", "c"),
		assign(9, 2, 24, ":=", "acme.Open(c)", "u", "err"),
		assign(10, 2, 23, "=", "acme.Open(c)", "u", "err"),
		assign(11, 2, 7, "=", "t", "u"),
		assign(12, 2, 20, "var", "acme.Key()", "k"),
		typed,
		assign(14, 2, 24, "var", "acme.Pair()", "x", "y"),
		assign(15, 2, 23, "=", "acme.Open(c)", "_", "err"),
		assign(17, 2, 8, ":=", "1", "n"),
		assign(20, 2, 31, "=", "", "_", "_", "_", "_", "_"),
	}
	var got []GoValue
	for _, v := range analysis.GoValues {
		switch v.Kind {
		case GoValueAssign:
			got = append(got, v)
		case GoValueStore:
			if v.Line != 16 {
				t.Errorf("unexpected store %+v", v)
			}
		}
	}
	if len(got) != len(want) {
		t.Fatalf("%d assigns, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if !reflect.DeepEqual(got[i], want[i]) {
			t.Errorf("assign %d:\n got %+v\nwant %+v", i, got[i], want[i])
		}
	}
}

func TestGoParser_CompositeReturnSources(t *testing.T) {
	const source = `package main

import "example.com/acme"

func ptr() *acme.Client {
	return &acme.Client{URL: "x"}
}

func val() acme.Options {
	return acme.Options{}
}

func call() *acme.Client {
	return acme.Dial()
}

func wrap() *acme.Client {
	t := acme.Dial()
	return t
}
`
	analysis := parseGoFact(t, source)
	got := map[string][]SourceNode{}
	for _, fn := range analysis.Functions {
		got[fn.ID.Name] = fn.ReturnSources
	}
	file := analysis.FilePath
	at := func(line int) *SourceLocation { return &SourceLocation{FilePath: file, Line: line} }
	want := map[string][]SourceNode{
		"ptr": {{
			Type: sourceNodeExpression, Value: `&acme.Client{URL: "x"}`, Location: at(6),
			SourceNodes: []SourceNode{{Type: sourceNodeValue, Value: `"x"`}},
		}},
		"val":  {{Type: sourceNodeExpression, Value: "acme.Options{}", Location: at(10)}},
		"call": {{Type: sourceNodeCallResult, CallTarget: &FunctionID{Package: "example.com/acme", Name: "Dial"}, Location: at(14)}},
		"wrap": {{Type: sourceNodeVariable, Name: "t", Location: at(19)}},
	}
	for name, sources := range want {
		if !reflect.DeepEqual(got[name], sources) {
			t.Errorf("%s return sources:\n got %+v\nwant %+v", name, got[name], sources)
		}
	}
}
