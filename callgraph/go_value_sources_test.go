// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"cmp"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// goSinkCalls parses src as the one file of the package example.com/acme/app
// and returns its calls of a function named sink, in source order.
func goSinkCalls(t *testing.T, src string) []FunctionCall {
	t.Helper()
	file := filepath.Join(t.TempDir(), "app.go")
	if err := os.WriteFile(file, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := NewGoParser().ParseFile(file, "example.com/acme/app")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	var calls []FunctionCall
	for i := range analysis.Functions {
		for _, call := range analysis.Functions[i].Calls {
			if call.Callee.Name == "sink" {
				calls = append(calls, call)
			}
		}
	}
	slices.SortFunc(calls, func(a, b FunctionCall) int {
		return cmp.Or(cmp.Compare(a.Line, b.Line), cmp.Compare(a.StartCol, b.StartCol))
	})
	return calls
}

// assertGoSinks checks the ArgumentSources of each sink call, rendered as the
// Rust tests render them (renderRustArguments).
func assertGoSinks(t *testing.T, src string, want []string) {
	t.Helper()
	calls := goSinkCalls(t, src)
	if len(calls) != len(want) {
		t.Fatalf("got %d sink calls, want %d", len(calls), len(want))
	}
	for i, call := range calls {
		if got := renderRustArguments(call); got != want[i] {
			t.Errorf("sink call %d (line %d): got\n  %s\nwant\n  %s", i, call.Line, got, want[i])
		}
		if call.ArgumentSources != nil && len(call.ArgumentSources) != len(call.Arguments) {
			t.Errorf("sink call %d: %d sources for %d arguments", i, len(call.ArgumentSources), len(call.Arguments))
		}
	}
}

func TestGoArgumentSourcesLiterals(t *testing.T) {
	assertGoSinks(t, "package app\n\nfunc f() {\n"+
		"\tsink(\"AES\", `raw`, 128, -1, 1.5, true, 'c', 0x10)\n"+
		"\tsink([]byte(\"key\"), (\"DES\"), string(\"s\"), int64(256), nil)\n"+
		"}\n", []string{
		"VALUE=\"AES\" | VALUE=`raw` | VALUE=128 | VALUE=-1 | VALUE=1.5 | VALUE=true | VALUE='c' | VALUE=0x10",
		`VALUE="key" | VALUE="DES" | VALUE="s" | VALUE=256 | -`,
	})
}

func TestGoArgumentSourcesLocals(t *testing.T) {
	assertGoSinks(t, `package app

func f() {
	m := "secret"
	var k = "key"
	var size int = 256
	a, b := "x", 2
	alias := m
	sink(m, k, size, a, b, alias)
	x, err := load()
	sink(x, err)
}
`, []string{
		`VARIABLE m[VALUE="secret"] | VARIABLE k[VALUE="key"] | VARIABLE size[VALUE=256] | VARIABLE a[VALUE="x"] | VARIABLE b[VALUE=2] | VARIABLE alias[VARIABLE m[VALUE="secret"]]`,
		`<nil>`,
	})
}

func TestGoArgumentSourcesLocalLocationAndType(t *testing.T) {
	calls := goSinkCalls(t, "package app\n\nfunc f() {\n\tvar k string = \"key\"\n\tsink(k)\n}\n")
	if len(calls) != 1 || len(calls[0].ArgumentSources) != 1 || len(calls[0].ArgumentSources[0]) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	node := calls[0].ArgumentSources[0][0]
	if node.DeclaredType != "string" || node.Location == nil || node.Location.Line != 4 {
		t.Fatalf("VARIABLE k = %+v, want type string at line 4", node)
	}
}

func TestGoArgumentSourcesReassignedLocals(t *testing.T) {
	assertGoSinks(t, `package app

func f(c bool) {
	mode := "CBC"
	if c {
		mode = "GCM"
	}
	sink(mode)
	var pad string
	if c {
		pad = "PKCS7"
	}
	sink(pad)
	alg := "AES"
	alg = pick()
	sink(alg)
	n := 0
	n++
	sink(n)
	key := "k"
	fill(&key)
	sink(key)
	tag := "t"
	sink(tag)
	tag, err := load()
	sink(tag, err)
}
`, []string{
		`VARIABLE mode{"CBC","GCM"}!`,
		`VARIABLE pad{"PKCS7"}`,
		`VARIABLE alg{"AES"}`,
		`<nil>`,
		`VARIABLE key{"k"}`,
		`VARIABLE tag{"t"}`,
		`<nil>`,
	})
}

func TestGoArgumentSourcesShadowing(t *testing.T) {
	assertGoSinks(t, `package app

const alg = "AES"

func f(c bool) {
	sink(alg)
	if c {
		alg := "DES"
		sink(alg)
	}
	sink(alg)
	mode := "CBC"
	{
		mode := mode + "-x"
		mode = "GCM"
		sink(mode)
	}
	sink(mode)
}
`, []string{
		`VARIABLE alg[VALUE="AES"]`,
		`VARIABLE alg[VALUE="DES"]`,
		`VARIABLE alg[VALUE="AES"]`,
		`VARIABLE mode{"GCM"}`,
		// The write in the nested block names the name the block declared, but
		// like the Rust walk it counts against the outer local as well.
		`VARIABLE mode{"CBC","GCM"}!`,
	})
}

func TestGoArgumentSourcesParameters(t *testing.T) {
	assertGoSinks(t, `package app

type S struct{}

func f(a string, b, c int) {
	sink(c, a)
}

func (s *S) m(_ int, key []byte) {
	sink(s, key)
}

func g(k string, rest ...string) {
	k = "x"
	sink(k, rest)
	h := func(v string) { sink(v) }
	h("y")
}
`, []string{
		`PARAMETER c#2 | PARAMETER a#0`,
		`- | PARAMETER key#1`,
		// A parameter the body writes no longer holds the caller's value; a
		// variadic one holds a slice of the trailing arguments; a literal's
		// parameter is filled by whatever calls the func value.
		`<nil>`,
		`<nil>`,
	})
}

func TestGoArgumentSourcesCallResults(t *testing.T) {
	assertGoSinks(t, `package app

import "example.com/acme/hashes"

func f(key []byte) {
	sink(derive(key, "salt"))
	h := hashes.New()
	sink(h.Sum(nil))
	sink(hashes.Mix(derive(key, "x"), 4))
}
`, []string{
		`CALL_RESULT=derive(key, "salt")@example.com/acme/app.derive[PARAMETER key#0, VALUE="salt"]`,
		`CALL_RESULT=h.Sum(nil)@Sum[VARIABLE h[CALL_RESULT=hashes.New()@example.com/acme/hashes.New]]`,
		`CALL_RESULT=hashes.Mix(derive(key, "x"), 4)@example.com/acme/hashes.Mix[CALL_RESULT=derive(key, "x")@example.com/acme/app.derive[PARAMETER key#0, VALUE="x"], VALUE=4]`,
	})
}

func TestGoArgumentSourcesConsts(t *testing.T) {
	assertGoSinks(t, `package app

const bits = 3072

var mode = "CBC"

func f() {
	const name = "RSA"
	sink(bits, name, mode)
}
`, []string{
		// A package-level var may be written by any function of the package.
		`VARIABLE bits[VALUE=3072] | VARIABLE name[VALUE="RSA"] | -`,
	})
}

func TestGoArgumentSourcesExpressions(t *testing.T) {
	assertGoSinks(t, `package app

type Config struct {
	Name string
	Size int
}

func f(prefix string) {
	m := "b"
	sink(prefix+"-x", Config{Name: "a", Size: 3}, &Config{Name: m}, []string{"a", m}, [][]int{{1}, {2}})
	sink(!ok(), -prefixLen())
}
`, []string{
		`EXPRESSION=prefix+"-x"[PARAMETER prefix#0, VALUE="-x"] | ` +
			`EXPRESSION=Config{Name: "a", Size: 3}[VALUE="a", VALUE=3] | ` +
			`EXPRESSION=Config{Name: m}[VARIABLE m[VALUE="b"]] | ` +
			`EXPRESSION=[]string{"a", m}[VALUE="a", VARIABLE m[VALUE="b"]] | ` +
			`EXPRESSION=[][]int{{1}, {2}}[EXPRESSION={1}[VALUE=1], EXPRESSION={2}[VALUE=2]]`,
		`<nil>`,
	})
}

func TestGoArgumentSourcesDepthClipping(t *testing.T) {
	assertGoSinks(t, `package app

func f() {
	a := "x"
	b := a
	c := b
	d := c
	e := d
	sink(e)
	sink(w(w(w(w(w("deep"))))))
}
`, []string{
		`VARIABLE e[VARIABLE d[VARIABLE c[VARIABLE b[VARIABLE a]]]]`,
		`CALL_RESULT=w(w(w(w(w("deep")))))@example.com/acme/app.w[CALL_RESULT=w(w(w(w("deep"))))@example.com/acme/app.w[CALL_RESULT=w(w(w("deep")))@example.com/acme/app.w[CALL_RESULT=w(w("deep"))@example.com/acme/app.w[CALL_RESULT=w("deep")@example.com/acme/app.w]]]]`,
	})
}
