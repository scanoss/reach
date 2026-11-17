// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"cmp"
	"fmt"
	"slices"
	"strings"
	"testing"
)

// rustSinkCalls parses src as one file of the crate "app" and returns its
// calls of a function named sink, in source order.
func rustSinkCalls(t *testing.T, src string) []FunctionCall {
	t.Helper()
	dir := t.TempDir()
	writeRustTestFile(t, dir, src)
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	var calls []FunctionCall
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			for _, call := range analysis.Functions[i].Calls {
				if call.Callee.Name == "sink" {
					calls = append(calls, call)
				}
			}
		}
	}
	slices.SortFunc(calls, func(a, b FunctionCall) int {
		return cmp.Or(cmp.Compare(a.Line, b.Line), cmp.Compare(a.StartCol, b.StartCol))
	})
	return calls
}

// renderRustSources writes source nodes compactly: TYPE name=value#index,
// may values in braces (! when exhaustive), a call target after @, and
// children in brackets.
func renderRustSources(nodes []SourceNode) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		var b strings.Builder
		b.WriteString(n.Type)
		if n.Name != "" {
			b.WriteString(" " + n.Name)
		}
		if n.Value != "" {
			b.WriteString("=" + n.Value)
		}
		if n.Type == sourceNodeParameter {
			fmt.Fprintf(&b, "#%d", n.ParameterIndex)
		}
		if n.CallTarget != nil {
			b.WriteString("@" + n.CallTarget.String())
		}
		if len(n.MayValues) > 0 {
			b.WriteString("{" + strings.Join(n.MayValues, ",") + "}")
			if n.MayValuesExhaustive {
				b.WriteString("!")
			}
		}
		if len(n.SourceNodes) > 0 {
			b.WriteString("[" + renderRustSources(n.SourceNodes) + "]")
		}
		parts = append(parts, b.String())
	}
	return strings.Join(parts, ", ")
}

// renderRustArguments renders one call's ArgumentSources, argument by
// argument, "-" for an argument with none.
func renderRustArguments(call FunctionCall) string {
	if call.ArgumentSources == nil {
		return "<nil>"
	}
	parts := make([]string, len(call.ArgumentSources))
	for i, sources := range call.ArgumentSources {
		parts[i] = renderRustSources(sources)
		if parts[i] == "" {
			parts[i] = "-"
		}
	}
	return strings.Join(parts, " | ")
}

func assertRustSinks(t *testing.T, src string, want []string) {
	t.Helper()
	calls := rustSinkCalls(t, src)
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

func TestRustArgumentSourcesLiterals(t *testing.T) {
	assertRustSinks(t, `
use acme_cipher::sink;
fn f() {
    sink("AES", b"key", r"raw", 128, -1, 1.5, true, 'c');
    sink(&"AES", ("DES"), 256 as usize);
}
`, []string{
		`VALUE="AES" | VALUE=b"key" | VALUE=r"raw" | VALUE=128 | VALUE=-1 | VALUE=1.5 | VALUE=true | VALUE='c'`,
		`VALUE="AES" | VALUE="DES" | VALUE=256`,
	})
}

func TestRustArgumentSourcesConstItems(t *testing.T) {
	assertRustSinks(t, `
use acme_cipher::sink;
mod consts {
    pub const MODE: &str = "CBC";
}
use consts::MODE;
const ALG: &str = "AES";
const SAME: &str = ALG;
static BITS: u32 = 256;
static mut COUNTER: u32 = 0;
#[cfg(feature = "a")]
const PICK: &str = "A";
#[cfg(not(feature = "a"))]
const PICK: &str = "B";
struct Kdf;
impl Kdf {
    const NAME: &str = "PBKDF2";
    fn run(&self) {
        sink(Self::NAME, Kdf::NAME);
    }
}
fn f() {
    sink(ALG, SAME, BITS, MODE, consts::MODE, crate::ALG);
    unsafe { sink(COUNTER, PICK) };
    const LOCAL: &str = "L";
    sink(LOCAL);
}
`, []string{
		`FIELD Self::NAME[VALUE="PBKDF2"] | FIELD Kdf::NAME[VALUE="PBKDF2"]`,
		`FIELD ALG[VALUE="AES"] | FIELD SAME[VALUE="AES"] | FIELD BITS[VALUE=256] | FIELD MODE[VALUE="CBC"] | FIELD consts::MODE[VALUE="CBC"] | FIELD crate::ALG[VALUE="AES"]`,
		`<nil>`,
		`FIELD LOCAL[VALUE="L"]`,
	})
}

func TestRustArgumentSourcesLetBindings(t *testing.T) {
	assertRustSinks(t, `
use acme_cipher::sink;
const ALG: &str = "AES";
fn f() {
    let a = "AES";
    let b = a;
    sink(b);
    let a = "DES";
    sink(a);
    {
        let a = "RC4";
        sink(a);
    }
    sink(a);
    let ALG_LOCAL = ALG;
    sink(ALG_LOCAL);
    let k: &str = "typed";
    sink(k);
}
`, []string{
		`VARIABLE b[VARIABLE a[VALUE="AES"]]`,
		`VARIABLE a[VALUE="DES"]`,
		`VARIABLE a[VALUE="RC4"]`,
		`VARIABLE a[VALUE="DES"]`,
		`VARIABLE ALG_LOCAL[FIELD ALG[VALUE="AES"]]`,
		`VARIABLE k[VALUE="typed"]`,
	})
}

func TestRustArgumentSourcesShadowing(t *testing.T) {
	assertRustSinks(t, `
use acme_cipher::sink;
const KEY: &str = "outer";
fn f(alg: &str, opt: Option<&str>) {
    let alg = alg.trim();
    sink(alg);
    if let Some(KEYS) = opt {
        sink(KEYS);
    }
    let run = |KEY| sink(KEY);
    let (x, y) = ("a", "b");
    sink(x);
    match opt {
        Some(v) => sink(v),
        None => {}
    }
    for item in ["a"] {
        sink(item);
    }
    fn inner(alg: &str) {
        sink(alg);
    }
}
`, []string{
		`VARIABLE alg[CALL_RESULT=alg.trim()@app.trim[PARAMETER alg#0]]`,
		`<nil>`,
		`<nil>`,
		`<nil>`,
		`<nil>`,
		`<nil>`,
		`<nil>`,
	})
}

func TestRustArgumentSourcesParameters(t *testing.T) {
	assertRustSinks(t, `
use acme_cipher::sink;
struct Engine;
impl Engine {
    fn run(&self, alg: &str, key: &[u8]) {
        sink(key, alg);
    }
    fn assoc(alg: &str) {
        sink(alg);
    }
}
fn f(mut count: u32, mut size: u32, (a, b): (u8, u8), name: &str) {
    count = 2;
    sink(count, size, a, name);
    let run = move || sink(name);
}
`, []string{
		`PARAMETER key#1 | PARAMETER alg#0`,
		`PARAMETER alg#0`,
		`- | PARAMETER size#1 | - | PARAMETER name#3`,
		`PARAMETER name#3`,
	})
}

func TestRustArgumentSourcesReassignedLet(t *testing.T) {
	assertRustSinks(t, `
use acme_cipher::sink;
fn f(flag: bool, other: &str) {
    let mut alg = "AES";
    if flag {
        alg = "DES";
    }
    sink(alg);
    let mut mode = "CBC";
    if flag {
        mode = other;
    }
    sink(mode);
    let mut fixed = "GCM";
    sink(fixed);
    let late;
    late = "CTR";
    sink(late);
    let mut n = 1;
    n += 1;
    sink(n);
}
`, []string{
		`VARIABLE alg{"AES","DES"}!`,
		`VARIABLE mode{"CBC"}`,
		`VARIABLE fixed[VALUE="GCM"]`,
		`VARIABLE late{"CTR"}!`,
		`<nil>`,
	})
}

func TestRustArgumentSourcesCallResults(t *testing.T) {
	assertRustSinks(t, `
use acme_cipher::{sink, Cipher};
const ALG: &str = "AES";
fn helper(name: &str) -> String { name.to_string() }
fn f(key: &[u8]) {
    let c = Cipher::new(ALG, key);
    sink(c);
    sink(helper("DES"), String::from("RC4"), "x".to_string());
    let name = format!("{}-GCM", ALG);
    sink(name, 1 + 2);
    println!("{}", sink(key));
}
`, []string{
		`VARIABLE c[CALL_RESULT=Cipher::new(ALG, key)@acme_cipher.(Cipher).new[FIELD ALG[VALUE="AES"], PARAMETER key#0]]`,
		`CALL_RESULT=helper("DES")@app.helper[VALUE="DES"] | CALL_RESULT=String::from("RC4")@std.(String).from[VALUE="RC4"] | CALL_RESULT="x".to_string()@app.to_string[VALUE="x"]`,
		`VARIABLE name[EXPRESSION=format!("{}-GCM", ALG)[VALUE="{}-GCM", FIELD ALG[VALUE="AES"]]] | EXPRESSION=1 + 2[VALUE=1, VALUE=2]`,
		`PARAMETER key#0`,
	})
}

// A call in fully qualified syntax passes its receiver as the first argument,
// which its Arguments leave out; the sources follow Arguments.
func TestRustArgumentSourcesFullyQualifiedCall(t *testing.T) {
	calls := rustSinkCalls(t, `
use acme_cipher::Sinker;
fn f(s: Sinker) {
    Sinker::sink(&s, "AES");
}
`)
	if len(calls) != 1 {
		t.Fatalf("got %d sink calls, want 1", len(calls))
	}
	if got, want := renderRustArguments(calls[0]), `VALUE="AES"`; got != want || len(calls[0].Arguments) != 1 {
		t.Errorf("got %s for arguments %v, want %s", got, calls[0].Arguments, want)
	}
}

// The trace stops at rustValueMaxDepth: a long let chain keeps its first
// links and drops the literal beyond them.
func TestRustArgumentSourcesDepthBound(t *testing.T) {
	assertRustSinks(t, `
use acme_cipher::sink;
fn f() {
    let a = "AES";
    let b = a;
    let c = b;
    let d = c;
    let e = d;
    let g = e;
    sink(g);
}
`, []string{
		`VARIABLE g[VARIABLE e[VARIABLE d[VARIABLE c[VARIABLE b]]]]`,
	})
}
