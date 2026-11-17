// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"
	"reflect"
	"testing"
)

// parseRustBinaryExprs parses one file and returns its binary expressions.
func parseRustBinaryExprs(t *testing.T, src string, opts ...ParserOption) []RustBinaryExpr {
	t.Helper()
	dir := t.TempDir()
	writeRustTestFile(t, dir, src)
	analyses, err := NewRustParser(opts...).ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("got %d analyses, want 1", len(analyses))
	}
	return analyses[0].RustBinaryExprs
}

// TestRustBinaryExprs: every binary expression of a function body, nested
// ones and those in an expression macro's arguments included, in source
// order, with its operator, its operands as written and their spans, keyed by
// the innermost function the graph lists that holds it (a fn nested in a body
// has no declaration of its own: its calls are the enclosing function's, and
// so are its expressions); one outside a body (a const item, a parameter's
// array length) is none.
func TestRustBinaryExprs(t *testing.T) {
	src := `const N: usize = 2 * 16;
fn mul(s: Scalar, base: [u8; N + 1]) -> Point {
    let p = s * base + acme::G;
    &s * &p
}
impl Key {
    fn check(&self, a: u8) {
        assert_eq!(a << 2, self.x);
        fn inner(x: u8) -> bool { x == 0 }
    }
}
`
	got := parseRustBinaryExprs(t, src)
	want := []RustBinaryExpr{
		{Op: "+", Left: "s * base", Right: "acme::G", Line: 3, StartCol: 13, EndCol: 31, LeftEndCol: 21, RightStartCol: 24, Function: "app.mul"},
		{Op: "*", Left: "s", Right: "base", Line: 3, StartCol: 13, EndCol: 21, LeftEndCol: 14, RightStartCol: 17, Function: "app.mul"},
		{Op: "*", Left: "&s", Right: "&p", Line: 4, StartCol: 5, EndCol: 12, LeftEndCol: 7, RightStartCol: 10, Function: "app.mul"},
		{Op: "<<", Left: "a", Right: "2", Line: 8, StartCol: 20, EndCol: 26, LeftEndCol: 21, RightStartCol: 25, Function: "app.(Key).check"},
		{Op: "==", Left: "x", Right: "0", Line: 9, StartCol: 35, EndCol: 41, LeftEndCol: 36, RightStartCol: 40, Function: "app.(Key).check"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("binary expressions:\n got %+v\nwant %+v", got, want)
	}
}

// TestRustBinaryExprSpansLines: an expression over several lines has its end
// line, and each operand the line its inner end stands on when that is not
// the first.
func TestRustBinaryExprSpansLines(t *testing.T) {
	src := "fn f(a: u8, b: u8) -> u8 {\n    (a\n      + 1)\n        * b\n}\n"
	got := parseRustBinaryExprs(t, src)
	want := []RustBinaryExpr{
		{Op: "*", Left: "(a\n      + 1)", Right: "b", Line: 2, StartCol: 5, EndCol: 12, EndLine: 4, LeftEndCol: 11, LeftEndLine: 3, RightStartCol: 11, RightLine: 4, Function: "app.f"},
		{Op: "+", Left: "a", Right: "1", Line: 2, StartCol: 6, EndCol: 10, EndLine: 3, LeftEndCol: 7, RightStartCol: 9, RightLine: 3, Function: "app.f"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("binary expressions:\n got %+v\nwant %+v", got, want)
	}
}

// TestRustBinaryExprsTestModule: a test-only module's expressions are left
// out unless the scan includes tests, as its functions are.
func TestRustBinaryExprsTestModule(t *testing.T) {
	src := "#[cfg(test)]\nmod tests {\n    fn t(a: u8) -> u8 { a + 1 }\n}\n"
	if got := parseRustBinaryExprs(t, src); len(got) != 0 {
		t.Errorf("without tests = %+v, want none", got)
	}
	got := parseRustBinaryExprs(t, src, WithIncludeTests(true))
	if len(got) != 1 || got[0].Op != "+" || got[0].Function == "" {
		t.Errorf("with tests = %+v, want a + 1 in t", got)
	}
}

// TestRustBinaryExprsInGraph: the builder files each Rust file's binary
// expressions under its path.
func TestRustBinaryExprsInGraph(t *testing.T) {
	dir := t.TempDir()
	writeRustFile(t, dir, "lib.rs", "pub fn derive(s: u8, b: u8) -> u8 { s * b }\n")
	graph, err := NewBuilderForEcosystem("rust", NewRustParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	file := filepath.Join(dir, "lib.rs")
	if got := graph.RustBinaryExprs[file]; len(got) != 1 || got[0].Op != "*" || got[0].Function != "app.derive" {
		t.Errorf("RustBinaryExprs[%s] = %+v, want s * b in app.derive", file, got)
	}
}
