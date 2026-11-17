// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"reflect"
	"testing"
)

// parseRustFunction parses one file and returns the declaration named name.
func parseRustFunction(t *testing.T, src, name string) FunctionDecl {
	t.Helper()
	dir := t.TempDir()
	writeRustTestFile(t, dir, src)
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			if fn.ID.Name == name {
				return fn
			}
		}
	}
	t.Fatalf("no function %s", name)
	return FunctionDecl{}
}

// TestRustConstantRefs: every path of two or more segments a body reads
// outside a callee is a reference, as written without whitespace, with its
// position kind; a callee (turbofish included), a use and a path's own prefix
// are not; a path inside an expression macro is read as code.
func TestRustConstantRefs(t *testing.T) {
	src := `use acme_kdf::Mode;
fn run(x: u32, m: Mode) -> u32 {
    use acme_kdf::other::Thing;
    let a = acme_kdf::ALG_ONE;
    let b = Kdf::<Sha256>::new(acme_kdf::Salt::DEFAULT);
    if x == acme_kdf::LIMIT { return acme_kdf::FALLBACK; }
    let arr = [acme_kdf::A, Mode::B];
    match m {
        Mode::Cbc | acme_kdf::Mode::Ctr => {}
        _ => {}
    }
    let f = acme_kdf::derive;
    assert_eq!(x, acme_kdf::EXPECTED);
    let q = <Kdf as acme_kdf::Tagged>::TAG;
    acme_kdf::derive(x);
    acme_kdf::derive::<u8>(x);
    acme_kdf::MAX
}
`
	fn := parseRustFunction(t, src, "run")
	type ref struct{ text, context string }
	var got []ref
	for _, r := range fn.ConstantRefs {
		got = append(got, ref{r.Text, r.Context})
	}
	want := []ref{
		{"acme_kdf::ALG_ONE", ConstantRefInit},
		{"acme_kdf::Salt::DEFAULT", ConstantRefArg},
		{"acme_kdf::LIMIT", ConstantRefCompare},
		{"acme_kdf::FALLBACK", ConstantRefReturn},
		{"acme_kdf::A", ConstantRefArray},
		{"Mode::B", ConstantRefArray},
		{"Mode::Cbc", ConstantRefCase},
		{"acme_kdf::Mode::Ctr", ConstantRefCase},
		{"acme_kdf::derive", ConstantRefInit},
		{"acme_kdf::EXPECTED", ConstantRefOther},
		{"<Kdf as acme_kdf::Tagged>::TAG", ConstantRefInit},
		{"acme_kdf::MAX", ConstantRefOther},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("refs:\n got %v\nwant %v", got, want)
	}
	if r := fn.ConstantRefs[0]; r.Line != 4 || r.StartCol != 13 || r.EndCol != 30 || r.EndLine != 0 {
		t.Errorf("first ref span = %d:%d-%d (end line %d), want 4:13-30", r.Line, r.StartCol, r.EndCol, r.EndLine)
	}
}

// TestRustLetDeclarations: one declaration per name a let binds, with the
// whole statement's span, the type as written and the initializer's kind,
// read through `?` and parentheses.
func TestRustLetDeclarations(t *testing.T) {
	src := `fn run() -> Result<(), acme_kdf::Error> {
    let mut key: [u8; 32] = [0; 32];
    let kdf = acme_kdf::Kdf::new(&key)?;
    let (a, mut b) = (1, 2);
    let tag = "v1";
    let n = 4 as u64;
    let path = acme_kdf::DEFAULT;
    let pending;
    let Some(x) = maybe() else { return Ok(()) };
    Ok(())
}
`
	fn := parseRustFunction(t, src, "run")
	want := []VarDecl{
		{Type: "[u8;32]", Name: "key", Init: VarInitOther, Line: 2, StartCol: 5, EndCol: 37},
		{Name: "kdf", Init: VarInitCall, Line: 3, StartCol: 5, EndCol: 41},
		{Name: "a", Init: VarInitOther, Line: 4, StartCol: 5, EndCol: 29},
		{Name: "b", Init: VarInitOther, Line: 4, StartCol: 5, EndCol: 29},
		{Name: "tag", Init: VarInitLiteral, Line: 5, StartCol: 5, EndCol: 20},
		{Name: "n", Init: VarInitCast, Line: 6, StartCol: 5, EndCol: 22},
		{Name: "path", Init: VarInitOther, Line: 7, StartCol: 5, EndCol: 34},
		{Name: "pending", Line: 8, StartCol: 5, EndCol: 17},
	}
	if !reflect.DeepEqual(fn.Declarations, want) {
		t.Errorf("declarations:\n got %+v\nwant %+v", fn.Declarations, want)
	}
}
