// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"reflect"
	"testing"
)

// withoutTypeRefs drops the references in the position kind type, which
// TestRustTypeRefs covers.
func withoutTypeRefs(refs []ConstantRef) []ConstantRef {
	var out []ConstantRef
	for _, r := range refs {
		if r.Context != ConstantRefType {
			out = append(out, r)
		}
	}
	return out
}

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
	fn.ConstantRefs = withoutTypeRefs(fn.ConstantRefs)
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

// TestRustNameRefs: a one-segment path a body reads as a value is a reference
// when its name starts with an upper-case letter (a constant, a unit struct or
// a variant brought in by a use: `&X25519`, `SysRng`); a lower-case name (a
// local), a callee, a pattern and a macro's name are not; a type is one only
// in the position kind type (TestRustTypeRefs). A struct
// literal's path is a reference too, of one segment or more.
func TestRustNameRefs(t *testing.T) {
	src := `use acme_kdf::{Key, X25519};
fn run(x: u32, Mode: u8) -> Key {
    let alg = X25519;
    let k = acme_kdf::derive(&X25519, x);
    let rng = SysRng;
    let y = x;
    let none: Option<u8> = None;
    let Z = Key::new(y);
    let lit = Key { bits: 1 };
    let full = acme_kdf::Key { bits: X25519 };
    let t: Key = SysRng.key();
    match y {
        LIMIT => {}
        _ => {}
    }
    if y == MAX { return Fallback; }
    debug_assert!(y != MAX2);
    match LIMIT2 {
        _ => {}
    }
    if FLAG {}
    while FLAG2 {}
    let c = || Default2;
    if let Some(v) = CACHE {}
    loop { break STOP; }
    Key { bits: 2 }
}
`
	fn := parseRustFunction(t, src, "run")
	fn.ConstantRefs = withoutTypeRefs(fn.ConstantRefs)
	type ref struct{ text, context string }
	var got []ref
	for _, r := range fn.ConstantRefs {
		got = append(got, ref{r.Text, r.Context})
	}
	want := []ref{
		{"X25519", ConstantRefInit},
		{"X25519", ConstantRefOther},
		{"SysRng", ConstantRefInit},
		{"Key", ConstantRefStruct},
		{"acme_kdf::Key", ConstantRefStruct},
		{"X25519", ConstantRefOther},
		{"SysRng", ConstantRefOther},
		{"MAX", ConstantRefCompare},
		{"Fallback", ConstantRefReturn},
		{"MAX2", ConstantRefCompare},
		{"LIMIT2", ConstantRefOther},
		{"FLAG", ConstantRefOther},
		{"FLAG2", ConstantRefOther},
		{"Default2", ConstantRefOther},
		{"CACHE", ConstantRefOther},
		{"STOP", ConstantRefOther},
		{"Key", ConstantRefStruct},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("refs:\n got %v\nwant %v", got, want)
	}
	if r := fn.ConstantRefs[0]; r.Line != 3 || r.StartCol != 15 || r.EndCol != 21 {
		t.Errorf("first ref span = %d:%d-%d, want 3:15-21", r.Line, r.StartCol, r.EndCol)
	}
	if r := fn.ConstantRefs[3]; r.Line != 9 || r.StartCol != 15 || r.EndCol != 18 {
		t.Errorf("struct ref span = %d:%d-%d, want 8:15-18", r.Line, r.StartCol, r.EndCol)
	}
}

// TestRustTypeRefs: a path written as a whole type is a reference in the
// position kind type, where OpenGrep matches a path pattern: a field, a
// parameter, a return type, a let annotation, a cast, a generic argument, a
// `dyn` or `impl` trait, an alias, an impl's self type, a const's type. A fn's
// signature holds its own; one outside any fn (a field, an alias, an impl
// header, a trait fn's signature) is the file's <varinit>. A generic type's
// head, a trait bound (generic arguments included), an impl's trait, a
// qualified path, a declared name, a primitive, the prelude's types and a
// lower-case name are not.
func TestRustTypeRefs(t *testing.T) {
	src := `use acme::Key;
pub struct Holder { rng: SysRng, keys: Vec<acme::Key>, n: u8, s: String }
pub struct Pair(Key, Option<acme::Nonce>);
enum Slot { A(SysRng), B { k: acme::Key } }
type Alias = acme::Cipher;
const C: acme::Level = acme::LOW;
impl Holder {}
impl Tr for acme::Key {}
impl From<SysRng> for Holder {}
trait Sealed { fn seal(&self) -> acme::Sealed; }
fn run<R: Into<SysRng>, T = acme::Dflt>(r: R, k: &acme::Key, h: impl acme::Hash, d: Box<dyn acme::Dyn>) -> Result<Key, acme::Error>
where R: Bound<acme::Other> {
    let x: acme::Key = make();
    let y = make::<SysRng>();
    let z = x as Key;
    let f = |a: Rng2| -> Rng3 { a };
    let p: <X as acme::Tr>::Out = q;
    let g: Gen<u8> = q;
    let w: wrapper = q;
}
`
	type ref struct {
		text      string
		line, col int
	}
	typeRefs := func(fn FunctionDecl) []ref {
		var got []ref
		for _, r := range fn.ConstantRefs {
			if r.Context == ConstantRefType {
				got = append(got, ref{r.Text, r.Line, r.StartCol})
			}
		}
		return got
	}
	run := parseRustFunction(t, src, "run")
	wantRun := []ref{
		{"acme::Dflt", 11, 29}, {"R", 11, 44}, {"acme::Key", 11, 51}, {"acme::Hash", 11, 70},
		{"acme::Dyn", 11, 93}, {"Key", 11, 115}, {"acme::Error", 11, 120},
		{"acme::Key", 13, 12}, {"SysRng", 14, 20}, {"Key", 15, 18}, {"Rng2", 16, 17}, {"Rng3", 16, 26},
	}
	if got := typeRefs(run); !reflect.DeepEqual(got, wantRun) {
		t.Errorf("run's type refs:\n got %v\nwant %v", got, wantRun)
	}
	varinit := parseRustFunction(t, src, "<varinit:main>")
	wantVarinit := []ref{
		{"SysRng", 2, 26}, {"acme::Key", 2, 44}, {"Key", 3, 17}, {"acme::Nonce", 3, 29},
		{"SysRng", 4, 15}, {"acme::Key", 4, 31}, {"acme::Cipher", 5, 14}, {"acme::Level", 6, 10},
		{"Holder", 7, 6}, {"acme::Key", 8, 13}, {"Holder", 9, 23}, {"acme::Sealed", 10, 34},
	}
	if got := typeRefs(varinit); !reflect.DeepEqual(got, wantVarinit) {
		t.Errorf("varinit's type refs:\n got %v\nwant %v", got, wantVarinit)
	}
	if r := run.ConstantRefs[0]; r.EndCol != 39 || r.Context != ConstantRefType {
		t.Errorf("first ref = %+v, want acme::Dflt ending at column 39", r)
	}
}

// TestRustTypeRefScopes: a static's type and its initializer's turbofish are
// listed once each in <varinit>, an extern fn's signature too; a fn nested in
// a body gives its signature to the enclosing fn; a test-only module in a scan
// without tests gives none.
func TestRustTypeRefScopes(t *testing.T) {
	src := `static K: Lazy<acme::Kdf> = Lazy::<acme::Kdf>::new(make);
extern "C" { fn ext(a: SysRng) -> acme::Out; }
#[cfg(test)]
mod tests { struct T { r: TestOnly } }
fn outer() { fn inner(a: Inner1) -> Inner2 { a } }
`
	texts := func(fn FunctionDecl) []string {
		var got []string
		for _, r := range fn.ConstantRefs {
			if r.Context == ConstantRefType {
				got = append(got, r.Text)
			}
		}
		return got
	}
	if got, want := texts(parseRustFunction(t, src, "<varinit:main>")), []string{"acme::Kdf", "acme::Kdf", "SysRng", "acme::Out"}; !reflect.DeepEqual(got, want) {
		t.Errorf("varinit's type refs = %v, want %v", got, want)
	}
	if got, want := texts(parseRustFunction(t, src, "outer")), []string{"Inner1", "Inner2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("outer's type refs = %v, want %v", got, want)
	}
}
