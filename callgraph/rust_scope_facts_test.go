// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"
	"reflect"
	"testing"
)

// parseRustScopeFacts parses one file and returns its imports and items.
func parseRustScopeFacts(t *testing.T, src string, opts ...ParserOption) ([]RustImport, []RustItem) {
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
	return analyses[0].RustImports, analyses[0].RustItems
}

// TestRustImportsAsWritten: every leaf of a use tree is one binding, with the
// path as written (no resolution of crate/self/super, the leading `::`
// dropped), the alias, the declaration's span and its use tree text; an
// `extern crate` binds the crate like Python's `import a as z`; a use inside a
// function is local.
func TestRustImportsAsWritten(t *testing.T) {
	src := `extern crate acme_kdf as kdf;
pub use acme_kdf::{Kdf, other::{Thing as T, self}, *};
use ::acme_x::Y;
use {acme_a::B, acme_c};
use crate::inner::Helper;
use acme_mac::{self as mac};

fn run() {
    use acme_kdf::Hkdf;
}
`
	imports, _ := parseRustScopeFacts(t, src)
	want := []RustImport{
		{Module: "acme_kdf", Alias: "kdf", Text: "acme_kdf as kdf", Line: 1, StartCol: 1, EndCol: 30},
		{Module: "acme_kdf", Name: "Kdf", Text: "acme_kdf::{Kdf, other::{Thing as T, self}, *}", Line: 2, StartCol: 1, EndCol: 55},
		{Module: "acme_kdf::other", Name: "Thing", Alias: "T", Text: "acme_kdf::{Kdf, other::{Thing as T, self}, *}", Line: 2, StartCol: 1, EndCol: 55},
		{Module: "acme_kdf", Name: "other", Text: "acme_kdf::{Kdf, other::{Thing as T, self}, *}", Line: 2, StartCol: 1, EndCol: 55},
		{Module: "acme_kdf", Name: "*", Text: "acme_kdf::{Kdf, other::{Thing as T, self}, *}", Line: 2, StartCol: 1, EndCol: 55},
		{Module: "acme_x", Name: "Y", Text: "::acme_x::Y", Line: 3, StartCol: 1, EndCol: 17},
		{Module: "acme_a", Name: "B", Text: "{acme_a::B, acme_c}", Line: 4, StartCol: 1, EndCol: 25},
		{Name: "acme_c", Text: "{acme_a::B, acme_c}", Line: 4, StartCol: 1, EndCol: 25},
		{Module: "crate::inner", Name: "Helper", Text: "crate::inner::Helper", Line: 5, StartCol: 1, EndCol: 26},
		{Name: "acme_mac", Alias: "mac", Text: "acme_mac::{self as mac}", Line: 6, StartCol: 1, EndCol: 29},
		{Module: "acme_kdf", Name: "Hkdf", Text: "acme_kdf::Hkdf", Line: 9, StartCol: 5, EndCol: 24, Local: true},
	}
	if !reflect.DeepEqual(imports, want) {
		t.Errorf("imports:\n got %+v\nwant %+v", imports, want)
	}
}

// TestRustImportSpansLines: a use written over several lines has its end line.
func TestRustImportSpansLines(t *testing.T) {
	imports, _ := parseRustScopeFacts(t, "use acme_kdf::{\n    Kdf,\n};\n")
	want := []RustImport{{Module: "acme_kdf", Name: "Kdf", Text: "acme_kdf::{\n    Kdf,\n}", Line: 1, StartCol: 1, EndCol: 3, EndLine: 3}}
	if !reflect.DeepEqual(imports, want) {
		t.Errorf("imports:\n got %+v\nwant %+v", imports, want)
	}
}

// TestRustItems: the items of a file at any depth, in source order, with
// their spans; `mod m;` and a trait's bodiless method are no items; a
// test-only module is left out unless the scan includes tests, as its
// functions are.
func TestRustItems(t *testing.T) {
	src := `extern crate acme_core;
mod outer;
pub mod inner {
    pub const K: u32 = 1;
}
static S: u8 = 2;
struct Key;
trait Signer { fn sign(&self); }
impl<H> Signer for acme_kdf::Kdf<H> {
    fn sign(&self) {
        const LOCAL: u8 = 3;
    }
}
#[cfg(test)]
mod tests {
    fn helper() {}
}
`
	_, items := parseRustScopeFacts(t, src)
	want := []RustItem{
		{Kind: RustItemExternCrate, Name: "acme_core", Line: 1, StartCol: 1, EndCol: 24},
		{Kind: RustItemMod, Name: "inner", Line: 3, StartCol: 1, EndCol: 2, EndLine: 5},
		{Kind: RustItemConst, Name: "K", Line: 4, StartCol: 5, EndCol: 26},
		{Kind: RustItemStatic, Name: "S", Line: 6, StartCol: 1, EndCol: 18},
		{Kind: RustItemStruct, Name: "Key", Line: 7, StartCol: 1, EndCol: 12},
		{Kind: RustItemTrait, Name: "Signer", Line: 8, StartCol: 1, EndCol: 33},
		{Kind: RustItemImpl, Name: "acme_kdf::Kdf<H>", Line: 9, StartCol: 1, EndCol: 2, EndLine: 13},
		{Kind: RustItemFn, Name: "sign", Line: 10, StartCol: 5, EndCol: 6, EndLine: 12, Params: []RustParam{{Pattern: "&self", Self: true, Line: 10, StartCol: 13, EndCol: 18}}},
		{Kind: RustItemConst, Name: "LOCAL", Line: 11, StartCol: 9, EndCol: 29},
	}
	if !reflect.DeepEqual(items, want) {
		t.Errorf("items:\n got %+v\nwant %+v", items, want)
	}

	_, items = parseRustScopeFacts(t, src, WithIncludeTests(true))
	tail := items[len(items)-2:]
	wantTail := []RustItem{
		{Kind: RustItemMod, Name: "tests", Line: 15, StartCol: 1, EndCol: 2, EndLine: 17},
		{Kind: RustItemFn, Name: "helper", Line: 16, StartCol: 5, EndCol: 19},
	}
	if !reflect.DeepEqual(tail, wantTail) {
		t.Errorf("items with tests, tail:\n got %+v\nwant %+v", tail, wantTail)
	}
}

// TestRustScopeFactsInGraph: the builder files each Rust file's imports and
// items under its path.
func TestRustScopeFactsInGraph(t *testing.T) {
	dir := t.TempDir()
	writeRustFile(t, dir, "lib.rs", "use acme_kdf::Kdf;\n\npub fn derive() { Kdf::new(); }\n")
	graph, err := NewBuilderForEcosystem("rust", NewRustParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	file := filepath.Join(dir, "lib.rs")
	if got := graph.RustImports[file]; len(got) != 1 || got[0].Module != "acme_kdf" || got[0].Name != "Kdf" {
		t.Errorf("RustImports[%s] = %+v, want the one use of acme_kdf::Kdf (have %v)", file, got, graph.RustImports)
	}
	if got := graph.RustItems[file]; len(got) != 1 || got[0].Kind != RustItemFn || got[0].Name != "derive" {
		t.Errorf("RustItems[%s] = %+v, want the fn derive", file, got)
	}
}

// TestRustTypeAliasItems: a type alias is an item at any depth, in a module,
// a function body and an impl (an associated type definition), with its
// aliased type as written and the column of its `type` keyword after any
// visibility; a trait's associated type declaration is none.
func TestRustTypeAliasItems(t *testing.T) {
	src := `pub type Cipher = acme_ctr::Ctr<acme_block::Block128>;
type Pair<T> = AcmeGcm<T, U12>;
pub(crate) type Multi =
    acme::Mode<acme::Cipher>;
trait Out { type Output; type Bounded: Clone; }
impl Out for Key {
    type Output = acme::Digest;
}
fn run() {
    type Local = acme::Hash;
}
`
	_, items := parseRustScopeFacts(t, src)
	want := []RustItem{
		{Kind: RustItemType, Name: "Cipher", Line: 1, StartCol: 1, EndCol: 55, Type: "acme_ctr::Ctr<acme_block::Block128>", KeywordCol: 5},
		{Kind: RustItemType, Name: "Pair", Line: 2, StartCol: 1, EndCol: 32, Type: "AcmeGcm<T, U12>", KeywordCol: 1},
		{Kind: RustItemType, Name: "Multi", Line: 3, StartCol: 1, EndCol: 30, EndLine: 4, Type: "acme::Mode<acme::Cipher>", KeywordCol: 12},
		{Kind: RustItemTrait, Name: "Out", Line: 5, StartCol: 1, EndCol: 48},
		{Kind: RustItemImpl, Name: "Key", Line: 6, StartCol: 1, EndCol: 2, EndLine: 8},
		{Kind: RustItemType, Name: "Output", Line: 7, StartCol: 5, EndCol: 32, Type: "acme::Digest", KeywordCol: 5},
		{Kind: RustItemFn, Name: "run", Line: 9, StartCol: 1, EndCol: 2, EndLine: 11},
		{Kind: RustItemType, Name: "Local", Line: 10, StartCol: 5, EndCol: 29, Type: "acme::Hash", KeywordCol: 5},
	}
	if !reflect.DeepEqual(items, want) {
		t.Errorf("items:\n got %+v\nwant %+v", items, want)
	}
}

// TestRustFnParams: a fn item carries its parameters in order, each with the
// pattern before the `:` and the type after it as written, and its span
// without attributes; a shorthand self is a receiver with no type, a typed
// `self: Box<Self>` a receiver with its type. A trait's bodiless method is no
// item.
func TestRustFnParams(t *testing.T) {
	src := `trait Signer { fn sign(&self, m: &[u8]); }
impl Signer {
    fn sign(&self, key: &acme::SigningKey, #[allow(unused)] mut m: Path<G>) {}
    fn boxed(self: Box<Self>, (a, b): (u8, u8), _: u8) {}
    fn owned(&'a mut self,
        data: Vec<
            u8>) {}
}
fn bare() {}
`
	_, items := parseRustScopeFacts(t, src)
	want := map[string][]RustParam{
		"sign": {
			{Pattern: "&self", Self: true, Line: 3, StartCol: 13, EndCol: 18},
			{Pattern: "key", Type: "&acme::SigningKey", Line: 3, StartCol: 20, EndCol: 42},
			{Pattern: "mut m", Type: "Path<G>", Line: 3, StartCol: 61, EndCol: 75},
		},
		"boxed": {
			{Pattern: "self", Type: "Box<Self>", Self: true, Line: 4, StartCol: 14, EndCol: 29},
			{Pattern: "(a, b)", Type: "(u8, u8)", Line: 4, StartCol: 31, EndCol: 47},
			{Pattern: "_", Type: "u8", Line: 4, StartCol: 49, EndCol: 54},
		},
		"owned": {
			{Pattern: "&'a mut self", Self: true, Line: 5, StartCol: 14, EndCol: 26},
			{Pattern: "data", Type: "Vec<\n            u8>", Line: 6, StartCol: 9, EndCol: 16, EndLine: 7},
		},
		"bare": nil,
	}
	got := map[string][]RustParam{}
	for _, it := range items {
		if it.Kind == RustItemFn {
			got[it.Name] = it.Params
		} else if it.Params != nil {
			t.Errorf("%s %s has params %+v", it.Kind, it.Name, it.Params)
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("params:\n got %+v\nwant %+v", got, want)
	}
}
