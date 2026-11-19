// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"

	"github.com/scanoss/reach/callgraph/contracts"
)

// buildRustCrate builds the graph of an invented crate from its files.
func buildRustCrate(t *testing.T, files map[string]string, kb *contracts.KnowledgeBase) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	writeRustFile(t, dir, "Cargo.toml", "[package]\nname = \"acme\"\nversion = \"0.1.0\"\nedition = \"2021\"\n")
	for name, src := range files {
		writeRustFile(t, dir, name, src)
	}
	parser := NewRustParser()
	if kb != nil {
		parser.kb = kb
	}
	graph, err := NewBuilderForEcosystem("rust", parser).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "acme"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

// rustCallees lists the callee keys a function calls, and those it reaches
// without a call expression.
func rustCallees(t *testing.T, graph *CallGraph, caller string) (calls, implicit []string) {
	t.Helper()
	fn, ok := graph.Functions[caller]
	if !ok {
		t.Fatalf("%s is not declared; have %v", caller, keysOfFunctions(graph))
	}
	for i := range fn.Calls {
		calls = append(calls, fn.Calls[i].Callee.String())
	}
	for i := range fn.ImplicitCalls {
		implicit = append(implicit, fn.ImplicitCalls[i].Callee.String())
	}
	return calls, implicit
}

func keysOfFunctions(graph *CallGraph) []string {
	var out []string
	for key := range graph.Functions {
		out = append(out, key)
	}
	slices.Sort(out)
	return out
}

// `<Alias as Trait>::Assoc::f(..)` names f on the type the crate's own
// `impl Trait for Type { type Assoc = T; }` gives Assoc, T being declared in
// the impl's module, which is not the caller's.
func TestRustParser_QualifiedAssocTypeCallResolvesThroughTheCratesImpl(t *testing.T) {
	t.Parallel()
	graph := buildRustCrate(t, map[string]string{
		"src/lib.rs": "pub mod wrap;\n",
		"src/wrap.rs": `mod inner;

pub trait Codec {
    type Key;
}

type Chosen = inner::Scheme;

pub fn load(b: &[u8]) {
    <Chosen as Codec>::Key::from_bytes(b);
}
`,
		"src/wrap/inner.rs": `pub struct Scheme;
pub struct Key;

impl Key {
    pub fn from_bytes(b: &[u8]) -> Key { Key }
}

impl super::Codec for Scheme {
    type Key = Key;
}
`,
	}, nil)
	calls, _ := rustCallees(t, graph, "acme::wrap.load")
	if !slices.Contains(calls, "acme::wrap::inner.(Key).from_bytes") {
		t.Errorf("calls = %v, want acme::wrap::inner.(Key).from_bytes", calls)
	}
}

// An associated type of a dependency's trait resolves through the KB's
// trait_associated_types; one neither the crate nor the KB names keeps the
// key it had.
func TestRustParser_QualifiedAssocTypeCallResolvesThroughTheKB(t *testing.T) {
	t.Parallel()
	kb, err := contracts.Load([]byte(`schema_version: "2"
ecosystem: rust
library:
  name: widget
trait_associated_types:
  - trait: Shaper
    name: Handle
    type: widget::shape::Handle
contracts: []
`))
	if err != nil {
		t.Fatal(err)
	}
	graph := buildRustCrate(t, map[string]string{
		"src/lib.rs": `use widget::{Shaper, Round};

pub fn open(b: &[u8]) {
    <Round as Shaper>::Handle::from_bytes(b);
    <Round as Unknown>::Other::from_bytes(b);
}
`,
	}, kb)
	calls, _ := rustCallees(t, graph, "acme.open")
	if !slices.Contains(calls, "widget::shape.(Handle).from_bytes") {
		t.Errorf("calls = %v, want widget::shape.(Handle).from_bytes", calls)
	}
	for _, c := range calls {
		if c == "widget::shape.(Other).from_bytes" || c == "widget.(Other).from_bytes" {
			t.Errorf("an uncataloged associated type resolved: %s", c)
		}
	}
}

// A call the crate makes to its own item through a public path (`pub use`)
// reaches the declaration, and so does the FromStr a `parse::<T>()` runs.
func TestRustBuilder_CallThroughOwnPublicPathJoinsTheDeclaration(t *testing.T) {
	t.Parallel()
	graph := buildRustCrate(t, map[string]string{
		"src/lib.rs": `mod native;
pub mod keys;
pub mod api;
pub use native::token;

pub fn read(s: &str) {
    crate::keys::Identity::from_buffer(s);
    crate::api::run(s);
    let _ = s.parse::<token::Recipient>();
}
`,
		"src/keys.rs": "mod identity;\npub use identity::Identity;\n",
		"src/keys/identity.rs": `pub struct Identity;
impl Identity {
    pub fn from_buffer(s: &str) -> Identity { Identity }
}
`,
		"src/api.rs":       "mod inner;\npub use self::inner::*;\n",
		"src/api/inner.rs": "pub fn run(s: &str) {}\n",
		"src/native.rs":    "pub mod token;\n",
		"src/native/token.rs": `pub struct Recipient;
impl std::str::FromStr for Recipient {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, ()> { Ok(Recipient) }
}
`,
	}, nil)
	for _, key := range []string{
		"acme::keys::identity.(Identity).from_buffer",
		"acme::native::token.(Recipient).from_str",
	} {
		if _, declared := graph.Functions[key]; !declared {
			t.Fatalf("%s is not declared; have %v", key, keysOfFunctions(graph))
		}
		if callers := graph.Callers[key]; !slices.Contains(callers, "acme.read") {
			t.Errorf("callers of %s = %v, want acme.read", key, callers)
		}
	}
	var run string
	for key := range graph.Functions {
		if graph.Functions[key].ID.Name == "run" {
			run = key
		}
	}
	if callers := graph.Callers[run]; run == "" || !slices.Contains(callers, "acme.read") {
		t.Errorf("callers of %q = %v, want acme.read", run, callers)
	}
}

// A function handed to a combinator as a value runs when the combinator
// calls it: the caller reaches it, a type or variant named as a value is no
// function.
func TestRustParser_FunctionPassedAsValueIsReached(t *testing.T) {
	t.Parallel()
	graph := buildRustCrate(t, map[string]string{
		"src/lib.rs": `pub fn first(i: &[u8]) -> u8 { i[0] }
pub fn second(i: &[u8]) -> u8 { i[1] }
pub enum Kind { A }

pub fn either(i: &[u8]) -> u8 {
    combine((first, &second), Kind::A, None).run(i)
}
`,
	}, nil)
	callers := func(key string) []string { return graph.Callers[key] }
	for _, key := range []string{"acme.first", "acme.second"} {
		if !slices.Contains(callers(key), "acme.either") {
			t.Errorf("callers of %s = %v, want acme.either", key, callers(key))
		}
	}
	_, implicit := rustCallees(t, graph, "acme.either")
	for _, c := range implicit {
		if c == "acme.(Kind).A" || c == "acme.A" || c == "acme.None" {
			t.Errorf("a variant was taken for a function value: %s", c)
		}
	}
}

// The trait hierarchy is recorded as supertypes in owner form: an impl's
// trait, a supertrait, and a blanket impl's parameter under its bound. A
// trait's required method is an abstract declaration.
func TestRustParser_TraitHierarchyIsRecordedAsSupertypes(t *testing.T) {
	t.Parallel()
	graph := buildRustCrate(t, map[string]string{
		"src/lib.rs": `pub trait Core {}

pub trait Seal: Core {
    fn seal_detached(&self, b: &mut [u8]);
    fn seal_in_place(&self, b: &mut [u8]) { self.seal_detached(b); }
}

pub trait Box {
    fn boxed(&self, b: &[u8]) -> Vec<u8>;
}

impl<S: Seal> Box for S {
    fn boxed(&self, b: &[u8]) -> Vec<u8> { let mut v = b.to_vec(); self.seal_in_place(&mut v); v }
}

pub struct Cipher;
impl Core for Cipher {}
impl Seal for Cipher {
    fn seal_detached(&self, b: &mut [u8]) {}
}
`,
	}, nil)
	want := map[string][]string{
		"acme.Seal":   {"acme.Core", "acme.S"},
		"acme.Cipher": {"acme.Core", "acme.Seal"},
	}
	for owner, supers := range want {
		got := slices.Clone(graph.SourceSupertypes[owner])
		slices.Sort(got)
		if !slices.Equal(got, supers) {
			t.Errorf("supertypes of %s = %v, want %v", owner, got, supers)
		}
	}
	fn, ok := graph.Functions["acme.(Seal).seal_detached"]
	if !ok || !fn.Abstract {
		t.Errorf("acme.(Seal).seal_detached declared = %v, abstract = %v; want an abstract declaration", ok, ok && fn.Abstract)
	}
	if fn, ok := graph.Functions["acme.(Box).boxed"]; !ok || fn.ReturnType != "Vec<u8>" {
		t.Errorf("acme.(Box).boxed return type = %q, want Vec<u8>", fn.ReturnType)
	}
	if fn, ok := graph.Functions["acme.(Seal).seal_in_place"]; !ok || fn.Abstract {
		t.Errorf("the default method acme.(Seal).seal_in_place must stay a concrete declaration")
	}
}

// The variable of a `for` over an iterator written by its trait,
// `impl Iterator<Item = &dyn Sealer>`, holds the item type: a method call on
// it is a call on the trait.
func TestRustParser_ForOverImplIteratorBindsTheItemType(t *testing.T) {
	t.Parallel()
	graph := buildRustCrate(t, map[string]string{
		"src/lib.rs": `pub trait Sealer {
    fn seal(&self, b: &[u8]);
}

pub fn seal_all<'a>(sealers: impl Iterator<Item = &'a dyn Sealer>, b: &[u8]) {
    for s in sealers {
        s.seal(b);
    }
}
`,
	}, nil)
	calls, _ := rustCallees(t, graph, "acme.seal_all")
	if !slices.Contains(calls, "acme.(Sealer).seal") {
		t.Errorf("calls = %v, want acme.(Sealer).seal", calls)
	}
}

// A handler a framework registration names is that framework's entry point:
// the function that registers it does not become its caller, so it stays a
// root even when nothing calls the registering function.
func TestRustBuilder_RegisteredHandlerKeepsNoCaller(t *testing.T) {
	t.Parallel()
	graph := buildRustCrate(t, map[string]string{
		"src/lib.rs": `use axum::{routing::get, Router};

async fn list() -> &'static str { "x" }
fn helper(i: &[u8]) -> u8 { i[0] }

pub fn app() -> Router {
    apply(helper);
    Router::new().route("/", get(list))
}
`,
	}, nil)
	list := graph.Functions["acme.list"]
	if list == nil || list.EntryKind == "" {
		t.Fatalf("acme.list is not an entry point: %+v", list)
	}
	if callers := graph.Callers["acme.list"]; len(callers) > 0 {
		t.Errorf("callers of the registered handler = %v, want none", callers)
	}
	if callers := graph.Callers["acme.helper"]; !slices.Contains(callers, "acme.app") {
		t.Errorf("callers of acme.helper = %v, want acme.app", callers)
	}
}
