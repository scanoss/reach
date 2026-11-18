// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"context"
	"testing"

	sitter "github.com/smacker/go-tree-sitter"
	"github.com/smacker/go-tree-sitter/rust"
)

// rustCallSitesSource writes calls in every position a call can stand: on an
// unresolved receiver, through parentheses, of an index, of a call's result, of
// a closure, in a const or static initializer at module, inline module, impl
// and trait level, in a nested function and in an expression macro.
const rustCallSitesSource = `use acme_kdf::Kdf;

static LEVEL: u8 = acme_kdf::level();
const SALT: &[u8] = acme_kdf::Salt::DEFAULT;

mod inner {
    pub static TABLE: [u8; 2] = acme_kdf::table(acme_kdf::Mode::Cbc);
}

pub struct Holder;

impl Holder {
    const ROUNDS: u32 = acme_kdf::rounds();
    fn derive(&self, input: &[u8], fs: &[fn(u8) -> u8]) -> u8 {
        let k = Kdf::new(input).unwrap();
        (helper)(1);
        fs[0](2);
        make()(3);
        (|x: u8| x)(4);
        unknown.thing().other(5);
        fn nested() { acme_kdf::nested_call(); }
        assert!(k.verify(input));
        <Kdf as acme_kdf::Tagged>::tag()
    }
}

trait Tagged {
    const TAG: u8 = acme_kdf::tag_of();
}

fn helper(x: u8) -> u8 { x }
fn make() -> fn(u8) -> u8 { helper }
`

// TestRustEveryCallIsASite: every call expression of the source, resolved or
// not, is a call of some declaration with its exact span, so a detector that
// reads calls as written sees all of them; a call written inside an
// expression macro is one too.
func TestRustEveryCallIsASite(t *testing.T) {
	dir := t.TempDir()
	writeRustTestFile(t, dir, rustCallSitesSource)
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	type span struct{ line, startCol, endCol int }
	sites := map[span]string{}
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			for _, call := range fn.Calls {
				sites[span{call.Line, call.StartCol, call.EndCol}] = fn.ID.String()
			}
		}
	}

	parser := sitter.NewParser()
	parser.SetLanguage(rust.GetLanguage())
	src := []byte(rustCallSitesSource)
	tree, err := parser.ParseCtx(context.Background(), nil, src)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	var calls int
	var walk func(node *sitter.Node)
	walk = func(node *sitter.Node) {
		if node.Type() == rustNodeCallExpression {
			calls++
			at := span{int(node.StartPoint().Row) + 1, int(node.StartPoint().Column) + 1, int(node.EndPoint().Column) + 1}
			if _, ok := sites[at]; !ok {
				t.Errorf("call %q at %d:%d-%d is no site", node.Content(src), at.line, at.startCol, at.endCol)
			}
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i))
		}
	}
	walk(tree.RootNode())
	if calls != 15 {
		t.Fatalf("walked %d call expressions, want the 15 the source writes outside macros", calls)
	}
	if fn := sites[span{22, 17, 32}]; fn != "app.(Holder).derive" {
		t.Errorf("k.verify(input) inside assert! is a call of %q, want app.(Holder).derive", fn)
	}
	if fn := sites[span{3, 20, 37}]; fn != "app.<varinit:main>" {
		t.Errorf("the static initializer's call is a call of %q, want app.<varinit:main>", fn)
	}
}

// TestRustUnnamedCallee: a call of a value the parser cannot name keeps its
// written text and is keyed to a name no declaration has; a parenthesized
// callee is the callee.
func TestRustUnnamedCallee(t *testing.T) {
	fn := parseRustFunction(t, "fn helper(x: u8) -> u8 { x }\nfn run(fs: &[fn(u8) -> u8]) {\n    (helper)(1);\n    fs[0](2);\n}\n", "run")
	if len(fn.Calls) != 2 {
		t.Fatalf("calls = %+v, want 2", fn.Calls)
	}
	if got := fn.Calls[0].Callee.String(); got != "app.helper" {
		t.Errorf("(helper)(1) calls %s, want app.helper", got)
	}
	if got, raw := fn.Calls[1].Callee.String(), fn.Calls[1].Raw; got != "app."+rustUnnamedCallee || raw != "fs[0]" {
		t.Errorf("fs[0](2) calls %s (raw %q), want app.%s with raw fs[0]", got, raw, rustUnnamedCallee)
	}
}

// TestRustVarinit: the initializers of const and static items outside
// function bodies make their calls and read their paths in the file's
// <varinit>, resolved in the item's scope; a file without any has none.
func TestRustVarinit(t *testing.T) {
	fn := parseRustFunction(t, rustCallSitesSource, "<varinit:main>")
	var callees []string
	for _, call := range fn.Calls {
		callees = append(callees, call.Callee.String())
	}
	want := map[string]bool{"acme_kdf.level": true, "acme_kdf.table": true, "acme_kdf.rounds": true, "acme_kdf.tag_of": true}
	for _, c := range callees {
		delete(want, c)
	}
	if len(want) != 0 || len(fn.Calls) != 4 {
		t.Errorf("varinit calls = %v, missing %v", callees, want)
	}
	var refs []string
	for _, r := range withoutTypeRefs(fn.ConstantRefs) {
		refs = append(refs, r.Text+"/"+r.Context)
	}
	if len(refs) != 2 || refs[0] != "acme_kdf::Salt::DEFAULT/init" || refs[1] != "acme_kdf::Mode::Cbc/arg" {
		t.Errorf("varinit refs = %v, want acme_kdf::Salt::DEFAULT/init and acme_kdf::Mode::Cbc/arg", refs)
	}

	dir := t.TempDir()
	writeRustTestFile(t, dir, "fn run() { const K: u8 = acme_kdf::k(); }\n")
	analyses, err := NewRustParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range analyses[0].Functions {
		if f.ID.Name != "run" {
			t.Errorf("unexpected declaration %s: a const inside a function body is the function's", f.ID)
		}
	}
}
