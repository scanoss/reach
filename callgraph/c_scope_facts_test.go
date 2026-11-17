// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// cScopeGraph builds a C project of one file, main.c.
func cScopeGraph(t *testing.T, src string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem(ecosystemC, NewParserForEcosystem(ecosystemC)).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

func cScopeFunction(t *testing.T, graph *CallGraph, name string) *FunctionDecl {
	t.Helper()
	for _, fn := range graph.Functions {
		if fn.ID.Name == name {
			return fn
		}
	}
	t.Fatalf("no function %s", name)
	return nil
}

// A directive written inside a function body is listed in source order,
// marked InFunction.
func TestCIncludesInsideFunctionBodies(t *testing.T) {
	t.Parallel()
	src := "#include <zork/a.h>\n" +
		"void f(void) {\n" +
		"    #include <zork/b.h>\n" +
		"}\n" +
		"#include \"plugh.h\"\n"
	graph := cScopeGraph(t, src)
	var got []CInclude
	for _, includes := range graph.CIncludes {
		got = includes
	}
	want := []CInclude{
		{Line: 1, StartCol: 1, EndCol: 20, Header: "zork/a.h", System: true, Text: "#include <zork/a.h>"},
		{Line: 3, StartCol: 5, EndCol: 24, Header: "zork/b.h", System: true, Text: "#include <zork/b.h>", InFunction: true},
		{Line: 5, StartCol: 1, EndCol: 19, Header: "plugh.h", Text: "#include \"plugh.h\""},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("includes:\n got  %+v\n want %+v", got, want)
	}
}

// Every declared name of a body's declarations is listed with the whole
// declaration's span, its type with the declarator's pointers and arrays,
// and its initializer's kind.
func TestCDeclarationsOfABody(t *testing.T) {
	t.Parallel()
	src := "int f(int p) {\n" +
		"    const char *name = \"zork-256\", tag;\n" +
		"    unsigned  int groups[] = {ZORK_A, ZORK_B};\n" +
		"    void *ctx = NULL;\n" +
		"    int n = zork_len(p);\n" +
		"    if (p) {\n" +
		"        long k = (long) p;\n" +
		"    }\n" +
		"    int m = p,\n" +
		"        q;\n" +
		"    return n;\n" +
		"}\n"
	fn := cScopeFunction(t, cScopeGraph(t, src), "f")
	want := []VarDecl{
		{Type: "const char*", Name: "name", Line: 2, StartCol: 5, EndCol: 40, Init: VarInitLiteral},
		{Type: "const char", Name: "tag", Line: 2, StartCol: 5, EndCol: 40},
		{Type: "unsigned int[]", Name: "groups", Line: 3, StartCol: 5, EndCol: 47, Init: VarInitOther},
		{Type: "void*", Name: "ctx", Line: 4, StartCol: 5, EndCol: 22, Init: VarInitNull},
		{Type: "int", Name: "n", Line: 5, StartCol: 5, EndCol: 25, Init: VarInitCall},
		{Type: "long", Name: "k", Line: 7, StartCol: 9, EndCol: 27, Init: VarInitCast},
		{Type: "int", Name: "m", Line: 9, StartCol: 5, EndCol: 11, EndLine: 10, Init: VarInitOther},
		{Type: "int", Name: "q", Line: 9, StartCol: 5, EndCol: 11, EndLine: 10},
	}
	if !reflect.DeepEqual(fn.Declarations, want) {
		t.Errorf("declarations:\n got  %+v\n want %+v", fn.Declarations, want)
	}
}

// An assignment to a field of an object is a store: receiver and field as
// written, the operator, the value's text and the assignment's span. An
// assignment to a variable or an array element is not.
func TestCFieldStoresOfABody(t *testing.T) {
	t.Parallel()
	src := "void f(struct job *job, struct cfg c) {\n" +
		"    job->cipher_mode = ZORK_CCM;\n" +
		"    c.flags |= ZORK_PAD;\n" +
		"    job -> next->mode = 2;\n" +
		"    int x;\n" +
		"    x = 3;\n" +
		"    job->keys[0] = 4;\n" +
		"}\n"
	fn := cScopeFunction(t, cScopeGraph(t, src), "f")
	want := []AttributeStore{
		{Receiver: "job", Attribute: "cipher_mode", Operator: "=", Line: 2, StartCol: 5, EndCol: 32, Value: ComparedOperand{Text: "ZORK_CCM"}},
		{Receiver: "c", Attribute: "flags", Operator: "|=", Line: 3, StartCol: 5, EndCol: 24, Value: ComparedOperand{Text: "ZORK_PAD"}},
		{Receiver: "job->next", Attribute: "mode", Operator: "=", Line: 4, StartCol: 5, EndCol: 26, Value: ComparedOperand{Text: "2"}},
	}
	if !reflect.DeepEqual(fn.AttributeStores, want) {
		t.Errorf("stores:\n got  %+v\n want %+v", fn.AttributeStores, want)
	}
}
