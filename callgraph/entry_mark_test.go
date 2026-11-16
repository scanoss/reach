// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

// TestEntryPoint_NamesTheCatalogEntry: a declaration a catalog entry makes an
// entry point carries that entry's ID; one that language semantics make an
// entry point (main) carries none.
func TestEntryPoint_NamesTheCatalogEntry(t *testing.T) {
	t.Parallel()
	fns := parseJavaInline(t, `package com.example;

import org.springframework.web.bind.annotation.GetMapping;

class Controller {
    @GetMapping("/sign")
    String sign() { return ""; }

    public static void main(String[] args) {}
}
`)
	tracer := NewTracer(&CallGraph{Functions: map[string]*FunctionDecl{}}, ".")
	for _, tc := range []struct {
		name string
		want EntryMark
	}{
		{"sign", EntryMark{Kind: RootKindFrameworkEntry, Rule: "java/spring:decorator:RequestMapping"}},
		{"main", EntryMark{Kind: RootKindMain}},
	} {
		decl := findFunctionByName(fns, tc.name)
		if decl == nil {
			t.Fatalf("no function %s", tc.name)
		}
		if got, ok := tracer.EntryPoint(decl, nil); !ok || got != tc.want {
			t.Errorf("EntryPoint(%s) = %+v, %v; want %+v", tc.name, got, ok, tc.want)
		}
	}
}
