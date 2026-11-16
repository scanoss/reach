// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"reflect"
	"testing"
)

// A supertype named through wildcard imports is exported as the candidate the
// graph knows, in Java's lookup order; one the graph cannot settle keeps its
// candidates, and so does a clause lookup order does not decide.
func TestExportSupertypesSettlesWildcardCandidates(t *testing.T) {
	t.Parallel()
	graph := &CallGraph{
		SourceSupertypes: map[string][]string{
			"app.Impl": {
				"app.Formatter|lib.Formatter|java.lang.Formatter", // same package, declared below
				"app.Callback|lib.Callback|java.lang.Callback",    // lib, from the dependency's bytecode
				"app.Unknown|lib.Unknown|java.lang.Unknown",       // nowhere
				"app.Outer.Node|app.Other.Node",                   // two nested declarations
			},
			"app.Formatter": nil,
			"app.Runner":    {"app.Runnable|java.lang.Runnable"}, // platform type
		},
		TypeHierarchy: map[string][]string{"java.lang.Thread": {"java.lang.Runnable"}},
		ExternalMethodSignatures: map[string][]ExternalMethodSignature{
			qualifiedMethodArityKey("lib", "Callback", "call#1"): nil,
			qualifiedMethodArityKey("app", "Outer$Node", "x#0"):  nil,
		},
	}
	got := graph.ExportSupertypes()
	want := map[string][]string{
		"app.Impl": {
			"app.Formatter",
			"lib.Callback",
			"app.Unknown|lib.Unknown|java.lang.Unknown",
			"app.Outer.Node|app.Other.Node",
		},
		"app.Formatter": {},
		"app.Runner":    {"java.lang.Runnable"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExportSupertypes = %#v, want %#v", got, want)
	}
	if graph.SourceSupertypes["app.Impl"][1] != "app.Callback|lib.Callback|java.lang.Callback" {
		t.Error("ExportSupertypes modified the graph")
	}
}
