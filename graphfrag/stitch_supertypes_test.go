// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"reflect"
	"sort"
	"testing"
)

// A call on a type that only inherits an overloaded method resolves to every
// overload of the supertype, always in node order, and the same on every call.
func TestInheritedTargetsListsOverloadsInNodeOrder(t *testing.T) {
	t.Parallel()
	base, sub := ComponentKey{Purl: "pkg:maven/a/base", Version: "1"}, ComponentKey{Purl: "pkg:maven/a/sub", Version: "1"}
	var functions []Function
	var want []graphNode
	for _, params := range []string{"Ljava/lang/String;", "I", "J", "[B", "Z", "D", "F", "C"} {
		sig := "a.(Base).run#1$" + params
		functions = append(functions, Function{Signature: sig})
		want = append(want, graphNode{Component: base, Function: sig})
	}
	fragments := map[ComponentKey]Fragment{
		base: {Component: base, Functions: functions},
		sub:  {Component: sub, Functions: []Function{{Signature: "a.(Sub).other#0"}}, Supertypes: map[string][]string{"a.Sub": {"a.Base"}}},
	}
	h := indexTypeHierarchy([]ComponentKey{sub, base}, fragments)
	sort.Slice(want, func(i, j int) bool { return nodeLess(want[i], want[j]) })
	for range 20 {
		fresh := indexTypeHierarchy([]ComponentKey{sub, base}, fragments)
		if got := fresh.inheritedTargets("a.(Sub).run#1"); !reflect.DeepEqual(got, want) {
			t.Fatalf("inheritedTargets = %v, want %v", got, want)
		}
	}
	first := h.inheritedTargets("a.(Sub).run#1")
	if again := h.inheritedTargets("a.(Sub).run#1"); !reflect.DeepEqual(again, first) {
		t.Fatalf("second call = %v, want %v", again, first)
	}
	if got := h.inheritedTargets("a.(Sub).run#1$I"); !reflect.DeepEqual(got, []graphNode{{Component: base, Function: "a.(Base).run#1$I"}}) {
		t.Fatalf("exact overload = %v", got)
	}
}
