// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"reflect"
	"testing"
)

// callerLists is the call-site-free view of reverseAdjacency, in the same
// order: the chain walk reads one where it read the other.
func TestCallerListsMatchReverseAdjacency(t *testing.T) {
	t.Parallel()
	a, b := ComponentKey{Purl: "pkg:maven/x/a", Version: "1"}, ComponentKey{Purl: "pkg:maven/x/a-b", Version: "1"}
	node := func(c ComponentKey, f string) graphNode { return graphNode{Component: c, Function: f} }
	target, other := node(a, "t.(T).run#0"), node(b, "t.(T).run#0")
	adjacency := map[graphNode][]adjacencyEdge{}
	for i, caller := range []graphNode{node(b, "z#0"), node(a, "z#0"), node(a, "m#0"), node(b, "c#0"), node(a, "c#0"), node(a, "m#0")} {
		adjacency[caller] = append(adjacency[caller],
			adjacencyEdge{target: target, entryCall: &CallSite{Line: i}},
			adjacencyEdge{target: other, entryCall: &CallSite{Line: 100 + i}})
	}
	adjacency[target] = nil
	for range 10 {
		if got, want := callerLists(adjacency), callersWithoutCallSites(reverseAdjacency(adjacency)); !reflect.DeepEqual(got, want) {
			t.Fatalf("callerLists = %v, want %v", got, want)
		}
	}
}
