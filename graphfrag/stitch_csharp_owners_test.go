// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

var (
	csOwnerApp = ComponentKey{Purl: "pkg:nuget/App", Version: "1.0.0"}
	csOwnerDep = ComponentKey{Purl: "pkg:nuget/Acme.Crypto", Version: "2.0.0"}
)

const (
	csOwnerSink  = "Acme.Crypto.Engines.(Sm4Engine).Init#2"
	csOwnerGuess = "App.(Sm4Engine).Init#2"
)

// csharpOwnerVerdict stitches a C# application over Acme.Crypto and returns
// the verdict of the one finding, which sits in the dependency's Init. The
// application calls it with the key the parser guessed on its own namespace,
// carrying the owners the file's usings allow.
func csharpOwnerVerdict(t *testing.T, owners []string) ExportFindingGraph {
	t.Helper()
	fragments := map[ComponentKey]Fragment{
		csOwnerApp: {
			Component: csOwnerApp, GraphAlgoVersion: GraphAlgoVersionCSharp,
			Functions: []Function{{Signature: "App.(Program).Main#1"}},
			ExternalCalls: []ExternalCall{{
				Caller: "App.(Program).Main#1", TargetSignature: csOwnerGuess, Resolution: ResolutionExact,
				MethodName: "Init", Arity: 2, CallSite: 7, CandidateOwners: owners,
			}},
		},
		csOwnerDep: {
			Component: csOwnerDep, GraphAlgoVersion: GraphAlgoVersionCSharp,
			Functions:        []Function{{Signature: csOwnerSink}},
			CryptoOperations: []CryptoOperation{{Function: csOwnerSink, FindingID: "f", RuleID: "rule", FilePath: "src/Sm4Engine.cs", StartLine: 1}},
		},
	}
	res, err := StitchWithOptions(csOwnerApp, DependencyGraph{csOwnerApp: {csOwnerDep}}, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	graphs := res.ToCallgraphExport(csOwnerApp, ScanMeta{Ecosystem: "csharp"}).FindingGraphs
	if len(graphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(graphs))
	}
	return graphs[0]
}

// The using that declares the type re-keys the call, so the dependency's
// finding is reachable.
func TestStitch_CSharpCandidateOwnerReachesTheDependency(t *testing.T) {
	t.Parallel()
	fg := csharpOwnerVerdict(t, []string{"App.Sm4Engine", "System.Sm4Engine", "Acme.Crypto.Engines.Sm4Engine"})
	if fg.Reachability != ReachabilityReachable {
		t.Fatalf("got %q, want %q", fg.Reachability, ReachabilityReachable)
	}
}

// Without the owners, the caller-local guess matches nothing: this is what a
// fragment before 1.39 carries.
func TestStitch_CSharpWithoutCandidateOwnersStaysUnreachable(t *testing.T) {
	t.Parallel()
	fg := csharpOwnerVerdict(t, nil)
	if fg.Reachability == ReachabilityReachable {
		t.Fatalf("got %q, want it not reachable", fg.Reachability)
	}
}

// Two usings that both declare the type name leave the owner ambiguous, and
// a wrong edge costs precision: neither is taken.
func TestStitch_CSharpAmbiguousCandidateOwnersTakeNoEdge(t *testing.T) {
	t.Parallel()
	fragments := map[ComponentKey]Fragment{}
	other := ComponentKey{Purl: "pkg:nuget/Other.Crypto", Version: "3.0.0"}
	fragments[csOwnerApp] = Fragment{
		Component: csOwnerApp, GraphAlgoVersion: GraphAlgoVersionCSharp,
		Functions: []Function{{Signature: "App.(Program).Main#1"}},
		ExternalCalls: []ExternalCall{{
			Caller: "App.(Program).Main#1", TargetSignature: csOwnerGuess, Resolution: ResolutionExact,
			MethodName: "Init", Arity: 2, CallSite: 7,
			CandidateOwners: []string{"App.Sm4Engine", "Acme.Crypto.Engines.Sm4Engine", "Other.Engines.Sm4Engine"},
		}},
	}
	fragments[csOwnerDep] = Fragment{
		Component: csOwnerDep, GraphAlgoVersion: GraphAlgoVersionCSharp,
		Functions:        []Function{{Signature: csOwnerSink}},
		CryptoOperations: []CryptoOperation{{Function: csOwnerSink, FindingID: "f", RuleID: "rule", FilePath: "src/Sm4Engine.cs", StartLine: 1}},
	}
	fragments[other] = Fragment{
		Component: other, GraphAlgoVersion: GraphAlgoVersionCSharp,
		Functions: []Function{{Signature: "Other.Engines.(Sm4Engine).Init#2"}},
	}
	res, err := StitchWithOptions(csOwnerApp, DependencyGraph{csOwnerApp: {csOwnerDep, other}}, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	graphs := res.ToCallgraphExport(csOwnerApp, ScanMeta{Ecosystem: "csharp"}).FindingGraphs
	if len(graphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(graphs))
	}
	if graphs[0].Reachability == ReachabilityReachable {
		t.Fatalf("got %q, want it not reachable", graphs[0].Reachability)
	}
}
