// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

// rustTraitFinding stitches an application whose main calls
// `acme_sign.(Cipher).boxed` into acme-sign, an invented crate laid out as
// RustCrypto's aead is: Cipher implements Seal, whose default seal_in_place
// calls the required seal_detached; a blanket `impl<S: Seal> Box for S`
// (keyed under S) gives Cipher boxed, which calls seal_in_place. The finding
// sits in the implementations of seal_detached named by impls.
func rustTraitFinding(t *testing.T, supertypes map[string][]string, impls ...string) ExportFindingGraph {
	t.Helper()
	app := Fragment{
		Component:        rustApp,
		GraphAlgoVersion: GraphAlgoVersionRust,
		Functions:        []Function{{Signature: "app.main"}},
		ExternalCalls: []ExternalCall{{
			Caller: "app.main", TargetSignature: "acme_sign.(Cipher).boxed", Resolution: ResolutionExact, MethodName: "boxed", CallSite: 3,
		}},
		EntryKinds: map[string]string{"app.main": RootKindMain},
	}
	functions := []Function{
		{Signature: "acme_sign.(S).boxed", CanonicalSignature: "acme_sign.S.boxed(?)"},
		{Signature: "acme_sign.(Seal).seal_in_place", CanonicalSignature: "acme_sign.Seal.seal_in_place(?)"},
		{Signature: "acme_sign.(Seal).seal_detached", CanonicalSignature: "acme_sign.Seal.seal_detached(?)", Abstract: true},
	}
	var ops []CryptoOperation
	for i, impl := range impls {
		functions = append(functions, Function{Signature: impl, CanonicalSignature: impl + "(?)"})
		ops = append(ops, CryptoOperation{Function: impl, FindingID: "f-" + string(rune('1'+i)), RuleID: "rule.seal"})
	}
	dep := Fragment{
		Component:        rustSign,
		Module:           "acme_sign",
		GraphAlgoVersion: GraphAlgoVersionRust,
		AbstractMethods:  true,
		Functions:        functions,
		InternalEdges: []InternalEdge{
			{Caller: "acme_sign.(S).boxed", Callee: "acme_sign.(Seal).seal_in_place", Resolution: ResolutionExact, MethodName: "seal_in_place", CallSite: 10},
			{Caller: "acme_sign.(Seal).seal_in_place", Callee: "acme_sign.(Seal).seal_detached", Resolution: ResolutionExact, MethodName: "seal_detached", CallSite: 20},
		},
		Supertypes:       supertypes,
		CryptoOperations: ops,
	}
	res, err := StitchWithOptions(rustApp, DependencyGraph{rustApp: {rustSign}},
		map[ComponentKey]Fragment{rustApp: app, rustSign: dep},
		StitchOptions{EntryRootedOnly: true, HierarchyFromSupertypes: true, AmbiguousDispatchUnknown: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	cg := res.ToCallgraphExport(rustApp, ScanMeta{Ecosystem: "rust"})
	if len(cg.FindingGraphs) == 0 {
		t.Fatal("no finding graphs")
	}
	return cg.FindingGraphs[0]
}

// A call to a method a Rust type gets from a blanket impl reaches the
// blanket's body through the type's supertypes, and a trait's required
// method dispatches to the implementation: reachable with one
// implementation, unknown with two, never unreachable. Without the
// supertypes nothing joins.
func TestStitch_RustTraitDispatchThroughBlanketImplAndDefaultMethod(t *testing.T) {
	t.Parallel()
	hierarchy := map[string][]string{
		"acme_sign.Cipher": {"acme_sign.Seal"},
		"acme_sign.Other":  {"acme_sign.Seal"},
		"acme_sign.Seal":   {"acme_sign.S"},
	}
	if fg := rustTraitFinding(t, hierarchy, "acme_sign.(Cipher).seal_detached"); fg.Reachability != ReachabilityReachable {
		t.Errorf("one implementation: reachability %q, want reachable", fg.Reachability)
	}
	if fg := rustTraitFinding(t, hierarchy, "acme_sign.(Cipher).seal_detached", "acme_sign.(Other).seal_detached"); fg.Reachability != ReachabilityUnknown {
		t.Errorf("two implementations: reachability %q, want unknown", fg.Reachability)
	}
	if fg := rustTraitFinding(t, nil, "acme_sign.(Cipher).seal_detached"); fg.Reachability == ReachabilityReachable {
		t.Error("reachable without the supertypes")
	}
}
