// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

// A client call site the client could not type (bare name#arity target,
// name_only) is matched by name and arity against the direct dependencies, so
// the finding it would reach reads unknown with unresolved_dispatch instead of
// unreachable.
func TestStitch_BareNameOnlyCallSiteMatchesByNameAndArity(t *testing.T) {
	t.Parallel()
	root := Fragment{
		Component: componentA,
		Functions: []Function{{Signature: "com.acme.app.(AppEntry).entry#0"}},
		ExternalCalls: []ExternalCall{{
			Caller: "com.acme.app.(AppEntry).entry#0", TargetSignature: "build#0",
			Resolution: ResolutionNameOnly, MethodName: "build", Arity: 0, CallSite: 10,
		}},
	}
	sink := Fragment{
		Component: componentC,
		Functions: []Function{{Signature: "net.crypto.(SSLContextBuilder).build#0"}},
		CryptoOperations: []CryptoOperation{
			{Function: "net.crypto.(SSLContextBuilder).build#0", FindingID: "f-sink", RuleID: "rule.tls"},
		},
	}
	fg := onlyStitchedFinding(t, componentA, DependencyGraph{componentA: {componentC}},
		map[ComponentKey]Fragment{componentA: root, componentC: sink})
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("reachability = %q, reason = %q; want %q, %q",
			fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// ambiguousDispatchFixture is the root calling an interface method of a
// dependency that has two implementations there, one holding crypto.
func ambiguousDispatchFixture() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root := Fragment{
		Component: componentA,
		Functions: []Function{{Signature: "com.acme.app.(AppEntry).entry#0"}},
		ExternalCalls: []ExternalCall{{
			Caller: "com.acme.app.(AppEntry).entry#0", TargetSignature: "net.crypto.(Helper).create#0",
			TargetCanonicalSignature: "net.crypto.Helper.create()",
			Resolution:               ResolutionExact, MethodName: "create", CallSite: 10,
		}},
	}
	surface := "net.crypto.Helper.create()"
	dep := Fragment{
		Component: componentC,
		Functions: []Function{
			{Signature: "net.crypto.(Helper).create#0", FunctionName: "net.crypto.Helper.create", CanonicalSignature: surface},
			{Signature: "net.crypto.(JceHelper).create#0", FunctionName: "net.crypto.JceHelper.create", CanonicalSignature: "net.crypto.JceHelper.create()", CompatibleCanonicalSignatures: []string{surface}},
			{Signature: "net.crypto.(NamedHelper).create#0", FunctionName: "net.crypto.NamedHelper.create", CanonicalSignature: "net.crypto.NamedHelper.create()", CompatibleCanonicalSignatures: []string{surface}},
		},
		CryptoOperations: []CryptoOperation{
			{Function: "net.crypto.(JceHelper).create#0", FindingID: "f-jce", RuleID: "rule.cipher"},
		},
	}
	return componentA, DependencyGraph{componentA: {componentC}},
		map[ComponentKey]Fragment{componentA: root, componentC: dep}
}

func ambiguousFixtureReachability(t *testing.T, opts StitchOptions) string {
	t.Helper()
	root, deps, fragments := ambiguousDispatchFixture()
	res, err := StitchWithOptions(root, deps, fragments, opts)
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	for _, fg := range res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java"}).FindingGraphs {
		return fg.Reachability
	}
	return ""
}

// The fail-closed default does not cross an interface call site with two
// implementations; AmbiguousDispatchAsTyped crosses it to each, as the live
// tracer does.
func TestStitch_AmbiguousDispatchAsTyped(t *testing.T) {
	t.Parallel()
	if got := ambiguousFixtureReachability(t, StitchOptions{EntryRootedOnly: true}); got == ReachabilityReachable {
		t.Fatalf("default: reachability = %q, want not reachable", got)
	}
	if got := ambiguousFixtureReachability(t, StitchOptions{EntryRootedOnly: true, AmbiguousDispatchAsTyped: true}); got != ReachabilityReachable {
		t.Fatalf("AmbiguousDispatchAsTyped: reachability = %q, want %q", got, ReachabilityReachable)
	}
}

// AmbiguousDispatchUnknown serves the finding behind the two-implementation
// call site as unknown with ambiguous_dispatch, not reachable and not silently
// unreachable.
func TestStitch_AmbiguousDispatchUnknown(t *testing.T) {
	t.Parallel()
	root, deps, fragments := ambiguousDispatchFixture()
	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true, AmbiguousDispatchUnknown: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	fgs := res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java"}).FindingGraphs
	if len(fgs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(fgs))
	}
	if fgs[0].Reachability != ReachabilityUnknown || fgs[0].UnresolvedReason != UnresolvedReasonAmbiguousDispatch {
		t.Fatalf("reachability = %q, reason = %q; want %q, %q", fgs[0].Reachability, fgs[0].UnresolvedReason,
			ReachabilityUnknown, UnresolvedReasonAmbiguousDispatch)
	}
}
