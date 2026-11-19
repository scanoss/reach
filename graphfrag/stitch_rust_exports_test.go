// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

var (
	rustApp  = ComponentKey{Purl: "pkg:cargo/app", Version: "1.0.0"}
	rustSign = ComponentKey{Purl: "pkg:cargo/acme-sign", Version: "1.0.0"}
)

// rustExportCallFinding stitches an application whose main calls target
// (exact, as the client keys it) into acme-sign, whose function sink holds the
// finding and whose fragment carries exports, and returns the finding.
func rustExportCallFinding(t *testing.T, target, sink string, exports map[string]string) ExportFindingGraph {
	t.Helper()
	app := Fragment{
		Component:        rustApp,
		GraphAlgoVersion: GraphAlgoVersionRust,
		Functions:        []Function{{Signature: "app.main"}},
		ExternalCalls: []ExternalCall{{
			Caller: "app.main", TargetSignature: target, Resolution: ResolutionExact, MethodName: "sign", CallSite: 3,
		}},
		EntryKinds: map[string]string{"app.main": RootKindMain},
	}
	dep := Fragment{
		Component:        rustSign,
		Module:           "acme_sign",
		GraphAlgoVersion: GraphAlgoVersionRust,
		Functions:        []Function{{Signature: sink}, {Signature: "acme_sign::sig.other"}},
		Exports:          exports,
		CryptoOperations: []CryptoOperation{{Function: sink, FindingID: "f-1", RuleID: "rule.sign"}},
	}
	res, err := StitchWithOptions(rustApp, DependencyGraph{rustApp: {rustSign}},
		map[ComponentKey]Fragment{rustApp: app, rustSign: dep}, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	cg := res.ToCallgraphExport(rustApp, ScanMeta{Ecosystem: "rust"})
	if len(cg.FindingGraphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(cg.FindingGraphs))
	}
	return cg.FindingGraphs[0]
}

// A consumer calls a crate by the paths its `pub use` items and modules give
// (callgraph.CallGraph.RustExports): a re-exported function, a method of a
// re-exported type, a re-export renamed with `as`, and a function through an
// imported module (`use acme_sign::sig; sig::sign(..)`). Each joins the
// declaration the crate's exports name; without them nothing is reached.
func TestStitch_RustCallJoinsThroughExports(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, target, sink string
		exports            map[string]string
	}{
		{"re-exported function", "acme_sign.sign", "acme_sign::sig::imp.sign",
			map[string]string{"acme_sign.sign": "acme_sign::sig::imp.sign"}},
		{"method of a re-exported type", "acme_sign.(Signer).new", "acme_sign::sig.(Signer).new",
			map[string]string{"acme_sign.Signer": "acme_sign::sig.(Signer)"}},
		{"renamed re-export", "acme_sign.(Digest).new", "acme_sign::inner.(Hasher).new",
			map[string]string{"acme_sign.Digest": "acme_sign::inner.(Hasher)"}},
		{"function through an imported module", "acme_sign.(sig).sign", "acme_sign::sig.sign",
			map[string]string{"acme_sign.sig": "acme_sign::sig"}},
	}
	for _, tc := range tests {
		if fg := rustExportCallFinding(t, tc.target, tc.sink, tc.exports); fg.Reachability != ReachabilityReachable {
			t.Errorf("%s: reachability %q, want reachable", tc.name, fg.Reachability)
		}
		if fg := rustExportCallFinding(t, tc.target, tc.sink, nil); fg.Reachability == ReachabilityReachable {
			t.Errorf("%s: reachable without exports", tc.name)
		}
	}
}

// A crate re-exports another crate's type (`pub use acme_rng::OsRng;` in
// acme-sign): its export names the declaration as acme-rng keys it, and
// acme-rng's own exports lead to the module that declares it. A consumer's
// call through acme-sign's path reaches acme-rng's method.
func TestStitch_RustCallJoinsThroughAnotherCratesReExport(t *testing.T) {
	t.Parallel()
	rng := ComponentKey{Purl: "pkg:cargo/acme-rng", Version: "1.0.0"}
	sink := "acme_rng::os.(OsRng).fill_bytes"
	stitch := func(signExports map[string]string) ExportFindingGraph {
		app := Fragment{
			Component:        rustApp,
			GraphAlgoVersion: GraphAlgoVersionRust,
			Functions:        []Function{{Signature: "app.main"}},
			ExternalCalls: []ExternalCall{{
				Caller: "app.main", TargetSignature: "acme_sign.(OsRng).fill_bytes", Resolution: ResolutionExact, MethodName: "fill_bytes", CallSite: 3,
			}},
			EntryKinds: map[string]string{"app.main": RootKindMain},
		}
		sign := Fragment{
			Component: rustSign, Module: "acme_sign", GraphAlgoVersion: GraphAlgoVersionRust,
			Functions: []Function{{Signature: "acme_sign.other"}},
			Exports:   signExports,
		}
		rngFrag := Fragment{
			Component: rng, Module: "acme_rng", GraphAlgoVersion: GraphAlgoVersionRust,
			Functions:        []Function{{Signature: sink}},
			Exports:          map[string]string{"acme_rng.OsRng": "acme_rng::os.(OsRng)"},
			CryptoOperations: []CryptoOperation{{Function: sink, FindingID: "f-1", RuleID: "rule.rng"}},
		}
		res, err := StitchWithOptions(rustApp, DependencyGraph{rustApp: {rustSign}, rustSign: {rng}},
			map[ComponentKey]Fragment{rustApp: app, rustSign: sign, rng: rngFrag}, StitchOptions{EntryRootedOnly: true})
		if err != nil {
			t.Fatalf("stitch: %v", err)
		}
		cg := res.ToCallgraphExport(rustApp, ScanMeta{Ecosystem: "rust"})
		if len(cg.FindingGraphs) != 1 {
			t.Fatalf("finding graphs = %d, want 1", len(cg.FindingGraphs))
		}
		return cg.FindingGraphs[0]
	}
	if fg := stitch(map[string]string{"acme_sign.OsRng": "acme_rng.(OsRng)"}); fg.Reachability != ReachabilityReachable {
		t.Errorf("reachability %q, want reachable", fg.Reachability)
	}
	if fg := stitch(nil); fg.Reachability == ReachabilityReachable {
		t.Errorf("reachable without acme-sign's export")
	}
}
