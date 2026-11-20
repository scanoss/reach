// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

// nodeLoadedVerdict stitches a Node application over the package acme and
// returns the verdict of the one finding, in acme's Signer.sign of
// lib/sign.js. The application's start calls acme's Client.connect of
// lib/client.js exactly and `x.sign()` on a receiver nothing typed, and
// makes appCalls; acmeLoads are the loads acme's functions make. signModule says whether
// lib/sign.js has a <module> function.
func nodeLoadedVerdict(t *testing.T, signModule bool, appCalls []ExternalCall, acmeLoads []InternalEdge) ExportFindingGraph {
	t.Helper()
	const (
		start   = "app/src/index.start"
		connect = "acme/lib/client.(Client).connect"
		sign    = "acme/lib/sign.(Signer).sign"
	)
	for i := range appCalls {
		appCalls[i].Caller = start
	}
	acme := []Function{
		{Signature: "acme/lib/client.<module>", FilePath: "lib/client.js"},
		{Signature: connect, FilePath: "lib/client.js"},
		{Signature: "acme/lib/client.(Client).open", FilePath: "lib/client.js"},
		{Signature: sign, FilePath: "lib/sign.js"},
	}
	if signModule {
		acme = append(acme, Function{Signature: "acme/lib/sign.<module>", FilePath: "lib/sign.js"})
	}
	fragments := map[ComponentKey]Fragment{
		untypedApp: {
			Component: untypedApp, GraphAlgoVersion: GraphAlgoVersionNode,
			Functions: []Function{{Signature: start, FilePath: "src/index.js"}},
			ExternalCalls: append([]ExternalCall{
				{Caller: start, TargetSignature: connect, Resolution: ResolutionExact, MethodName: "connect", CallSite: 3},
				{Caller: start, TargetSignature: "app/src/index.sign", Resolution: ResolutionNameOnly, MethodName: "sign", CallSite: 4},
			}, appCalls...),
		},
		untypedAcme: {
			Component: untypedAcme, GraphAlgoVersion: GraphAlgoVersionNode,
			Functions:        acme,
			InternalEdges:    acmeLoads,
			CryptoOperations: []CryptoOperation{{Function: sign, FindingID: "f", RuleID: "rule", FilePath: "lib/sign.js", StartLine: 1}},
		},
	}
	res, err := StitchWithOptions(untypedApp, DependencyGraph{untypedApp: {untypedAcme}}, fragments, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	graphs := res.ToCallgraphExport(untypedApp, ScanMeta{Ecosystem: "node"}).FindingGraphs
	if len(graphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(graphs))
	}
	return graphs[0]
}

func nodeLoads(caller, module string) InternalEdge {
	return InternalEdge{Caller: caller, Callee: module, Resolution: ResolutionExact, CallSite: 1}
}

// A method of a module nothing loads is no candidate of an untyped call:
// `x.sign()` cannot run acme's Signer.sign when no code the application
// reaches requires lib/sign.js. The guess itself does not load the module.
func TestStitch_NodeUntypedCallSkipsAModuleNothingLoads(t *testing.T) {
	t.Parallel()
	fg := nodeLoadedVerdict(t, true, nil, nil)
	if fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Fatalf("got %q %q, want no route and no reason", fg.Reachability, fg.UnresolvedReason)
	}
}

// The module is loaded by a function the application reaches (connect
// requires lib/sign.js): its method is a candidate again.
func TestStitch_NodeUntypedCallReachesALoadedModule(t *testing.T) {
	t.Parallel()
	fg := nodeLoadedVerdict(t, true, nil, []InternalEdge{nodeLoads("acme/lib/client.(Client).connect", "acme/lib/sign.<module>")})
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("got %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// Code reached only through a kept guess still loads what it requires:
// `x.open()` may run Client.open, of a module that is loaded, and open
// requires lib/sign.js.
func TestStitch_NodeUntypedCallReachesAModuleAGuessLoads(t *testing.T) {
	t.Parallel()
	fg := nodeLoadedVerdict(t, true,
		[]ExternalCall{nodeNameOnly("app/src/index.open", "open")},
		[]InternalEdge{nodeLoads("acme/lib/client.(Client).open", "acme/lib/sign.<module>")})
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("got %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// A module the fragment gives no <module> function leaves no load to
// follow, so its functions stay candidates.
func TestStitch_NodeUntypedCallKeepsAModuleWithNoTopLevel(t *testing.T) {
	t.Parallel()
	fg := nodeLoadedVerdict(t, false, nil, nil)
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("got %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}
