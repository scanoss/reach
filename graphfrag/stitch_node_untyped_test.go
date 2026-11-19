// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

var (
	untypedApp  = ComponentKey{Purl: "pkg:npm/app", Version: "1.0.0"}
	untypedAcme = ComponentKey{Purl: "pkg:npm/acme", Version: "2.0.0"}
)

// nodeUntypedVerdict stitches a Node application over the package acme and
// returns the verdict of the one finding, which sits in acme's function sink.
// The application's start calls acme's connect exactly, and makes appCalls;
// connect makes acmeCalls.
func nodeUntypedVerdict(t *testing.T, sink string, appCalls, acmeCalls []ExternalCall) ExportFindingGraph {
	t.Helper()
	const connect = "acme/lib/client.(Client).connect"
	for i := range appCalls {
		appCalls[i].Caller = "app/src/index.start"
	}
	for i := range acmeCalls {
		acmeCalls[i].Caller = connect
	}
	fragments := map[ComponentKey]Fragment{
		untypedApp: {
			Component: untypedApp, GraphAlgoVersion: GraphAlgoVersionNode,
			Functions: []Function{{Signature: "app/src/index.start"}, {Signature: "app/src/index.(Queue).push"}},
			ExternalCalls: append([]ExternalCall{{
				Caller: "app/src/index.start", TargetSignature: connect, Resolution: ResolutionExact, MethodName: "connect", CallSite: 3,
			}}, appCalls...),
		},
		untypedAcme: {
			Component: untypedAcme, GraphAlgoVersion: GraphAlgoVersionNode,
			Functions: []Function{
				{Signature: connect},
				{Signature: "acme/lib/cipher.(Aes).encrypt"},
				{Signature: "acme/lib/sign.(Signer).sign"},
				{Signature: "acme/lib/queue.(Queue).push"},
			},
			ExternalCalls:    acmeCalls,
			CryptoOperations: []CryptoOperation{{Function: sink, FindingID: "f", RuleID: "rule", FilePath: "lib/x.js", StartLine: 1}},
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

func nodeNameOnly(target, method string) ExternalCall {
	return ExternalCall{TargetSignature: target, Resolution: ResolutionNameOnly, MethodName: method, CallSite: 9}
}

// A member call inside a dependency that nothing typed
// (`this.cipher.encrypt(b)` on a field no source assigns a known value) can
// run the dependency's own method of that name: the finding in it reads
// unknown, not unreachable.
func TestStitch_NodeUntypedCallReachesItsOwnComponent(t *testing.T) {
	t.Parallel()
	fg := nodeUntypedVerdict(t, "acme/lib/cipher.(Aes).encrypt", nil, []ExternalCall{nodeNameOnly("acme/lib/client.encrypt", "encrypt")})
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("got %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// The application's own untyped call (`signer.sign(d)` on a parameter) can
// run a method of that name in a package it depends on.
func TestStitch_NodeUntypedCallReachesADependency(t *testing.T) {
	t.Parallel()
	fg := nodeUntypedVerdict(t, "acme/lib/sign.(Signer).sign", []ExternalCall{nodeNameOnly("app/src/index.sign", "sign")}, nil)
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("got %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// Without an untyped call of its name, a function nothing calls stays
// without a route: the name_only reading is of the calls made, not of every
// method.
func TestStitch_NodeUntypedCallOfAnotherNameReachesNothing(t *testing.T) {
	t.Parallel()
	fg := nodeUntypedVerdict(t, "acme/lib/sign.(Signer).sign", []ExternalCall{nodeNameOnly("app/src/index.verify", "verify")}, nil)
	if fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Fatalf("got %q %q, want no route and no reason", fg.Reachability, fg.UnresolvedReason)
	}
}

// A method name of a built-in value (`items.push(x)`) has candidates in the
// caller's own component only: the application's untyped push does not read
// a dependency's `push` as unknown, while the dependency's own does.
func TestStitch_NodeBuiltinMethodNameStaysInItsComponent(t *testing.T) {
	t.Parallel()
	const sink = "acme/lib/queue.(Queue).push"
	fg := nodeUntypedVerdict(t, sink, []ExternalCall{nodeNameOnly("app/src/index.push", "push")}, nil)
	if fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Fatalf("application push: %q %q, want no candidate", fg.Reachability, fg.UnresolvedReason)
	}
	fg = nodeUntypedVerdict(t, sink, nil, []ExternalCall{nodeNameOnly("acme/lib/client.push", "push")})
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("own push: %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// An exact route to the finding stands beside an untyped call of its name.
func TestStitch_NodeExactRouteWinsOverUntypedCall(t *testing.T) {
	t.Parallel()
	const sink = "acme/lib/sign.(Signer).sign"
	fg := nodeUntypedVerdict(t, sink, []ExternalCall{
		{TargetSignature: sink, Resolution: ResolutionExact, MethodName: "sign", CallSite: 5},
		nodeNameOnly("app/src/index.sign", "sign"),
	}, nil)
	if fg.Reachability != ReachabilityReachable {
		t.Fatalf("got %q %q, want %q", fg.Reachability, fg.UnresolvedReason, ReachabilityReachable)
	}
}

// An exact call into a dependency that no function or export of it
// resolves (`acme.(Signer).sign` on a class the package exports through a
// value it builds) runs some code of acme the fragments do not name: acme's
// functions of the called name read unknown, not unreachable.
func TestStitch_NodeUnresolvedCallIntoADependency(t *testing.T) {
	t.Parallel()
	exact := func(target, method string) ExternalCall {
		return ExternalCall{TargetSignature: target, Resolution: ResolutionExact, MethodName: method, CallSite: 7}
	}
	fg := nodeUntypedVerdict(t, "acme/lib/sign.(Signer).sign", []ExternalCall{exact("acme.(Signer).sign", "sign")}, nil)
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("into acme: %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
	// A module of the runtime is no dependency: its call names no candidate.
	fg = nodeUntypedVerdict(t, "acme/lib/sign.(Signer).sign", []ExternalCall{exact("crypto.sign", "sign")}, nil)
	if fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Fatalf("into crypto: %q %q, want no route and no reason", fg.Reachability, fg.UnresolvedReason)
	}
}
