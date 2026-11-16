// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

// instantiationVerdict stitches, with environment targets, a client whose
// calls are clientCalls over pyjwt, which declares RSAAlgorithm.sign (the
// finding), a subclass RSAPSSAlgorithm, a Factory whose make instantiates
// RSAAlgorithm, and jwt.<module> making jwtModuleCalls. imported adds the
// client's import of jwt.
func instantiationVerdict(t *testing.T, imported bool, jwtModuleCalls []ExternalCall, clientCalls ...ExternalCall) ExportFindingGraph {
	t.Helper()
	const sign = "jwt.algorithms.(RSAAlgorithm).sign"
	if imported {
		clientCalls = append(clientCalls, ExternalCall{Caller: "app.<module>", TargetSignature: "jwt.<module>", Resolution: ResolutionExact, MethodName: "<module>", CallSite: 1})
	}
	callers := map[string]bool{}
	var fns []Function
	for _, c := range clientCalls {
		if !callers[c.Caller] {
			callers[c.Caller] = true
			fns = append(fns, Function{Signature: c.Caller})
		}
	}
	for i := range jwtModuleCalls {
		jwtModuleCalls[i].Caller, jwtModuleCalls[i].CallSite = "jwt.<module>", 2
	}
	fragments := map[ComponentKey]Fragment{
		pyClient: {Component: pyClient, GraphAlgoVersion: GraphAlgoVersionPython, Functions: fns, ExternalCalls: clientCalls},
		pyJWT: {
			Component: pyJWT, GraphAlgoVersion: GraphAlgoVersionPython,
			Functions:  []Function{{Signature: "jwt.<module>"}, {Signature: sign}, {Signature: "jwt.factory.(Factory).make"}},
			Supertypes: map[string][]string{"jwt.algorithms.RSAPSSAlgorithm": {"jwt.algorithms.RSAAlgorithm"}},
			ExternalCalls: append(jwtModuleCalls, ExternalCall{
				Caller: "jwt.factory.(Factory).make", TargetSignature: "jwt.algorithms.RSAAlgorithm", Resolution: ResolutionExact, MethodName: "RSAAlgorithm", CallSite: 3,
			}),
			CryptoOperations: []CryptoOperation{{Function: sign, FindingID: "f", RuleID: "rule", FilePath: "x.py", StartLine: 1}},
		},
	}
	res, err := StitchWithOptions(pyClient, DependencyGraph{pyClient: {pyJWT}}, fragments,
		StitchOptions{EntryRootedOnly: true, ClasspathTargets: true, EnvironmentTargets: []string{"python"}, HierarchyFromSupertypes: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	graphs := res.ToCallgraphExport(pyClient, ScanMeta{Ecosystem: "python"}).FindingGraphs
	if len(graphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(graphs))
	}
	return graphs[0]
}

func untypedCall(caller, method string) ExternalCall {
	return ExternalCall{Caller: caller, TargetSignature: "app.(x)." + method, Resolution: ResolutionNameOnly, MethodName: method, CallSite: 5, ReceiverVar: "x"}
}

func exactCall(caller, target, method string) ExternalCall {
	return ExternalCall{Caller: caller, TargetSignature: target, Resolution: ResolutionExact, MethodName: method, CallSite: 6}
}

// A name_only candidate method of a class nothing the client reaches
// instantiates, calls through or hands around is not callable: the finding
// has no route. Any of those keeps it, unknown.
func TestStitch_PythonNameOnlyNeedsALiveClass(t *testing.T) {
	t.Parallel()
	sign := untypedCall("app.run", "sign")
	for _, c := range []struct {
		name     string
		imported bool
		jwt      []ExternalCall
		client   []ExternalCall
		live     bool
	}{
		{name: "nothing instantiates RSAAlgorithm", imported: true},
		{name: "the client instantiates it", imported: true, client: []ExternalCall{exactCall("app.run", "jwt.algorithms.RSAAlgorithm", "RSAAlgorithm")}, live: true},
		{name: "a typed call names it", imported: true, client: []ExternalCall{exactCall("app.run", "jwt.algorithms.(RSAAlgorithm).from_jwk", "from_jwk")}, live: true},
		{name: "jwt's top level instantiates a subclass", imported: true, jwt: []ExternalCall{exactCall("", "jwt.algorithms.(RSAPSSAlgorithm).<init>", "<init>")}, live: true},
		{name: "jwt's top level stores the class", imported: true, jwt: []ExternalCall{{TargetSignature: "jwt.algorithms.(RSAAlgorithm).<class>", Resolution: ResolutionNameOnly, MethodName: "<class>"}}, live: true},
		{name: "jwt's top level instantiates it but nothing imports jwt (a plugin)", jwt: []ExternalCall{exactCall("", "jwt.algorithms.RSAAlgorithm", "RSAAlgorithm")}, live: true},
		{name: "nothing imports jwt (a plugin)", live: true},
		{name: "a kept guess reaches the factory", imported: true, jwt: []ExternalCall{exactCall("", "jwt.factory.Factory", "Factory")}, client: []ExternalCall{untypedCall("app.run", "make")}, live: true},
		{name: "a guess reaches the factory nothing instantiates", imported: true, client: []ExternalCall{untypedCall("app.run", "make")}},
	} {
		fg := instantiationVerdict(t, c.imported, c.jwt, append(c.client, sign)...)
		live := fg.Reachability == ReachabilityUnknown && fg.UnresolvedReason == UnresolvedReasonDispatch
		if live != c.live || fg.Reachability == ReachabilityReachable {
			t.Errorf("%s: %q %q, want unknown %v", c.name, fg.Reachability, fg.UnresolvedReason, c.live)
		}
	}
}
