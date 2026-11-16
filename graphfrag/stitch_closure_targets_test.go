// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

// closureTargetsFixture is a project (A) calling a library (B) whose call into
// the crypto library C the dependency tree leaves out (B's dependencies are
// bDeps), as a Maven tree does when the project declares C itself. A also
// depends on E, which holds a function of the same signature with its own
// operation. resolution is the kind of B's call.
func closureTargetsFixture(bDeps []ComponentKey, resolution ResolutionKind) (DependencyGraph, map[ComponentKey]Fragment) {
	const sink = "net.crypto.(Sink).encrypt#0"
	fragments := map[ComponentKey]Fragment{
		componentA: {
			Component: componentA,
			Functions: []Function{{Signature: "app.(Main).run#0"}},
			ExternalCalls: []ExternalCall{{
				Caller: "app.(Main).run#0", TargetSignature: "pix.(User).use#0",
				Resolution: ResolutionExact, MethodName: "use", CallSite: 3,
			}},
		},
		componentB: {
			Component: componentB,
			Functions: []Function{{Signature: "pix.(User).use#0"}},
			ExternalCalls: []ExternalCall{{
				Caller: "pix.(User).use#0", TargetSignature: sink,
				Resolution: resolution, MethodName: "encrypt", CallSite: 5,
			}},
		},
		componentC: {
			Component:        componentC,
			Functions:        []Function{{Signature: sink}},
			CryptoOperations: []CryptoOperation{{Function: sink, FindingID: "f-c", RuleID: "rule.aes", FilePath: "C.java", StartLine: 1}},
		},
		componentE: {
			Component:        componentE,
			Functions:        []Function{{Signature: sink}},
			CryptoOperations: []CryptoOperation{{Function: sink, FindingID: "f-e", RuleID: "rule.aes", FilePath: "E.java", StartLine: 1}},
		},
	}
	return DependencyGraph{componentA: {componentB, componentC, componentE}, componentB: bDeps}, fragments
}

// closureTargetVerdicts stitches on the serving path and returns the
// reachability of C's finding and of E's.
func closureTargetVerdicts(t *testing.T, deps DependencyGraph, fragments map[ComponentKey]Fragment, closureTargets bool) (c, e string) {
	t.Helper()
	res, err := StitchWithOptions(componentA, deps, fragments, StitchOptions{
		EntryRootedOnly: true, ClasspathTargets: true, ClosureTargets: closureTargets,
	})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	byPurl := make(map[string]string)
	for _, fg := range res.ToCallgraphExport(componentA, ScanMeta{Ecosystem: "java"}).FindingGraphs {
		byPurl[fg.Dependency.PURL] = fg.Reachability
	}
	return byPurl[componentC.Purl+"@"+componentC.Version], byPurl[componentE.Purl+"@"+componentE.Version]
}

// A call the dependency tree leaves without a target resolves against the
// rest of the closure: the project reaches C through B.
func TestStitch_ClosureTargetsResolveAnOmittedEdge(t *testing.T) {
	t.Parallel()
	deps, fragments := closureTargetsFixture(nil, ResolutionExact)
	delete(fragments, componentE)
	deps[componentA] = deps[componentA][:2]
	if c, _ := closureTargetVerdicts(t, deps, fragments, false); c != ReachabilityUnreachable {
		t.Fatalf("without closure targets: C = %q, want %q", c, ReachabilityUnreachable)
	}
	if c, _ := closureTargetVerdicts(t, deps, fragments, true); c != ReachabilityReachable {
		t.Fatalf("with closure targets: C = %q, want %q", c, ReachabilityReachable)
	}
}

// A call the declared dependencies resolve keeps its target: E's function of
// the same signature is not reached.
func TestStitch_ClosureTargetsPreferDeclaredDependencies(t *testing.T) {
	t.Parallel()
	deps, fragments := closureTargetsFixture([]ComponentKey{componentC}, ResolutionExact)
	if c, e := closureTargetVerdicts(t, deps, fragments, true); c != ReachabilityReachable || e != ReachabilityUnreachable {
		t.Fatalf("C = %q, E = %q; want %q, %q", c, e, ReachabilityReachable, ReachabilityUnreachable)
	}
}

// A name-only call never widens: the stitch serves what it serves without
// closure targets.
func TestStitch_ClosureTargetsNeverWidenNameOnlyCalls(t *testing.T) {
	t.Parallel()
	deps, fragments := closureTargetsFixture(nil, ResolutionNameOnly)
	c0, e0 := closureTargetVerdicts(t, deps, fragments, false)
	if c, e := closureTargetVerdicts(t, deps, fragments, true); c != c0 || e != e0 {
		t.Fatalf("C = %q, E = %q; want %q, %q as without closure targets", c, e, c0, e0)
	}
}

// When several components of the closure hold the omitted target, the call
// gets the verdicts it gets when B declares them all: widening never changes
// the stitch's dispatch policy.
func TestStitch_ClosureTargetsKeepTheDispatchPolicy(t *testing.T) {
	t.Parallel()
	deps, fragments := closureTargetsFixture([]ComponentKey{componentC, componentE}, ResolutionExact)
	c0, e0 := closureTargetVerdicts(t, deps, fragments, false)
	deps, fragments = closureTargetsFixture(nil, ResolutionExact)
	if c, e := closureTargetVerdicts(t, deps, fragments, true); c != c0 || e != e0 {
		t.Fatalf("C = %q, E = %q; want %q, %q as when B declares both", c, e, c0, e0)
	}
}
