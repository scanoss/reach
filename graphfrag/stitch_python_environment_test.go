// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

var pyCryptography = ComponentKey{Purl: "pkg:pypi/cryptography", Version: "44.0.2"}

// pythonEnvironmentFixture is a Python client calling pyjwt, whose call into
// cryptography (resolution) no requires edge covers: pyjwt pulls cryptography
// in only with its `crypto` extra, and a lock without edges (Pipfile.lock)
// attributes it to nobody. cryptography still hangs from the client, so it is
// in the environment. algo is the graph algorithm id of pyjwt's fragment.
func pythonEnvironmentFixture(resolution ResolutionKind, algo string) (DependencyGraph, map[ComponentKey]Fragment) {
	const sink = "cryptography.hazmat.primitives.asymmetric.(RSAPrivateKey).sign"
	return DependencyGraph{pyClient: {pyJWT, pyCryptography}}, map[ComponentKey]Fragment{
		pyClient: {
			Component: pyClient, GraphAlgoVersion: GraphAlgoVersionPython,
			Functions: []Function{{Signature: "app.main.handle"}},
			ExternalCalls: []ExternalCall{{
				Caller: "app.main.handle", TargetSignature: "jwt.algorithms.(RSAAlgorithm).sign",
				Resolution: ResolutionExact, MethodName: "sign", CallSite: 3,
			}},
		},
		pyJWT: {
			Component: pyJWT, GraphAlgoVersion: algo,
			Functions: []Function{{Signature: "jwt.algorithms.(RSAAlgorithm).sign"}},
			ExternalCalls: []ExternalCall{{
				Caller: "jwt.algorithms.(RSAAlgorithm).sign", TargetSignature: sink,
				Resolution: resolution, MethodName: "sign", CallSite: 9,
			}},
		},
		pyCryptography: {
			Component: pyCryptography, GraphAlgoVersion: GraphAlgoVersionPython,
			Functions: []Function{{Signature: sink}},
			CryptoOperations: []CryptoOperation{
				{Function: sink, FindingID: "f-rsa", RuleID: "rule.rsa", FilePath: "cryptography/rsa.py", StartLine: 1},
			},
		},
	}
}

func environmentVerdict(t *testing.T, deps DependencyGraph, fragments map[ComponentKey]Fragment, ecosystems []string) ExportFindingGraph {
	t.Helper()
	res, err := StitchWithOptions(pyClient, deps, fragments, StitchOptions{
		EntryRootedOnly: true, ClasspathTargets: true, EnvironmentTargets: ecosystems,
	})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	cg := res.ToCallgraphExport(pyClient, ScanMeta{Ecosystem: "python"})
	if len(cg.FindingGraphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(cg.FindingGraphs))
	}
	return cg.FindingGraphs[0]
}

// A Python dependency's call into a component of the environment that its
// requires do not name resolves there: the client reaches cryptography's
// finding through pyjwt. Without the option the call is one into a
// dependency's module the stitch could not resolve, and reads unknown.
func TestStitch_PythonEnvironmentTargets(t *testing.T) {
	t.Parallel()
	deps, fragments := pythonEnvironmentFixture(ResolutionExact, GraphAlgoVersionPython)
	if fg := environmentVerdict(t, deps, fragments, nil); fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("declared targets only: %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
	if fg := environmentVerdict(t, deps, fragments, []string{"python"}); fg.Reachability != ReachabilityReachable {
		t.Fatalf("environment targets: %q, want %q", fg.Reachability, ReachabilityReachable)
	}
}

// The option names ecosystems: a component of another one (a Java graph id on
// the same shape) keeps its declared targets.
func TestStitch_EnvironmentTargetsOnlyForNamedEcosystems(t *testing.T) {
	t.Parallel()
	deps, fragments := pythonEnvironmentFixture(ResolutionExact, GraphAlgoVersion)
	jvm := fragments[pyJWT]
	jvm.Component = ComponentKey{Purl: "pkg:maven/io.jsonwebtoken/jjwt", Version: "0.12.6"}
	delete(fragments, pyJWT)
	fragments[jvm.Component] = jvm
	deps[pyClient][0] = jvm.Component
	if fg := environmentVerdict(t, deps, fragments, []string{"python"}); fg.Reachability != ReachabilityUnreachable {
		t.Fatalf("java component: %q, want %q", fg.Reachability, ReachabilityUnreachable)
	}
}

// A Python name_only call has no receiver type to tie it to its requires:
// its value may come from any installed package, so under environment
// targets its candidates are the whole environment's functions of its name.
// Without them it keeps its declared dependencies, here none.
func TestStitch_PythonEnvironmentNameOnlyWidens(t *testing.T) {
	t.Parallel()
	deps, fragments := pythonEnvironmentFixture(ResolutionNameOnly, GraphAlgoVersionPython)
	fg := environmentVerdict(t, deps, fragments, nil)
	if fg.Reachability == ReachabilityReachable || fg.UnresolvedReason == UnresolvedReasonDispatch {
		t.Fatalf("declared targets: %q %q, want no candidate", fg.Reachability, fg.UnresolvedReason)
	}
	fg = environmentVerdict(t, deps, fragments, []string{"python"})
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("environment targets: %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}
