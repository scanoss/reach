// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

var pyUrllib3 = ComponentKey{Purl: "pkg:pypi/urllib3", Version: "2.3.0"}

// pythonHierarchyFixture is PyGithub's GithubRetry: a client class whose base
// it names by urllib3's public path (`class GithubRetry(urllib3.Retry)`),
// while urllib3 declares the class at `urllib3.util.retry.Retry` and exports
// it. Retry declares `__init__` and `sleep`; the method sink holds a finding.
func pythonHierarchyFixture(sink string, calls ...ExternalCall) (DependencyGraph, map[ComponentKey]Fragment) {
	const retry = "urllib3.util.retry.(Retry)."
	fns := []Function{{Signature: retry + "<init>"}, {Signature: retry + "sleep"}}
	ops := []CryptoOperation{{Function: retry + sink, FindingID: "f", RuleID: "rule", FilePath: "urllib3/util/retry.py", StartLine: 1}}
	return DependencyGraph{pyClient: {pyUrllib3}}, map[ComponentKey]Fragment{
		pyClient: {
			Component: pyClient, GraphAlgoVersion: GraphAlgoVersionPython,
			Functions:     []Function{{Signature: "github.Requester.(Requester).retry"}},
			ExternalCalls: calls,
			Supertypes:    map[string][]string{"github.GithubRetry.GithubRetry": {"urllib3.Retry"}},
		},
		pyUrllib3: {
			Component: pyUrllib3, GraphAlgoVersion: GraphAlgoVersionPython,
			Functions:        fns,
			CryptoOperations: ops,
			Exports:          map[string]string{"urllib3.Retry": "urllib3.util.retry.(Retry)"},
		},
	}
}

// pythonHierarchyVerdicts is the reachability of a finding in each method of
// Retry, stitched one at a time.
func pythonHierarchyVerdicts(t *testing.T, calls ...ExternalCall) map[string]string {
	t.Helper()
	out := make(map[string]string)
	for _, sink := range []string{"<init>", "sleep"} {
		out["rule."+sink] = pythonHierarchyVerdict(t, sink, calls...)
	}
	return out
}

func pythonHierarchyVerdict(t *testing.T, sink string, calls ...ExternalCall) string {
	t.Helper()
	deps, fragments := pythonHierarchyFixture(sink, calls...)
	res, err := StitchWithOptions(pyClient, deps, fragments, StitchOptions{
		EntryRootedOnly: true, ClasspathTargets: true, HierarchyFromSupertypes: true,
	})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	graphs := res.ToCallgraphExport(pyClient, ScanMeta{Ecosystem: "python"}).FindingGraphs
	if len(graphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(graphs))
	}
	return graphs[0].Reachability
}

func clientCall(target, method string) ExternalCall {
	return ExternalCall{Caller: "github.Requester.(Requester).retry", TargetSignature: target, Resolution: ResolutionExact, MethodName: method, CallSite: 7}
}

// A method the client class only inherits resolves through its base, which
// the client names by the dependency's public path: the MRO walks into the
// dependency.
func TestStitch_PythonMROIntoDependencyThroughPublicBase(t *testing.T) {
	t.Parallel()
	got := pythonHierarchyVerdicts(t, clientCall("github.GithubRetry.(GithubRetry).sleep", "sleep"))
	if got["rule.sleep"] != ReachabilityReachable || got["rule.<init>"] == ReachabilityReachable {
		t.Fatalf("verdicts %v, want sleep reachable and <init> not", got)
	}
}

// Instantiating a client class with no `__init__` of its own runs the one it
// inherits from the dependency: the producer has no in-graph `__init__` to
// link, so the stitch links the call of the class to it.
func TestStitch_PythonInstantiationRunsInheritedDependencyInit(t *testing.T) {
	t.Parallel()
	got := pythonHierarchyVerdicts(t, clientCall("github.GithubRetry.GithubRetry", "GithubRetry"))
	if got["rule.<init>"] != ReachabilityReachable || got["rule.sleep"] == ReachabilityReachable {
		t.Fatalf("verdicts %v, want <init> reachable and sleep not", got)
	}
}

// Instantiating the dependency's class through its public path runs its
// `__init__`.
func TestStitch_PythonInstantiationOfExportedClass(t *testing.T) {
	t.Parallel()
	got := pythonHierarchyVerdicts(t, clientCall("urllib3.Retry", "Retry"))
	if got["rule.<init>"] != ReachabilityReachable {
		t.Fatalf("verdicts %v, want <init> reachable", got)
	}
}
