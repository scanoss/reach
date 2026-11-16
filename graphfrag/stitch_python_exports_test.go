// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

var pyOther = ComponentKey{Purl: "pkg:pypi/other", Version: "1.0.0"}

// pythonPublicCallFinding stitches a Python client calling target (exact)
// into a dependency fragment dep whose function sinkKey holds crypto, and
// returns the finding.
func pythonPublicCallFinding(t *testing.T, target string, resolution ResolutionKind, dep Fragment, sinkKey string, deps DependencyGraph, extra ...Fragment) ExportFindingGraph {
	t.Helper()
	client := Fragment{
		Component: pyClient,
		Functions: []Function{{Signature: "app.main.handle"}},
		ExternalCalls: []ExternalCall{{
			Caller: "app.main.handle", TargetSignature: target, Resolution: resolution, MethodName: "encode", Arity: 2, CallSite: 3,
		}},
	}
	dep.CryptoOperations = []CryptoOperation{{Function: sinkKey, FindingID: "f-1", RuleID: "rule.hmac"}}
	fragments := map[ComponentKey]Fragment{pyClient: client, dep.Component: dep}
	for _, f := range extra {
		fragments[f.Component] = f
	}
	res, err := StitchWithOptions(pyClient, deps, fragments, StitchOptions{EntryRootedOnly: true, HierarchyFromSupertypes: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	cg := res.ToCallgraphExport(pyClient, ScanMeta{Ecosystem: "python"})
	if len(cg.FindingGraphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(cg.FindingGraphs))
	}
	return cg.FindingGraphs[0]
}

func pythonFragment(component ComponentKey, exports map[string]string, keys ...string) Fragment {
	f := Fragment{Component: component, GraphAlgoVersion: GraphAlgoVersionPython, Exports: exports}
	for _, key := range keys {
		f.Functions = append(f.Functions, Function{Signature: key})
	}
	return f
}

// A client's exact call of a dependency's public name joins the declaration
// the dependency's exports give it: a function at a public path, a method of
// a class at a public path, an instantiation of a class at a public path (its
// __init__, or the one it inherits), and an instantiation of a Python class
// at its own path. Without the export the call reaches nothing.
func TestStitch_PythonCallJoinsThroughExports(t *testing.T) {
	t.Parallel()
	direct := DependencyGraph{pyClient: {pyJWT}}
	tests := []struct {
		name, target, sink string
		dep                Fragment
	}{
		{"function at a public path", "jwt.encode", "jwt.api_jwt.(PyJWT).encode",
			pythonFragment(pyJWT, map[string]string{"jwt.encode": "jwt.api_jwt.(PyJWT).encode"}, "jwt.api_jwt.(PyJWT).encode")},
		{"method of a class at a public path", "jwt.(PyJWT).encode", "jwt.api_jwt.(PyJWT).encode",
			pythonFragment(pyJWT, map[string]string{"jwt.PyJWT": "jwt.api_jwt.(PyJWT)"}, "jwt.api_jwt.(PyJWT).encode")},
		{"instantiation of a class at a public path", "jwt.PyJWT", "jwt.api_jwt.(PyJWT).<init>",
			pythonFragment(pyJWT, map[string]string{"jwt.PyJWT": "jwt.api_jwt.(PyJWT)"}, "jwt.api_jwt.(PyJWT).<init>")},
		{"instantiation of a class at its own path", "jwt.api_jwt.PyJWT", "jwt.api_jwt.(PyJWT).<init>",
			pythonFragment(pyJWT, nil, "jwt.api_jwt.(PyJWT).<init>")},
		{"instantiation of a class that inherits __init__", "jwt.Sub", "jwt.base.(Base).<init>",
			func() Fragment {
				f := pythonFragment(pyJWT, map[string]string{"jwt.Sub": "jwt.sub.(Sub)"}, "jwt.base.(Base).<init>", "jwt.sub.(Sub).run")
				f.Supertypes = map[string][]string{"jwt.sub.Sub": {"jwt.base.Base"}, "jwt.base.Base": {}}
				return f
			}()},
	}
	for _, tc := range tests {
		fg := pythonPublicCallFinding(t, tc.target, ResolutionExact, tc.dep, tc.sink, direct)
		if fg.Reachability != ReachabilityReachable {
			t.Errorf("%s: reachability %q, want reachable", tc.name, fg.Reachability)
		}
		bare := tc.dep
		bare.Exports, bare.Supertypes = nil, nil
		bare.GraphAlgoVersion = GraphAlgoVersion
		if fg := pythonPublicCallFinding(t, tc.target, ResolutionExact, bare, tc.sink, direct); fg.Reachability == ReachabilityReachable {
			t.Errorf("%s: reachable without exports", tc.name)
		}
	}
}

// Exports join only the caller's dependencies, in the component that
// exports, only typed calls (a name_only call stays a candidate, never a
// route), and only a class's methods: a public path naming a function joins
// no method spelled under it.
func TestStitch_PythonExportsBounds(t *testing.T) {
	t.Parallel()
	const sink = "jwt.api_jwt.(PyJWT).encode"
	dep := pythonFragment(pyJWT, map[string]string{"jwt.encode": sink, "jwt.PyJWT": "jwt.api_jwt.(PyJWT)"}, sink)

	notDirect := DependencyGraph{pyClient: {pyOther}, pyOther: {pyJWT}}
	for _, target := range []string{"jwt.encode", "jwt.(PyJWT).encode"} {
		if fg := pythonPublicCallFinding(t, target, ResolutionExact, dep, sink, notDirect, pythonFragment(pyOther, nil, "other.f")); fg.Reachability == ReachabilityReachable {
			t.Errorf("%s: an export of a component the client does not depend on joined its call", target)
		}
	}
	// pyOther declares the same key; pyJWT's export names pyJWT's.
	exporter := pythonFragment(pyJWT, map[string]string{"jwt.encode": sink}, sink)
	if fg := pythonPublicCallFinding(t, "jwt.encode", ResolutionExact, pythonFragment(pyOther, nil, sink), sink, DependencyGraph{pyClient: {pyJWT, pyOther}}, exporter); fg.Reachability == ReachabilityReachable {
		t.Error("an export joined another component's declaration of the same key")
	}
	if fg := pythonPublicCallFinding(t, "jwt.encode", ResolutionNameOnly, dep, sink, DependencyGraph{pyClient: {pyJWT}}); fg.Reachability == ReachabilityReachable {
		t.Error("a name_only call joined through an export")
	}
	if fg := pythonPublicCallFinding(t, "jwt.(encode).encode", ResolutionExact, dep, sink, DependencyGraph{pyClient: {pyJWT}}); fg.Reachability == ReachabilityReachable {
		t.Error("a method under a function's public path joined")
	}
}

// A Python class is indexed once at its own path, however many methods it
// has; a function without a class is not a class path.
func TestIndexPythonPublicNames_OneEntryPerClass(t *testing.T) {
	t.Parallel()
	frag := pythonFragment(pyJWT, nil, "jwt.api_jwt.(PyJWT).encode", "jwt.api_jwt.(PyJWT).decode", "jwt.api_jwt.helper")
	index := indexPythonPublicNames([]ComponentKey{pyJWT}, map[ComponentKey]Fragment{pyJWT: frag})
	if got := index["jwt.api_jwt.PyJWT"]; len(got) != 1 || got[0].decl != "jwt.api_jwt.(PyJWT)" {
		t.Fatalf("class entries %+v", got)
	}
	if len(index) != 1 {
		t.Fatalf("index %+v, want the class alone", index)
	}
}
