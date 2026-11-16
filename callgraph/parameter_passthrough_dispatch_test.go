// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"
	"testing"
)

// TestResolveParameterPassthroughDispatch_ConstructorArgumentDisambiguates is
// the minimal reproduction of the password4j withPBKDF2 shape: a factory
// method (viaImplA) constructs a concrete SinkImplA and passes it, in one
// statement, to with(Sink), whose ENTIRE body immediately dispatches on that
// parameter (s.run()) — an interface call site that is genuinely ambiguous
// judged in isolation (2 concrete Sink implementors in the graph), but
// resolvable for viaImplA's specific call because it supplies a
// constructor-known concrete type.
//
// Asserts: a new direct edge viaImplA -> SinkImplA.run is recorded as exact
// and carries ResolvedReceiverType "SinkImplA" — the fragment exporter reads
// this to stamp graph-fragment resolved_receiver_type (see
// internal/scan/fragment_export_resolved_receiver_test.go), which the
// stitcher then uses to disambiguate (see
// graphfrag/stitch_receiver_provenance_test.go).
// buildConstructorArgFixtureGraph builds the shared constructor-argument
// disambiguation fixture (interface Sink with two implementors, a
// pass-through Builder.with(Sink), and a caller passing new SinkImplA()).
// The passthrough pass runs inside BuildFromDirectories.
func buildConstructorArgFixtureGraph(t *testing.T) *CallGraph {
	t.Helper()
	root := t.TempDir()

	sinkID := FunctionID{Package: "com.acme", Type: "Sink", Name: "run#0"}
	implAID := FunctionID{Package: "com.acme", Type: "SinkImplA", Name: "run#0"}
	implBID := FunctionID{Package: "com.acme", Type: "SinkImplB", Name: "run#0"}
	withID := FunctionID{Package: "com.acme", Type: "Builder", Name: "with#1"}
	viaAID := FunctionID{Package: "com.acme", Type: "Builder", Name: "viaImplA#0"}

	sinkIface := FunctionDecl{
		ID: sinkID, FilePath: filepath.Join(root, "Sink.java"), StartLine: 1, EndLine: 2,
		OwnerType: ownerTypeInterface, OwnerName: "Sink", Parameters: []FunctionParameter{},
	}
	implA := FunctionDecl{
		ID: implAID, FilePath: filepath.Join(root, "SinkImplA.java"), StartLine: 1, EndLine: 4,
		OwnerType: ownerTypeClass, OwnerName: "SinkImplA", Parameters: []FunctionParameter{},
		OwnerBases: []string{"Sink"},
	}
	implB := FunctionDecl{
		ID: implBID, FilePath: filepath.Join(root, "SinkImplB.java"), StartLine: 1, EndLine: 4,
		OwnerType: ownerTypeClass, OwnerName: "SinkImplB", Parameters: []FunctionParameter{},
		OwnerBases: []string{"Sink"},
	}
	// with(Sink s) { s.run(); } — the pass-through candidate: a single call
	// whose ReceiverVar ("s") names its own only parameter.
	withFn := FunctionDecl{
		ID: withID, FilePath: filepath.Join(root, "Builder.java"), StartLine: 10, EndLine: 12,
		OwnerType: ownerTypeClass, OwnerName: "Builder",
		Parameters: []FunctionParameter{{Type: "Sink", Name: "s"}},
		Calls: []FunctionCall{
			{Callee: sinkID, ReceiverVar: "s", FilePath: filepath.Join(root, "Builder.java"), Line: 11, Raw: "s.run()"},
		},
	}
	// viaImplA() { with(new SinkImplA()); } — passes a constructor-known
	// concrete type as the ambiguous call's ultimate receiver.
	viaA := FunctionDecl{
		ID: viaAID, FilePath: filepath.Join(root, "Builder.java"), StartLine: 20, EndLine: 22,
		OwnerType: ownerTypeClass, OwnerName: "Builder",
		Calls: []FunctionCall{
			{
				Callee:    withID,
				Arguments: []string{"new SinkImplA()"},
				ArgumentSources: [][]SourceNode{
					{
						{
							Type:         sourceNodeCallResult,
							CallTarget:   &FunctionID{Package: "com.acme", Type: "SinkImplA", Name: "<init>#0"},
							DeclaredType: "SinkImplA",
						},
					},
				},
				FilePath: filepath.Join(root, "Builder.java"),
				Line:     21,
				Raw:      "with(new SinkImplA())",
			},
		},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {{Functions: []FunctionDecl{sinkIface, implA, implB, withFn, viaA}}},
		},
	}

	graph, err := NewBuilder(parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "com.acme"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

func TestResolveParameterPassthroughDispatch_ConstructorArgumentDisambiguates(t *testing.T) {
	graph := buildConstructorArgFixtureGraph(t)
	sinkImplAID := FunctionID{Package: "com.acme", Type: "SinkImplA", Name: "run#0"}
	sinkImplBID := FunctionID{Package: "com.acme", Type: "SinkImplB", Name: "run#0"}
	builderWithID := FunctionID{Package: "com.acme", Type: "Builder", Name: "with#1"}
	builderViaAID := FunctionID{Package: "com.acme", Type: "Builder", Name: "viaImplA#0"}
	withID, implAID, implBID, viaAID := builderWithID, sinkImplAID, sinkImplBID, builderViaAID

	// Precondition: the with() call site is genuinely ambiguous in isolation —
	// both SinkImplA.run and SinkImplB.run are candidates.
	ambiguousKey := dispatchGroupKeyForTest(withID.String(), 11, "run", 0)
	implARes, ok := graph.EdgeResolutions[EdgeResolutionKey(withID.String(), implAID.String(), EdgeResolution{
		Kind: EdgeKindInterfaceDispatch, DeclaredType: "com.acme.Sink", MethodName: "run", Arity: 0, CallSite: 11,
	})]
	if !ok || implARes.Kind != EdgeKindInterfaceDispatch {
		t.Fatalf("precondition failed: expected interface_dispatch edge with#1 -> SinkImplA.run, got %#v (key=%v)", implARes, ambiguousKey)
	}

	// The disambiguated bypass edge: viaImplA -> SinkImplA.run, exact, carrying
	// ResolvedReceiverType "SinkImplA".
	bypassKey := EdgeResolutionKey(viaAID.String(), implAID.String(), EdgeResolution{
		Kind: EdgeKindExact, MethodName: "run", Arity: 0, CallSite: 21,
	})
	bypass, ok := graph.EdgeResolutions[bypassKey]
	if !ok {
		t.Fatalf("expected a resolved pass-through bypass edge viaImplA -> SinkImplA.run; EdgeResolutions=%#v", graph.EdgeResolutions)
	}
	if bypass.Kind != EdgeKindExact {
		t.Fatalf("bypass edge kind = %q, want %q", bypass.Kind, EdgeKindExact)
	}
	if bypass.ResolvedReceiverType != "SinkImplA" {
		t.Fatalf("bypass edge ResolvedReceiverType = %q, want %q", bypass.ResolvedReceiverType, "SinkImplA")
	}

	// No bypass edge should exist to the OTHER implementor — the pass must not
	// guess when it has resolved the type.
	wrongKey := EdgeResolutionKey(viaAID.String(), implBID.String(), EdgeResolution{
		Kind: EdgeKindExact, MethodName: "run", Arity: 0, CallSite: 21,
	})
	if _, ok := graph.EdgeResolutions[wrongKey]; ok {
		t.Fatalf("unexpected bypass edge viaImplA -> SinkImplB.run; the resolved type must only ever match SinkImplA")
	}
}

// dispatchGroupKeyForTest is a tiny readability helper for failure messages;
// it has no behavior of its own.
func dispatchGroupKeyForTest(caller string, callSite int, method string, arity int) dispatchAmbiguousGroupKey {
	return dispatchAmbiguousGroupKey{Caller: caller, CallSite: callSite, MethodName: method, Arity: arity}
}

// TestResolveParameterPassthroughDispatch_NoBypassWithoutConcreteArgument is
// the regression guard: when NO caller of the pass-through candidate supplies
// a staticaly concrete argument (e.g. the argument is itself another
// interface-typed value with no constructor/declared-return-type anchor), no
// bypass edge is added and the original ambiguous group is left exactly as
// the pre-existing fail-closed policy would judge it.
func TestResolveParameterPassthroughDispatch_NoBypassWithoutConcreteArgument(t *testing.T) {
	root := t.TempDir()

	sinkID := FunctionID{Package: "com.acme", Type: "Sink", Name: "run#0"}
	implAID := FunctionID{Package: "com.acme", Type: "SinkImplA", Name: "run#0"}
	implBID := FunctionID{Package: "com.acme", Type: "SinkImplB", Name: "run#0"}
	withID := FunctionID{Package: "com.acme", Type: "Builder", Name: "with#1"}
	viaUnknownID := FunctionID{Package: "com.acme", Type: "Builder", Name: "viaUnknown#1"}

	sinkIface := FunctionDecl{
		ID: sinkID, FilePath: filepath.Join(root, "Sink.java"), StartLine: 1, EndLine: 2,
		OwnerType: ownerTypeInterface, OwnerName: "Sink", Parameters: []FunctionParameter{},
	}
	implA := FunctionDecl{
		ID: implAID, FilePath: filepath.Join(root, "SinkImplA.java"), StartLine: 1, EndLine: 4,
		OwnerType: ownerTypeClass, OwnerName: "SinkImplA", Parameters: []FunctionParameter{},
		OwnerBases: []string{"Sink"},
	}
	implB := FunctionDecl{
		ID: implBID, FilePath: filepath.Join(root, "SinkImplB.java"), StartLine: 1, EndLine: 4,
		OwnerType: ownerTypeClass, OwnerName: "SinkImplB", Parameters: []FunctionParameter{},
		OwnerBases: []string{"Sink"},
	}
	withFn := FunctionDecl{
		ID: withID, FilePath: filepath.Join(root, "Builder.java"), StartLine: 10, EndLine: 12,
		OwnerType: ownerTypeClass, OwnerName: "Builder",
		Parameters: []FunctionParameter{{Type: "Sink", Name: "s"}},
		Calls: []FunctionCall{
			{Callee: sinkID, ReceiverVar: "s", FilePath: filepath.Join(root, "Builder.java"), Line: 11, Raw: "s.run()"},
		},
	}
	// viaUnknown(Sink passthroughParam) { with(passthroughParam); } — the
	// argument is itself just a parameter with no constructor/return-type
	// anchor, so no concrete type can be resolved.
	viaUnknown := FunctionDecl{
		ID: viaUnknownID, FilePath: filepath.Join(root, "Builder.java"), StartLine: 30, EndLine: 32,
		OwnerType:  ownerTypeClass,
		OwnerName:  "Builder",
		Parameters: []FunctionParameter{{Type: "Sink", Name: "passthroughParam"}},
		Calls: []FunctionCall{
			{
				Callee:    withID,
				Arguments: []string{"passthroughParam"},
				FilePath:  filepath.Join(root, "Builder.java"),
				Line:      31,
				Raw:       "with(passthroughParam)",
			},
		},
	}

	parser := &stubParser{
		sep: ".",
		analyses: map[string][]*FileAnalysis{
			root: {{Functions: []FunctionDecl{sinkIface, implA, implB, withFn, viaUnknown}}},
		},
	}

	graph, err := NewBuilder(parser).BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "com.acme"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	for _, implKey := range []string{implAID.String(), implBID.String()} {
		key := EdgeResolutionKey(viaUnknownID.String(), implKey, EdgeResolution{
			Kind: EdgeKindExact, MethodName: "run", Arity: 0, CallSite: 31,
		})
		if _, ok := graph.EdgeResolutions[key]; ok {
			t.Fatalf("unexpected bypass edge viaUnknown -> %s; no concrete argument type was available to resolve", implKey)
		}
	}
}

// TestResolveParameterPassthroughDispatch_ConvergesToZero guards the fixpoint
// progress accounting: a bypass edge stamped in a prior iteration must not be
// re-counted as progress, or the loop spins to passthroughMaxIterations doing
// no-op work on every large graph. Re-running the whole pass on an
// already-resolved graph must therefore report zero resolutions.
func TestResolveParameterPassthroughDispatch_ConvergesToZero(t *testing.T) {
	graph := buildConstructorArgFixtureGraph(t)

	// The pass already ran inside BuildFromDirectories; a second run must be
	// a no-op with zero reported progress.
	if n := resolveParameterPassthroughDispatch(graph); n != 0 {
		t.Fatalf("second resolveParameterPassthroughDispatch pass resolved %d, want 0 (fixpoint must not re-count existing bypass edges)", n)
	}
}

func TestGroupAmbiguousDispatchEdges_IgnoresNonPassthroughCallers(t *testing.T) {
	passthroughID := FunctionID{Package: "com.acme", Type: "Builder", Name: "with#1"}
	nonPassthroughID := FunctionID{Package: "com.acme", Type: "Builder", Name: "helper#0"}
	ifaceID := FunctionID{Package: "com.acme", Type: "Sink", Name: "run#0"}
	implAID := FunctionID{Package: "com.acme", Type: "SinkImplA", Name: "run#0"}
	implBID := FunctionID{Package: "com.acme", Type: "SinkImplB", Name: "run#0"}

	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			passthroughID.String(): {
				ID:         passthroughID,
				Parameters: []FunctionParameter{{Type: "Sink", Name: "s"}},
				Calls:      []FunctionCall{{Callee: ifaceID, ReceiverVar: "s", Line: 10}},
			},
			nonPassthroughID.String(): {
				ID:    nonPassthroughID,
				Calls: []FunctionCall{{Callee: ifaceID, ReceiverVar: "local", Line: 20}},
			},
		},
		EdgeResolutions: map[string]EdgeResolution{},
	}

	for _, caller := range []FunctionID{passthroughID, nonPassthroughID} {
		callSite := 20
		if caller == passthroughID {
			callSite = 10
		}
		for _, callee := range []FunctionID{implAID, implBID} {
			res := EdgeResolution{Kind: EdgeKindInterfaceDispatch, MethodName: "run", Arity: 0, CallSite: callSite}
			graph.EdgeResolutions[EdgeResolutionKey(caller.String(), callee.String(), res)] = res
		}
	}

	groups := groupAmbiguousDispatchEdges(graph)
	if len(groups) != 1 {
		t.Fatalf("groups len = %d, want 1: %#v", len(groups), groups)
	}
	if _, ok := groups[dispatchAmbiguousGroupKey{Caller: passthroughID.String(), CallSite: 10, MethodName: "run", Arity: 0}]; !ok {
		t.Fatalf("expected passthrough group, got %#v", groups)
	}
	if _, ok := groups[dispatchAmbiguousGroupKey{Caller: nonPassthroughID.String(), CallSite: 20, MethodName: "run", Arity: 0}]; ok {
		t.Fatalf("non-passthrough caller should not be grouped: %#v", groups)
	}
}

// isEnabledOverloads is log4j-api 2.14.1's SimpleLogger.isEnabled at arity
// 4: four overloads that differ only in the third parameter.
func isEnabledOverloads() (*CallGraph, []string) {
	graph := &CallGraph{Functions: map[string]*FunctionDecl{}}
	var keys []string
	for _, third := range []string{"Message", "CharSequence", "Object", "String"} {
		last := "Throwable"
		id := FunctionID{Package: "org.apache.logging.log4j.simple", Type: "SimpleLogger", Name: "isEnabled#4$Level,Marker," + third + "," + last}
		graph.Functions[id.String()] = &FunctionDecl{ID: id, Parameters: []FunctionParameter{
			{Name: "testLevel", Type: "Level"}, {Name: "marker", Type: "Marker"}, {Name: "msg", Type: third}, {Name: "t", Type: last},
		}}
		keys = append(keys, id.String())
	}
	return graph, keys
}

// isEnabledCall is AbstractLogger.isEnabled(Level, Marker)'s self-call with
// the given third argument.
func isEnabledCall(third string) *FunctionCall {
	return &FunctionCall{
		Callee:    FunctionID{Name: "isEnabled#4"},
		Arguments: []string{"level", "marker", third, "null"},
		ArgumentSources: [][]SourceNode{
			{{Type: "PARAMETER", Name: "level", DeclaredType: "Level"}},
			{{Type: "PARAMETER", Name: "marker", DeclaredType: "Marker"}},
		},
	}
}

// TestResolveOverloadPerOwner_CastPicksOverload: `isEnabled(level, marker,
// (Object) null, null)` calls the Object overload, as javac binds it; the
// cast is the argument's static type. Without it the four overloads scored
// alike and the first in candidate order won, an order that changed from run
// to run.
func TestResolveOverloadPerOwner_CastPicksOverload(t *testing.T) {
	graph, keys := isEnabledOverloads()
	want := keys[2]
	for rot := range keys {
		order := append(append([]string(nil), keys[rot:]...), keys[:rot]...)
		got := resolveOverloadPerOwner(graph, isEnabledCall("(Object) null"), map[string][]string{"SimpleLogger": order})
		if got["SimpleLogger"] != want {
			t.Fatalf("candidates %v: picked %q, want %q", order, got["SimpleLogger"], want)
		}
	}
}

// TestResolveOverloadPerOwner_TieResolvesNothing: when the best score is
// shared, the argument types do not tell which overload the call binds, so the
// owner resolves to none rather than to whichever candidate came first.
func TestResolveOverloadPerOwner_TieResolvesNothing(t *testing.T) {
	graph, keys := isEnabledOverloads()
	for rot := range keys {
		order := append(append([]string(nil), keys[rot:]...), keys[:rot]...)
		got := resolveOverloadPerOwner(graph, isEnabledCall("msg"), map[string][]string{"SimpleLogger": order})
		if target, ok := got["SimpleLogger"]; ok {
			t.Fatalf("candidates %v: picked %q on a tie, want none", order, target)
		}
	}
}

func TestJavaCastArgumentType(t *testing.T) {
	cases := map[string]string{
		"(Object) null":             "Object",
		"( java.lang.String )value": "String",
		"(byte[]) buf":              "byte[]",
		"(Map<String, List<K>>) m":  "Map",
		"(int) -x":                  "int",
		"((Foo) bar)":               "",
		"(a) - b":                   "",
		"(a).b()":                   "",
		"(Foo) -x":                  "",
		"(a + b)":                   "",
		"(x)":                       "",
		"null":                      "",
		"new Foo()":                 "",
	}
	for expr, want := range cases {
		if got := javaCastArgumentType(expr); got != want {
			t.Errorf("javaCastArgumentType(%q) = %q, want %q", expr, got, want)
		}
	}
}

// TestNewResolvedReceiverIndex_EarliestSite: a constructor that calls
// context.getOrCreate(..) on lines 283 and 284 of sis-referencing's
// EllipsoidToCentricTransform has a resolved receiver type on both edges.
// The index keeps one site per caller and callee, the earliest, which the
// edge one hop further is attributed to; taking the last in map order put it
// on either line from run to run.
func TestNewResolvedReceiverIndex_EarliestSite(t *testing.T) {
	caller := "org.apache.sis.referencing.operation.transform.(EllipsoidToCentricTransform).<init>#5"
	callee := "org.apache.sis.referencing.operation.transform.(ContextualParameters).getOrCreate#1"
	for run := range 64 {
		graph := &CallGraph{EdgeResolutions: map[string]EdgeResolution{}}
		for _, site := range []struct{ line, col int }{{284, 9}, {283, 9}, {283, 30}, {290, 1}} {
			res := EdgeResolution{Kind: EdgeKindExact, MethodName: "getOrCreate", Arity: 1, CallSite: site.line, StartCol: site.col, EndCol: site.col + 20, ResolvedReceiverType: "ContextualParameters"}
			graph.EdgeResolutions[EdgeResolutionKey(caller, callee, res)] = res
		}
		_, line, startCol, _, ok := lookupResolvedReceiverType(newResolvedReceiverIndex(graph), caller, callee)
		if !ok || line != 283 || startCol != 9 {
			t.Fatalf("run %d: indexed site %d:%d (ok=%v), want 283:9", run, line, startCol, ok)
		}
	}
}
