// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"fmt"
	"slices"
	"testing"
)

const selectorAnchor = "lib.(Helper).create#1"

func literalCall(value string) *CallSite {
	return &CallSite{Line: 1, Parameters: []Parameter{{
		ParameterIndex: 0, ArgumentExpression: value, ResolvedValue: value,
		SourceNodes: []SourceNode{{Type: sourceNodeValue, Value: value}},
	}}}
}

func parameterNode(index int) []SourceNode {
	return []SourceNode{{Type: sourceNodeParameter, Name: "alg", ParameterIndex: &index}}
}

func passThroughCall() *CallSite {
	return &CallSite{Line: 2, Parameters: []Parameter{{ParameterIndex: 0, VariableName: "a", ArgumentExpression: "a", SourceNodes: parameterNode(0)}}}
}

// selectorCall is the anchor: lib.Helper.create(alg) passes its parameter to
// the crypto call.
func selectorCall() SelectorCall {
	return SelectorCall{Component: componentC, Function: selectorAnchor, Parameters: []Parameter{{
		ParameterIndex: 0, VariableName: "alg", ArgumentExpression: "alg", SourceNodes: parameterNode(0),
	}}}
}

// selectorFixture is a project (A) calling a library (B) that calls the
// anchor in a crypto library (C) with "X", and passes "Y" through a function
// the project never calls. B's resolved dependencies omit C, as a Maven tree
// does when the project declares C itself.
func selectorFixture(bDeps []ComponentKey) (DependencyGraph, map[ComponentKey]Fragment) {
	root := Fragment{
		Component: componentA,
		Functions: []Function{{Signature: "app.(Main).run#0"}},
		ExternalCalls: []ExternalCall{{
			Caller: "app.(Main).run#0", TargetSignature: "pix.(User).use#0",
			Resolution: ResolutionExact, MethodName: "use", CallSite: 3,
		}},
	}
	user := Fragment{
		Component: componentB,
		Functions: []Function{{Signature: "pix.(User).use#0"}, {Signature: "pix.(User).pass#1"}, {Signature: "pix.(User).caller#0"}},
		ExternalCalls: []ExternalCall{
			{Caller: "pix.(User).use#0", TargetSignature: selectorAnchor, Resolution: ResolutionExact, MethodName: "create", Arity: 1, CallSite: 5, EntryCall: literalCall(`"X"`)},
			{Caller: "pix.(User).pass#1", TargetSignature: selectorAnchor, Resolution: ResolutionExact, MethodName: "create", Arity: 1, CallSite: 9, EntryCall: passThroughCall()},
		},
		InternalEdges: []InternalEdge{{
			Caller: "pix.(User).caller#0", Callee: "pix.(User).pass#1", Resolution: ResolutionExact,
			MethodName: "pass", Arity: 1, CallSite: 12, EntryCall: literalCall(`"Y"`),
		}},
	}
	lib := Fragment{Component: componentC, Functions: []Function{{Signature: selectorAnchor}}}
	return DependencyGraph{componentA: {componentB, componentC}, componentB: bDeps},
		map[ComponentKey]Fragment{componentA: root, componentB: user, componentC: lib}
}

func selectorValuesOf(t *testing.T, deps DependencyGraph, fragments map[ComponentKey]Fragment, opts StitchOptions) SelectorValues {
	t.Helper()
	opts.SelectorCalls = []SelectorCall{selectorCall()}
	res, err := StitchWithOptions(componentA, deps, fragments, opts)
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	values := res.SelectorValues()
	if len(values) != 1 {
		t.Fatalf("SelectorValues() has %d entries, want 1", len(values))
	}
	return values[0]
}

func variantSummary(values SelectorValues) []string {
	out := make([]string, 0, len(values.Variants))
	for _, v := range values.Variants {
		out = append(out, fmt.Sprintf("%d:%s:%s:%s", v.Index, v.Parameters[v.Index].ResolvedValue, v.Reachability, v.UnresolvedReason))
	}
	slices.Sort(out)
	return out
}

// A value written in a component the dependency tree does not link to the
// anchor's still reaches it: the walk resolves calls against the whole pinned
// closure. Its verdict is the stitch's: the project reaches the call passing
// "X" and not the one passing "Y".
func TestSelectorValues_CrossComponentValuesOverTheClasspath(t *testing.T) {
	t.Parallel()
	deps, fragments := selectorFixture(nil)
	got := variantSummary(selectorValuesOf(t, deps, fragments, StitchOptions{EntryRootedOnly: true, ClasspathTargets: true}))
	want := []string{`0:"X":reachable:`, `0:"Y":unreachable:`}
	if !slices.Equal(got, want) {
		t.Fatalf("variants = %v, want %v", got, want)
	}
}

// Without classpath targets the walk follows the stitch's own edges only.
func TestSelectorValues_DependencyEdgesOnlyWithoutClasspath(t *testing.T) {
	t.Parallel()
	deps, fragments := selectorFixture(nil)
	if got := selectorValuesOf(t, deps, fragments, StitchOptions{EntryRootedOnly: true}); len(got.Variants) != 0 {
		t.Fatalf("variants = %v, want none", variantSummary(got))
	}
	deps, fragments = selectorFixture([]ComponentKey{componentC})
	if got := variantSummary(selectorValuesOf(t, deps, fragments, StitchOptions{EntryRootedOnly: true})); len(got) != 2 {
		t.Fatalf("variants = %v, want X and Y", got)
	}
}

// helperSurface makes C's anchor one of two implementations of lib.Api.create.
func helperSurface(fragments map[ComponentKey]Fragment) string {
	surface := "lib.Api.create(String)"
	fragments[componentC] = Fragment{Component: componentC, Functions: []Function{
		{Signature: "lib.(Api).create#1", FunctionName: "lib.Api.create", CanonicalSignature: surface},
		{Signature: selectorAnchor, FunctionName: "lib.Helper.create", CanonicalSignature: "lib.Helper.create(String)", CompatibleCanonicalSignatures: []string{surface}},
		{Signature: "lib.(Other).create#1", FunctionName: "lib.Other.create", CanonicalSignature: "lib.Other.create(String)", CompatibleCanonicalSignatures: []string{surface}},
	}}
	return surface
}

// A value passed across an interface call with several implementations is
// served unknown (ambiguous_dispatch), however the project reaches its caller:
// where it is written ("X") or on the way down ("Y", written in a function
// the project calls and passed on through the interface).
func TestSelectorValues_AmbiguousDispatchIsUnknown(t *testing.T) {
	t.Parallel()
	deps, fragments := selectorFixture([]ComponentKey{componentC})
	surface := helperSurface(fragments)
	root := fragments[componentA]
	root.ExternalCalls = append(root.ExternalCalls, ExternalCall{
		Caller: "app.(Main).run#0", TargetSignature: "pix.(User).caller#0", Resolution: ResolutionExact, MethodName: "caller", CallSite: 4,
	})
	fragments[componentA] = root
	user := fragments[componentB]
	user.ExternalCalls = []ExternalCall{
		{Caller: "pix.(User).use#0", TargetSignature: "lib.(Api).create#1", TargetCanonicalSignature: surface, Resolution: ResolutionExact, MethodName: "create", Arity: 1, CallSite: 5, EntryCall: literalCall(`"X"`)},
		{Caller: "pix.(User).pass#1", TargetSignature: "lib.(Api).create#1", TargetCanonicalSignature: surface, Resolution: ResolutionExact, MethodName: "create", Arity: 1, CallSite: 9, EntryCall: passThroughCall()},
	}
	fragments[componentB] = user
	got := variantSummary(selectorValuesOf(t, deps, fragments, StitchOptions{EntryRootedOnly: true, AmbiguousDispatchUnknown: true}))
	want := []string{`0:"X":unknown:ambiguous_dispatch`, `0:"Y":unknown:ambiguous_dispatch`}
	if !slices.Equal(got, want) {
		t.Fatalf("variants = %v, want %v", got, want)
	}
}

// A call site the project reaches only across an ambiguous interface call
// passes its value unknown, even over typed calls from there.
func TestSelectorValues_CallerReachedOnlyAcrossAmbiguousDispatch(t *testing.T) {
	t.Parallel()
	deps, fragments := selectorFixture([]ComponentKey{componentC})
	surface := "pix.Task.run()"
	fragments[componentA] = Fragment{
		Component: componentA,
		Functions: []Function{{Signature: "app.(Main).run#0"}},
		ExternalCalls: []ExternalCall{{
			Caller: "app.(Main).run#0", TargetSignature: "pix.(Task).run#0", TargetCanonicalSignature: surface,
			Resolution: ResolutionExact, MethodName: "run", CallSite: 3,
		}},
	}
	user := fragments[componentB]
	user.Functions = []Function{
		{Signature: "pix.(Task).run#0", CanonicalSignature: surface},
		{Signature: "pix.(User).use#0", CanonicalSignature: "pix.User.use()", CompatibleCanonicalSignatures: []string{surface}},
		{Signature: "pix.(Idle).run#0", CanonicalSignature: "pix.Idle.run()", CompatibleCanonicalSignatures: []string{surface}},
	}
	user.InternalEdges = nil
	user.ExternalCalls = user.ExternalCalls[:1]
	fragments[componentB] = user
	got := variantSummary(selectorValuesOf(t, deps, fragments, StitchOptions{EntryRootedOnly: true, AmbiguousDispatchUnknown: true}))
	want := []string{`0:"X":unknown:ambiguous_dispatch`}
	if !slices.Equal(got, want) {
		t.Fatalf("variants = %v, want %v", got, want)
	}
}

// chainFixture passes "Z" to the anchor through n functions that each pass
// their parameter on.
func chainFixture(n int) (DependencyGraph, map[ComponentKey]Fragment) {
	lib := Fragment{Component: componentC, Functions: []Function{{Signature: selectorAnchor}, {Signature: "lib.(Chain).top#0"}}}
	callee := selectorAnchor
	for i := range n {
		fn := fmt.Sprintf("lib.(Chain).f%d#1", i)
		lib.Functions = append(lib.Functions, Function{Signature: fn})
		lib.InternalEdges = append(lib.InternalEdges, InternalEdge{Caller: fn, Callee: callee, Resolution: ResolutionExact, MethodName: "f", Arity: 1, CallSite: i + 1, EntryCall: passThroughCall()})
		callee = fn
	}
	lib.InternalEdges = append(lib.InternalEdges, InternalEdge{Caller: "lib.(Chain).top#0", Callee: callee, Resolution: ResolutionExact, MethodName: "f", Arity: 1, CallSite: 99, EntryCall: literalCall(`"Z"`)})
	root := Fragment{Component: componentA, Functions: []Function{{Signature: "app.(Main).run#0"}}}
	return DependencyGraph{componentA: {componentC}}, map[ComponentKey]Fragment{componentA: root, componentC: lib}
}

// The walk follows a value up to 32 callers deep; past that it stops and says
// a value may be missing.
func TestSelectorValues_DepthCap(t *testing.T) {
	t.Parallel()
	deps, fragments := chainFixture(selectorMaxDepth - 1)
	got := selectorValuesOf(t, deps, fragments, StitchOptions{})
	if summary := variantSummary(got); !slices.Equal(summary, []string{`0:"Z":unreachable:`}) || got.Truncated {
		t.Fatalf("within the cap: variants = %v, truncated = %v; want Z, not truncated", summary, got.Truncated)
	}
	deps, fragments = chainFixture(selectorMaxDepth)
	got = selectorValuesOf(t, deps, fragments, StitchOptions{})
	if len(got.Variants) != 0 || !got.Truncated {
		t.Fatalf("past the cap: variants = %v, truncated = %v; want none, truncated", variantSummary(got), got.Truncated)
	}
}

// At most 256 distinct values reach one argument; the rest are cut and the
// call says so.
func TestSelectorValues_ValueBound(t *testing.T) {
	t.Parallel()
	for _, callers := range []int{selectorMaxValues, selectorMaxValues + 1} {
		user := Fragment{Component: componentB}
		for i := range callers {
			fn := fmt.Sprintf("pix.(User).c%d#0", i)
			user.Functions = append(user.Functions, Function{Signature: fn})
			user.ExternalCalls = append(user.ExternalCalls, ExternalCall{Caller: fn, TargetSignature: selectorAnchor, Resolution: ResolutionExact, MethodName: "create", Arity: 1, CallSite: 1, EntryCall: literalCall(fmt.Sprintf(`"v%d"`, i))})
		}
		fragments := map[ComponentKey]Fragment{
			componentA: {Component: componentA, Functions: []Function{{Signature: "app.(Main).run#0"}}},
			componentB: user,
			componentC: {Component: componentC, Functions: []Function{{Signature: selectorAnchor}}},
		}
		got := selectorValuesOf(t, DependencyGraph{componentA: {componentB}, componentB: {componentC}}, fragments, StitchOptions{})
		wantTruncated := callers > selectorMaxValues
		if len(got.Variants) != selectorMaxValues || got.Truncated != wantTruncated {
			t.Fatalf("%d callers: %d variants, truncated = %v; want %d, %v", callers, len(got.Variants), got.Truncated, selectorMaxValues, wantTruncated)
		}
	}
}

// A value resolves only when every source of the argument agrees on it: an
// argument built from the parameter and another value names neither.
func TestResolveBoundSourceNodes(t *testing.T) {
	t.Parallel()
	zero, one := 0, 1
	tests := []struct {
		name  string
		nodes []SourceNode
		want  string
	}{
		{"the parameter itself", []SourceNode{{Type: sourceNodeParameter, ParameterIndex: &zero}}, "V"},
		{"another parameter", []SourceNode{{Type: sourceNodeParameter, ParameterIndex: &one}}, ""},
		{"parameter and the same literal", []SourceNode{{Type: sourceNodeParameter, ParameterIndex: &zero}, {Type: sourceNodeValue, Value: "V"}}, "V"},
		{"parameter and another literal", []SourceNode{{Type: sourceNodeParameter, ParameterIndex: &zero}, {Type: sourceNodeValue, Value: "W"}}, ""},
		{"a call result of the parameter", []SourceNode{{Type: "CALL_RESULT", SourceNodes: []SourceNode{{Type: sourceNodeParameter, ParameterIndex: &zero}}}}, ""},
		{"a variable holding a literal", []SourceNode{{Type: sourceNodeVariable, SourceNodes: []SourceNode{{Type: sourceNodeValue, Value: "W"}}}}, "W"},
	}
	for _, tc := range tests {
		if got, _ := resolveBoundSourceNodes(tc.nodes, selectorParameter{index: 0}, "V", true); got != tc.want {
			t.Errorf("%s: resolved %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Only a call the dependency tree leaves without a target is resolved against
// the whole closure: one it resolves keeps its target, and a function of the
// same name in another component gets none of its values.
func TestSelectorValues_ResolvedCallsKeepTheirTarget(t *testing.T) {
	t.Parallel()
	deps, fragments := selectorFixture([]ComponentKey{componentC})
	fragments[componentD] = Fragment{Component: componentD, Functions: []Function{{Signature: selectorAnchor}}}
	deps[componentA] = append(deps[componentA], componentD)
	call := selectorCall()
	call.Component = componentD
	res, err := StitchWithOptions(componentA, deps, fragments, StitchOptions{EntryRootedOnly: true, ClasspathTargets: true, SelectorCalls: []SelectorCall{call}})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	if got := res.SelectorValues()[0]; len(got.Variants) != 0 {
		t.Fatalf("the other component's function got %v", variantSummary(got))
	}
}

// Many callers pass the anchor's argument: the variants come in caller order
// on every run, not in the order the stitch's edge maps happen to yield.
func TestSelectorValues_VariantsInCallerOrder(t *testing.T) {
	t.Parallel()
	deps, fragments := selectorFixture(nil)
	user := fragments[componentB]
	var want []string
	for i := range 12 {
		caller := fmt.Sprintf("pix.(Caller%02d).call#0", i)
		value := fmt.Sprintf(`"V%02d"`, i)
		user.Functions = append(user.Functions, Function{Signature: caller})
		user.ExternalCalls = append(user.ExternalCalls, ExternalCall{
			Caller: caller, TargetSignature: selectorAnchor, Resolution: ResolutionExact,
			MethodName: "create", Arity: 1, CallSite: 20 + i, EntryCall: literalCall(value),
		})
		want = append(want, value)
	}
	fragments[componentB] = user
	// Callers sort by function key: pix.(Caller..), then pix.(User).pass#1,
	// which passes on "Y" from its own caller, then pix.(User).use#0 ("X").
	want = append(want, `"Y"`, `"X"`)
	for range 10 {
		got := selectorValuesOf(t, deps, fragments, StitchOptions{EntryRootedOnly: true, ClasspathTargets: true})
		var order []string
		for _, v := range got.Variants {
			order = append(order, v.Parameters[v.Index].ResolvedValue)
		}
		if !slices.Equal(order, want) {
			t.Fatalf("variant order = %v, want %v", order, want)
		}
	}
}
