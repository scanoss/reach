// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"testing"
)

const (
	hasherSumFn   = "org.example.hash.(Hasher).sum#1"
	standardSumFn = "org.example.hash.(Hashers.Standard).sum#1"
	plainSumFn    = "org.example.hash.(Hashers.Plain).sum#1"
	appMainFn     = "com.acme.app.(Main).main#1"
)

func constructs(class string) GraphFragmentRawSource {
	return GraphFragmentRawSource{
		Type: "CALL_RESULT", DeclaredType: class, Value: "new " + class + "()",
		CallTarget: "org.example.hash.(" + class + ").<init>#0",
	}
}

// hasherDependency is a library with an interface, two implementations of it
// nested in the factory class, and factories that return them. Only Standard
// reaches a crypto operation; Plain holds another, so each verdict shows
// which body the stitch took.
func hasherDependency(t *testing.T) Fragment {
	t.Helper()
	return hasherDependencyOf(t, "java")
}

func hasherDependencyOf(t *testing.T, ecosystem string) Fragment {
	t.Helper()
	sum := "org.example.hash.Hasher.sum(byte[]): byte[]"
	factory := func(name string, returns ...GraphFragmentRawSource) GraphFragmentFunction {
		return GraphFragmentFunction{
			Key: "org.example.hash.(Hashers)." + name + "#0", FunctionName: "org.example.hash.Hashers." + name,
			CanonicalSignature: "org.example.hash.Hashers." + name + "(): Hasher", ReturnSources: returns,
		}
	}
	doc := GraphFragmentExport{
		SchemaVersion: SchemaVersion,
		ScanMetadata:  GraphFragmentScanMetadata{Ecosystem: ecosystem, AbstractMethods: true},
		Functions: []GraphFragmentFunction{
			{Key: hasherSumFn, FunctionName: "org.example.hash.Hasher.sum", CanonicalSignature: sum, Abstract: true},
			{Key: standardSumFn, FunctionName: "org.example.hash.Hashers.Standard.sum", CanonicalSignature: "org.example.hash.Hashers.Standard.sum(byte[]): byte[]", CompatibleCanonicalSignatures: []string{sum}},
			{Key: plainSumFn, FunctionName: "org.example.hash.Hashers.Plain.sum", CanonicalSignature: "org.example.hash.Hashers.Plain.sum(byte[]): byte[]", CompatibleCanonicalSignatures: []string{sum}},
			factory("standard", constructs("Standard")),
			factory("plain", constructs("Plain")),
			factory("either", constructs("Standard"), constructs("Plain")),
			factory("orNull", constructs("Standard"), GraphFragmentRawSource{Type: "VALUE", Value: "null"}),
			factory("cached", constructs("Standard"), GraphFragmentRawSource{Type: "FIELD", Name: "cached"}),
			factory("anonymous", GraphFragmentRawSource{
				Type: "CALL_RESULT", DeclaredType: "Standard", Value: "new Standard() { }",
				CallTarget: "org.example.hash.(Standard).<init>#0",
			}),
			factory("foreign", GraphFragmentRawSource{
				Type: "CALL_RESULT", DeclaredType: "Standard", Value: "new Standard()",
				CallTarget: "org.example.other.(Standard).<init>#0",
			}),
			factory("unread"),
		},
	}
	frag := doc.ToFragment(componentC)
	frag.CryptoOperations = []CryptoOperation{
		{Function: standardSumFn, FindingID: "f-standard", RuleID: "rule.digest"},
		{Function: plainSumFn, FindingID: "f-plain", RuleID: "rule.copy"},
	}
	return frag
}

// hasherCallSites is the project's request: `Hasher h = Hashers.<factory>();
// h.sum(data);`, decoded from the JSON a client sends. receiverProducer is
// the request's receiver_producer on the call of sum; "" leaves the field
// out, as a client that does not know it does.
func hasherCallSites(t *testing.T, factory, receiverProducer string) Fragment {
	t.Helper()
	call := map[string]any{
		"caller_key": appMainFn, "target_key": hasherSumFn, "resolution": "exact",
		"method_name": "sum", "arity": 1, "receiver_var": "h", "line": 14,
	}
	if receiverProducer != "" {
		call["receiver_producer"] = receiverProducer
	}
	request := map[string]any{
		"schema_version": SchemaVersion,
		"functions":      []map[string]any{{"key": appMainFn}},
		"external_calls": []map[string]any{
			{
				"caller_key": appMainFn, "target_key": "org.example.hash.(Hashers)." + factory + "#0", "resolution": "exact",
				"method_name": factory, "assigned_var": "h", "line": 13,
			},
			call,
		},
	}
	data, err := json.Marshal(request)
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	var doc GraphFragmentExport
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	return doc.ToFragment(componentA)
}

func hasherVerdicts(t *testing.T, factory, receiverProducer string) map[string]ExportFindingGraph {
	t.Helper()
	dep := hasherDependency(t)
	fragments := map[ComponentKey]Fragment{componentA: hasherCallSites(t, factory, receiverProducer), componentC: dep}
	res, err := StitchWithOptions(componentA, DependencyGraph{componentA: {componentC}}, fragments, StitchOptions{
		EntryRootedOnly: true, ClasspathTargets: true, HierarchyFromSupertypes: true, AmbiguousDispatchUnknown: true,
	})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	original := map[string]string{}
	for id, served := range servedFindingIDs(componentC, &dep) {
		original[served] = id
	}
	out := map[string]ExportFindingGraph{}
	for _, fg := range res.ToCallgraphExport(componentA, ScanMeta{Ecosystem: "java"}).FindingGraphs {
		out[original[fg.FindingID]] = fg
	}
	return out
}

func producerKey(factory string) string {
	return "org.example.hash.(Hashers)." + factory + "#0"
}

// A method called on the result of a factory that builds one class runs that
// class's body, whatever the other implementations of the interface do.
func TestStitch_ReceiverTypedByItsFactory(t *testing.T) {
	t.Parallel()
	got := hasherVerdicts(t, "standard", producerKey("standard"))
	wantVerdict(t, got, "f-standard", ReachabilityReachable, "")
	wantVerdict(t, got, "f-plain", ReachabilityUnreachable, "")

	got = hasherVerdicts(t, "plain", producerKey("plain"))
	wantVerdict(t, got, "f-standard", ReachabilityUnreachable, "")
	wantVerdict(t, got, "f-plain", ReachabilityReachable, "")
}

// A return of null yields no object a method could run on: the factory still
// builds one class.
func TestStitch_FactoryThatMayReturnNullStillTypesItsReceiver(t *testing.T) {
	t.Parallel()
	got := hasherVerdicts(t, "orNull", producerKey("orNull"))
	wantVerdict(t, got, "f-standard", ReachabilityReachable, "")
	wantVerdict(t, got, "f-plain", ReachabilityUnreachable, "")
}

// Whenever the facts do not single out one class, the call stays the
// ambiguous dispatch it is without them.
func TestStitch_ReceiverKeepsAmbiguousDispatchWithoutOneConstructedClass(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, factory, receiverProducer string }{
		{"a client that does not send the producer", "standard", ""},
		{"a factory that builds two classes", "either", producerKey("either")},
		{"a factory that also returns a field", "cached", producerKey("cached")},
		{"a factory that builds an anonymous subclass", "anonymous", producerKey("anonymous")},
		{"a factory whose class another package declares", "foreign", producerKey("foreign")},
		{"a factory with no return facts", "unread", producerKey("unread")},
		{"a producer the closure does not declare", "standard", "org.example.hash.(Hashers).missing#0"},
	}
	baseline := hasherVerdicts(t, "standard", "")
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := hasherVerdicts(t, tc.factory, tc.receiverProducer)
			for _, id := range []string{"f-standard", "f-plain"} {
				wantVerdict(t, got, id, ReachabilityUnknown, UnresolvedReasonAmbiguousDispatch)
				if got[id].Reachability != baseline[id].Reachability || got[id].UnresolvedReason != baseline[id].UnresolvedReason {
					t.Errorf("%s: differs from the verdict without the producer", id)
				}
			}
		})
	}
}

// Only a Java fragment's return provenance tells an instantiation from any
// other call: a fragment of another ecosystem constructs nothing, whatever
// its returns look like, so a call into it is never narrowed.
func TestFragment_ConstructsNothingOutsideJava(t *testing.T) {
	t.Parallel()
	for _, ecosystem := range []string{"python", "go", "rust", "node"} {
		dep := hasherDependencyOf(t, ecosystem)
		for _, fn := range dep.Functions {
			if fn.Constructs != "" {
				t.Errorf("%s %s: constructs %q, want nothing", ecosystem, fn.Signature, fn.Constructs)
			}
		}
	}
}

func TestFragment_ConstructsOnlyWhenEveryReturnBuildsOneClass(t *testing.T) {
	t.Parallel()
	dep := hasherDependency(t)
	want := map[string]string{
		producerKey("standard"): "org.example.hash.(Standard)", producerKey("plain"): "org.example.hash.(Plain)",
		producerKey("orNull"): "org.example.hash.(Standard)", producerKey("foreign"): "org.example.other.(Standard)",
	}
	for _, fn := range dep.Functions {
		if fn.Constructs != want[fn.Signature] {
			t.Errorf("%s: constructs %q, want %q", fn.Signature, fn.Constructs, want[fn.Signature])
		}
	}
}
