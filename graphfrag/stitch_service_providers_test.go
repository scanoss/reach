// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"reflect"
	"testing"
)

const (
	spParserParse = "tika.parser.(Parser).parse#1"
	spParserSig   = "tika.parser.Parser.parse(InputStream): void"
	spPdfParse    = "plug.(PdfParser).parse#1"
	spRarParse    = "plug.(RarParser).parse#1"
	spZipStream   = "plug.(Formats.Zip).parse#1$InputStream"
	spZipFile     = "plug.(Formats.Zip).parse#1$File"
)

// serviceProviderFixture is reach-engine-v2 nor-202..209: the application
// calls Tika (core), whose parse calls Parser.parse on the parsers
// ServiceLoader loads; the parsers live in a plugin component that depends on
// core and registers some of them in META-INF/services. The plugin's
// fragment, mined alone, cannot prove its classes implement Parser.
func serviceProviderFixture(registered map[string][]string, coreImpl bool) (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root := Fragment{
		Component: componentA,
		Functions: []Function{{Signature: "app.(Upload).handle#0"}},
		ExternalCalls: []ExternalCall{{
			Caller: "app.(Upload).handle#0", TargetSignature: "tika.(Tika).parse#1",
			Resolution: ResolutionExact, MethodName: "parse", Arity: 1, CallSite: 10,
		}},
	}
	core := Fragment{
		Component:       componentB,
		AbstractMethods: true,
		Functions: []Function{
			{Signature: "tika.(Tika).parse#1", CanonicalSignature: "tika.Tika.parse(InputStream): String"},
			{Signature: spParserParse, FunctionName: "tika.parser.Parser.parse", CanonicalSignature: spParserSig, Abstract: true},
			{Signature: "tika.parser.(Parser).getName#0", FunctionName: "tika.parser.Parser.getName", CanonicalSignature: "tika.parser.Parser.getName(): String", Abstract: true},
		},
		InternalEdges: []InternalEdge{{
			Caller: "tika.(Tika).parse#1", Callee: spParserParse, Resolution: ResolutionExact,
			MethodName: "parse", Arity: 1, CallSite: 527,
		}},
	}
	if coreImpl {
		core.Functions = append(core.Functions, Function{
			Signature: "tika.parser.(EmptyParser).parse#1", FunctionName: "tika.parser.EmptyParser.parse",
			CanonicalSignature: "tika.parser.EmptyParser.parse(InputStream): void", CompatibleCanonicalSignatures: []string{spParserSig},
		})
	}
	plugin := Fragment{
		Component:       componentC,
		AbstractMethods: true,
		Functions: []Function{
			{Signature: spPdfParse, FunctionName: "plug.PdfParser.parse", CanonicalSignature: "plug.PdfParser.parse(InputStream): void"},
			{Signature: spRarParse, FunctionName: "plug.RarParser.parse", CanonicalSignature: "plug.RarParser.parse(InputStream): void"},
			{Signature: spZipStream, FunctionName: "plug.Formats.Zip.parse", CanonicalSignature: "plug.Formats.Zip.parse(InputStream): void"},
			{Signature: spZipFile, FunctionName: "plug.Formats.Zip.parse", CanonicalSignature: "plug.Formats.Zip.parse(File): void"},
		},
		Supertypes: map[string][]string{
			"plug.PdfParser":   {"tika.parser.AbstractParser"},
			"plug.RarParser":   {"tika.parser.AbstractParser"},
			"plug.Formats.Zip": {"tika.parser.AbstractParser"},
		},
		ServiceProviders: registered,
		CryptoOperations: []CryptoOperation{
			{Function: spPdfParse, FindingID: "f-pdf", RuleID: "rule.digest"},
			{Function: spRarParse, FindingID: "f-rar", RuleID: "rule.rar"},
			{Function: spZipStream, FindingID: "f-zip", RuleID: "rule.zip"},
			{Function: spZipFile, FindingID: "f-zipfile", RuleID: "rule.zipfile"},
		},
	}
	deps := DependencyGraph{componentA: {componentB, componentC}, componentC: {componentB}}
	return componentA, deps, map[ComponentKey]Fragment{componentA: root, componentB: core, componentC: plugin}
}

func serviceProviderVerdicts(t *testing.T, registered map[string][]string, coreImpl, enabled bool) map[string]ExportFindingGraph {
	t.Helper()
	root, deps, fragments := serviceProviderFixture(registered, coreImpl)
	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		EntryRootedOnly: true, ClasspathTargets: true, HierarchyFromSupertypes: true,
		ServiceProviderDispatch: enabled, AmbiguousDispatchUnknown: true,
	})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	plugin := fragments[componentC]
	original := map[string]string{}
	for id, served := range servedFindingIDs(componentC, &plugin) {
		original[served] = id
	}
	out := map[string]ExportFindingGraph{}
	for _, fg := range res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java"}).FindingGraphs {
		if fg.Reachability == ReachabilityUnknown && fg.UnresolvedReason == "" {
			// Served as unreachable (projectreach.findingVerdicts): the
			// suppression that left it unknown is not on its route.
			fg.Reachability = ReachabilityUnreachable
		}
		out[original[fg.FindingID]] = fg
	}
	return out
}

// A class the plugin registers for the service type is a target of a call on
// the service type; with several implementations in the closure the call is
// ambiguous dispatch (unknown), never reachable. A class it does not register
// stays unreached, and so does the overload that does not implement the
// method.
func TestStitch_ServiceProvidersDispatchToRegisteredClasses(t *testing.T) {
	t.Parallel()
	registered := map[string][]string{"tika.parser.Parser": {"plug.PdfParser", "plug.Formats$Zip"}}
	got := serviceProviderVerdicts(t, registered, true, true)
	wantVerdict(t, got, "f-pdf", ReachabilityUnknown, UnresolvedReasonAmbiguousDispatch)
	wantVerdict(t, got, "f-zip", ReachabilityUnknown, UnresolvedReasonAmbiguousDispatch)
	wantVerdict(t, got, "f-zipfile", ReachabilityUnreachable, "")
	wantVerdict(t, got, "f-rar", ReachabilityUnreachable, "")
}

// The sole implementation in the closure, registered, is the call's target.
func TestStitch_SoleRegisteredProviderIsReachable(t *testing.T) {
	t.Parallel()
	got := serviceProviderVerdicts(t, map[string][]string{"tika.parser.Parser": {"plug.PdfParser"}}, false, true)
	wantVerdict(t, got, "f-pdf", ReachabilityReachable, "")
	wantVerdict(t, got, "f-rar", ReachabilityUnreachable, "")
}

// Without the option, or without a registration, or with a registration of a
// class the closure does not declare, nothing joins.
func TestStitch_ServiceProvidersNeedARegistrationAndTheOption(t *testing.T) {
	t.Parallel()
	registered := map[string][]string{"tika.parser.Parser": {"plug.PdfParser"}}
	wantVerdict(t, serviceProviderVerdicts(t, registered, false, false), "f-pdf", ReachabilityUnreachable, "")
	wantVerdict(t, serviceProviderVerdicts(t, nil, false, true), "f-pdf", ReachabilityUnreachable, "")
	absent := map[string][]string{"tika.parser.Parser": {"plug.Missing"}, "tika.parser.Unknown": {"plug.PdfParser"}}
	wantVerdict(t, serviceProviderVerdicts(t, absent, false, true), "f-pdf", ReachabilityUnreachable, "")
}

// The stitch leaves the caller's fragments as they were.
func TestStitch_ServiceProvidersDoNotMutateInput(t *testing.T) {
	t.Parallel()
	root, deps, fragments := serviceProviderFixture(map[string][]string{"tika.parser.Parser": {"plug.PdfParser"}}, true)
	before := append([]Function(nil), fragments[componentC].Functions...)
	if _, err := StitchWithOptions(root, deps, fragments, StitchOptions{HierarchyFromSupertypes: true, ServiceProviderDispatch: true}); err != nil {
		t.Fatalf("stitch: %v", err)
	}
	if !reflect.DeepEqual(fragments[componentC].Functions, before) {
		t.Error("stitch modified the plugin fragment's functions")
	}
}

// service_providers survive the structural re-encode and decode.
func TestFragment_ServiceProvidersRoundTrip(t *testing.T) {
	t.Parallel()
	registered := map[string][]string{"tika.parser.Parser": {"plug.PdfParser", "plug.Formats$Zip"}}
	_, _, fragments := serviceProviderFixture(registered, false)
	data, err := EncodeFragment(fragments[componentC])
	if err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}
	structural, err := StructuralExport(data)
	if err != nil {
		t.Fatalf("StructuralExport: %v", err)
	}
	got, err := DecodeFragment(componentC, structural)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	if !reflect.DeepEqual(got.ServiceProviders, registered) {
		t.Errorf("service providers = %v, want %v", got.ServiceProviders, registered)
	}
}
