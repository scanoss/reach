// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

const (
	surfaceCloseFn = "com.itextpdf.text.pdf.(PdfDocument).close#0"
	surfaceBaseFn  = "com.itextpdf.text.pdf.(PdfWriter).flushAcroFields#0"
	surfaceCopyFn  = "com.itextpdf.text.pdf.(PdfCopy).flushAcroFields#0"
)

// concreteSurfaceFixture is reach-engine-v2 nor-304: the client closes a
// PdfDocument, whose close calls writer.flushAcroFields() on a field declared
// PdfWriter. PdfWriter's method has a body (empty); PdfCopy overrides it, and
// only the override decrypts. A crypto operation behind each body tells the
// two routes apart.
func concreteSurfaceFixture(abstractMethods, baseAbstract bool, receiverType string) (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
	root := Fragment{
		Component: componentA,
		Functions: []Function{{Signature: "com.acme.app.(Report).write#0"}},
		ExternalCalls: []ExternalCall{{
			Caller: "com.acme.app.(Report).write#0", TargetSignature: surfaceCloseFn,
			Resolution: ResolutionExact, MethodName: "close", CallSite: 10,
		}},
	}
	base := "com.itextpdf.text.pdf.PdfWriter.flushAcroFields(): void"
	dep := Fragment{
		Component:       componentC,
		AbstractMethods: abstractMethods,
		Functions: []Function{
			{Signature: surfaceCloseFn, CanonicalSignature: "com.itextpdf.text.pdf.PdfDocument.close(): void"},
			{Signature: surfaceBaseFn, FunctionName: "com.itextpdf.text.pdf.PdfWriter.flushAcroFields", CanonicalSignature: base, Abstract: baseAbstract},
			{Signature: surfaceCopyFn, FunctionName: "com.itextpdf.text.pdf.PdfCopy.flushAcroFields", CanonicalSignature: "com.itextpdf.text.pdf.PdfCopy.flushAcroFields(): void", CompatibleCanonicalSignatures: []string{base}},
		},
		InternalEdges: []InternalEdge{{
			Caller: surfaceCloseFn, Callee: surfaceBaseFn, Resolution: ResolutionExact,
			MethodName: "flushAcroFields", CallSite: 878, ReceiverVar: "writer", ResolvedReceiverType: receiverType,
		}},
		CryptoOperations: []CryptoOperation{
			{Function: surfaceCopyFn, FindingID: "f-copy", RuleID: "rule.cipher"},
		},
	}
	if !baseAbstract {
		dep.CryptoOperations = append(dep.CryptoOperations, CryptoOperation{Function: surfaceBaseFn, FindingID: "f-base", RuleID: "rule.digest"})
	}
	return componentA, DependencyGraph{componentA: {componentC}}, map[ComponentKey]Fragment{componentA: root, componentC: dep}
}

func concreteSurfaceVerdicts(t *testing.T, abstractMethods, baseAbstract bool, receiverType string) map[string]ExportFindingGraph {
	t.Helper()
	root, deps, fragments := concreteSurfaceFixture(abstractMethods, baseAbstract, receiverType)
	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{
		EntryRootedOnly: true, ClasspathTargets: true, HierarchyFromSupertypes: true, AmbiguousDispatchUnknown: true,
	})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	dep := fragments[componentC]
	original := map[string]string{}
	for id, served := range servedFindingIDs(componentC, &dep) {
		original[served] = id
	}
	out := map[string]ExportFindingGraph{}
	for _, fg := range res.ToCallgraphExport(root, ScanMeta{Ecosystem: "java"}).FindingGraphs {
		out[original[fg.FindingID]] = fg
	}
	return out
}

func wantVerdict(t *testing.T, got map[string]ExportFindingGraph, id, reachability, reason string) {
	t.Helper()
	fg, ok := got[id]
	if !ok {
		t.Fatalf("%s: no finding graph; got %v", id, got)
	}
	if fg.Reachability != reachability || fg.UnresolvedReason != reason {
		t.Errorf("%s: reachability = %q, reason = %q; want %q, %q", id, fg.Reachability, fg.UnresolvedReason, reachability, reason)
	}
}

// A call on a type whose method has a body may run that body or any override:
// the sole override is ambiguous dispatch (unknown), the base body stays
// reachable.
func TestStitch_OverrideOfConcreteMethodIsAmbiguous(t *testing.T) {
	t.Parallel()
	got := concreteSurfaceVerdicts(t, true, false, "")
	wantVerdict(t, got, "f-copy", ReachabilityUnknown, UnresolvedReasonAmbiguousDispatch)
	wantVerdict(t, got, "f-base", ReachabilityReachable, "")
}

// The sole implementation of an abstract method is the call's target.
func TestStitch_SoleImplementationOfAbstractMethodTraverses(t *testing.T) {
	t.Parallel()
	got := concreteSurfaceVerdicts(t, true, true, "")
	wantVerdict(t, got, "f-copy", ReachabilityReachable, "")
}

// A fragment that does not mark abstract methods (graph-fragment-1.23 and
// older) cannot tell an empty method from an abstract one: the stitch reads
// its methods as before.
func TestStitch_UnmarkedFragmentKeepsSoleOverride(t *testing.T) {
	t.Parallel()
	got := concreteSurfaceVerdicts(t, false, false, "")
	wantVerdict(t, got, "f-copy", ReachabilityReachable, "")
}

// A receiver whose runtime type the producer resolved picks the body: the
// override when it is the subclass, the base method alone when it is the
// declared class.
func TestStitch_ResolvedReceiverPicksConcreteCandidate(t *testing.T) {
	t.Parallel()
	got := concreteSurfaceVerdicts(t, true, false, "com.itextpdf.text.pdf.PdfCopy")
	wantVerdict(t, got, "f-copy", ReachabilityReachable, "")

	got = concreteSurfaceVerdicts(t, true, false, "com.itextpdf.text.pdf.PdfWriter")
	wantVerdict(t, got, "f-copy", ReachabilityUnreachable, "")
	wantVerdict(t, got, "f-base", ReachabilityReachable, "")
}

// A structural graph re-encoded for annotate keeps its abstract marks.
func TestFragment_AbstractMethodsRoundTrip(t *testing.T) {
	t.Parallel()
	_, _, fragments := concreteSurfaceFixture(true, true, "")
	data, err := EncodeFragment(fragments[componentC])
	if err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}
	got, err := DecodeFragment(componentC, data)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	if !got.AbstractMethods {
		t.Error("abstract_methods lost in the round trip")
	}
	for _, fn := range got.Functions {
		if want := fn.Signature == surfaceBaseFn; fn.Abstract != want {
			t.Errorf("%s: abstract = %v, want %v", fn.Signature, fn.Abstract, want)
		}
	}
}
