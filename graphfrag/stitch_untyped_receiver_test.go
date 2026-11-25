// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

var (
	goApp   = ComponentKey{Purl: "pkg:generic/project"}
	goLib   = ComponentKey{Purl: "pkg:golang/example.com/hash", Version: "1.0.0"}
	rustLib = ComponentKey{Purl: "pkg:cargo/hashlib", Version: "1.0.0"}
)

func verdictsOf(t *testing.T, root, dep ComponentKey, fragments map[ComponentKey]Fragment) map[string]ExportFindingGraph {
	t.Helper()
	res, err := StitchWithOptions(root, DependencyGraph{root: {dep}}, fragments, StitchOptions{
		EntryRootedOnly: true, ClasspathTargets: true, HierarchyFromSupertypes: true, AmbiguousDispatchUnknown: true,
	})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	library := fragments[dep]
	original := map[string]string{}
	for id, served := range servedFindingIDs(dep, &library) {
		original[served] = id
	}
	out := map[string]ExportFindingGraph{}
	for _, fg := range res.ToCallgraphExport(root, ScanMeta{}).FindingGraphs {
		out[original[fg.FindingID]] = fg
	}
	return out
}

// wantNoRoute checks that a finding has no route and no call the stitch
// could not resolve on the way to it: reachability is then unreachable, or a
// bare unknown when the stitch refused a call elsewhere, which a consumer
// serves as unreachable.
func wantNoRoute(t *testing.T, got map[string]ExportFindingGraph, id string) {
	t.Helper()
	fg, ok := got[id]
	if !ok {
		t.Fatalf("%s: no finding graph; got %v", id, got)
	}
	if fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Errorf("%s: reachability = %q, reason = %q; want no route and no reason", id, fg.Reachability, fg.UnresolvedReason)
	}
}

// goInterfaceFixture is `h := hash.Standard(); h.Sum(data)`: the project
// calls a method of an interface a dependency declares. A Go producer exports
// the call name_only, keyed by the interface's own method.
func goInterfaceFixture(projectAlgo string) map[ComponentKey]Fragment {
	const main = "example.com/app.main"
	return map[ComponentKey]Fragment{
		goApp: {
			Component: goApp, Module: "example.com/app", GraphAlgoVersion: projectAlgo,
			Functions: []Function{{Signature: main}},
			ExternalCalls: []ExternalCall{
				{Caller: main, TargetSignature: "example.com/hash.Standard", Resolution: ResolutionExact, MethodName: "Standard", AssignedVar: "h", CallSite: 10},
				{
					Caller: main, TargetSignature: "example.com/hash.(Hasher).Sum", Resolution: ResolutionNameOnly,
					DeclaredType: "example.com/hash.Hasher", MethodName: "Sum", Arity: 1, ReceiverVar: "h", CallSite: 11,
				},
			},
		},
		goLib: {
			Component: goLib, Module: "example.com/hash", GraphAlgoVersion: GraphAlgoVersionGo,
			Functions: []Function{
				{Signature: "example.com/hash.Standard"},
				{Signature: "example.com/hash.(Hasher).Sum"},
				{Signature: "example.com/hash.(standard).Sum"},
				{Signature: "example.com/hash.(plain).Sum"},
				{Signature: "example.com/hash.(table).Reset"},
				{Signature: "example.com/hash.Sum"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "example.com/hash.(standard).Sum", FindingID: "f-standard", RuleID: "rule.digest"},
				{Function: "example.com/hash.(plain).Sum", FindingID: "f-plain", RuleID: "rule.copy"},
				{Function: "example.com/hash.(table).Reset", FindingID: "f-reset", RuleID: "rule.table"},
				{Function: "example.com/hash.Sum", FindingID: "f-free", RuleID: "rule.free"},
			},
		},
	}
}

// A Go call on an interface a dependency declares names no implementation.
// The interface's own method has no body, so matching the call to it alone
// read every implementation as unreachable: the methods of that name may run,
// and what they reach is unknown. A function of that name is no method of
// any type, so the call cannot run it.
func TestStitch_GoInterfaceCallReadsItsImplementationsUnknown(t *testing.T) {
	t.Parallel()
	got := verdictsOf(t, goApp, goLib, goInterfaceFixture(GraphAlgoVersionGo))
	wantVerdict(t, got, "f-standard", ReachabilityUnknown, UnresolvedReasonDispatch)
	wantVerdict(t, got, "f-plain", ReachabilityUnknown, UnresolvedReasonDispatch)
	wantNoRoute(t, got, "f-reset")
	wantNoRoute(t, got, "f-free")
}

// The same call sites from a project of another ecosystem keep the match to
// the declaration alone.
func TestStitch_InterfaceKeyedNameOnlyCallIsUnchangedOutsideGo(t *testing.T) {
	t.Parallel()
	got := verdictsOf(t, goApp, goLib, goInterfaceFixture(GraphAlgoVersion))
	for _, id := range []string{"f-standard", "f-plain", "f-reset", "f-free"} {
		wantNoRoute(t, got, id)
	}
}

// rustUntypedFixture is `let h = hashlib::standard(); h.sum(data);`, the same
// on the result of a function whose return type names no type, and
// `bytes.iter()` on a parameter. A Rust producer that cannot type a receiver
// keys the method call in the project's own crate, where nothing declares it.
func rustUntypedFixture(projectAlgo string) map[ComponentKey]Fragment {
	const main = "app.main"
	return map[ComponentKey]Fragment{
		goApp: {
			Component: goApp, Module: "app", GraphAlgoVersion: projectAlgo,
			Functions: []Function{{Signature: main}},
			ExternalCalls: []ExternalCall{
				{Caller: main, TargetSignature: "hashlib.standard", Resolution: ResolutionExact, MethodName: "standard", AssignedVar: "h", CallSite: 7},
				{Caller: main, TargetSignature: "app.sum", Resolution: ResolutionExact, MethodName: "sum", ReceiverVar: "h", CallSite: 8},
				{Caller: main, TargetSignature: "app.iter", Resolution: ResolutionExact, MethodName: "iter", ReceiverVar: "bytes", CallSite: 9},
				{Caller: main, TargetSignature: "hashlib.generic", Resolution: ResolutionExact, MethodName: "generic", AssignedVar: "g", CallSite: 10},
				{Caller: main, TargetSignature: "app.reset", Resolution: ResolutionExact, MethodName: "reset", ReceiverVar: "g", CallSite: 11},
			},
		},
		rustLib: {
			Component: rustLib, Module: "hashlib", GraphAlgoVersion: GraphAlgoVersionRust,
			Supertypes: map[string][]string{"hashlib.Standard": {"hashlib.Hasher"}, "hashlib.Plain": {"hashlib.Hasher"}},
			Functions: []Function{
				{Signature: "hashlib.standard", ReturnType: "Box<dyn Hasher>"},
				{Signature: "hashlib.generic", ReturnType: "T"},
				{Signature: "hashlib.(Hasher).sum"},
				{Signature: "hashlib.(Standard).sum"},
				{Signature: "hashlib.(Plain).sum"},
				{Signature: "hashlib.(Ledger).sum"},
				{Signature: "hashlib.(Ledger).reset"},
				{Signature: "hashlib.(Table).iter"},
				{Signature: "hashlib.sum"},
			},
			CryptoOperations: []CryptoOperation{
				{Function: "hashlib.(Standard).sum", FindingID: "f-standard", RuleID: "rule.digest"},
				{Function: "hashlib.(Plain).sum", FindingID: "f-plain", RuleID: "rule.copy"},
				{Function: "hashlib.(Table).iter", FindingID: "f-iter", RuleID: "rule.table"},
				{Function: "hashlib.sum", FindingID: "f-free", RuleID: "rule.free"},
				{Function: "hashlib.(Ledger).sum", FindingID: "f-ledger", RuleID: "rule.ledger"},
				{Function: "hashlib.(Ledger).reset", FindingID: "f-reset", RuleID: "rule.reset"},
			},
		},
	}
}

// A Rust method call on a value a dependency returned, which the project
// could not type, runs a method of the type that dependency function declares
// it returns, or of a type implementing that trait: what it reaches is
// unknown, not unreachable. A method of that name on another type, a free
// function, a call on a value whose producer's return type names no type, and
// a call on any other untyped value stay out.
func TestStitch_RustUntypedCallOnADependencyValueReadsUnknown(t *testing.T) {
	t.Parallel()
	got := verdictsOf(t, goApp, rustLib, rustUntypedFixture(GraphAlgoVersionRust))
	wantVerdict(t, got, "f-standard", ReachabilityUnknown, UnresolvedReasonDispatch)
	wantVerdict(t, got, "f-plain", ReachabilityUnknown, UnresolvedReasonDispatch)
	for _, id := range []string{"f-ledger", "f-reset", "f-iter", "f-free"} {
		wantNoRoute(t, got, id)
	}
}

func TestRustReturnedTypeName(t *testing.T) {
	t.Parallel()
	for returned, want := range map[string]string{
		"Box<dyn Hasher>": "Hasher", "ClientBuilder": "ClientBuilder", "Self": "Owner", "&mut Self": "Owner",
		"Result<Client, Error>": "Client", "crate::Result<Client>": "Client", "Option<Arc<dyn tls::Signer + Send>>": "Signer",
		"impl Hasher + 'static": "Hasher", "&'a Config<T>": "Config", "Vec<u8>": "Vec",
		"": "", "T": "", "(A, B)": "", "u64": "", "[u8; 32]": "",
	} {
		if got := rustReturnedTypeName(returned, "hashlib.Owner"); got != want {
			t.Errorf("%q: type %q, want %q", returned, got, want)
		}
	}
}

func TestStitch_UntypedCallKeyedInTheProjectIsUnchangedOutsideRust(t *testing.T) {
	t.Parallel()
	got := verdictsOf(t, goApp, rustLib, rustUntypedFixture(GraphAlgoVersion))
	for _, id := range []string{"f-standard", "f-plain", "f-ledger", "f-reset", "f-iter", "f-free"} {
		wantNoRoute(t, got, id)
	}
}
