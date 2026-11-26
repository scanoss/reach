// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package appreach

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	gf "github.com/scanoss/reach/graphfrag"
)

// The closure below is invented. The application calls alpha's A.run, which
// calls A.hash, where alpha has an annotated operation; alpha's A.unused holds
// another one nothing calls. beta is a dependency the application declares
// but never calls. gamma has no graph and is the only way to delta.
//
//	app -> alpha (A.run -> A.hash: op-hash; A.unused: op-unused)
//	app -> beta  (B.seal: op-seal)
//	app -> gamma (no graph) -> delta (D.wrap: op-wrap)
var (
	alpha = ComponentKey{Purl: "pkg:maven/org.example/alpha", Version: "1.0"}
	beta  = ComponentKey{Purl: "pkg:maven/org.example/beta", Version: "2.0"}
	gamma = ComponentKey{Purl: "pkg:maven/org.example/gamma", Version: "3.0"}
	delta = ComponentKey{Purl: "pkg:maven/org.example/delta", Version: "4.0"}
)

func javaFunction(owner, name string) gf.Function {
	pkg := "org.example." + owner
	typ := strings.ToUpper(owner[:1])
	return gf.Function{
		Signature:          pkg + ".(" + typ + ")." + name + "#0",
		FunctionName:       pkg + "." + typ + "." + name,
		CanonicalSignature: pkg + "." + typ + "." + name + "(): void",
		Visibility:         "public", OwnerVisibility: "public",
	}
}

func op(function gf.Function, id, file string, line int) gf.CryptoOperation {
	return gf.CryptoOperation{Function: function.Signature, FindingID: id, RuleID: "invented-" + id, FilePath: file, StartLine: line, EndLine: line}
}

func closureFixture() Input {
	run, hash, unused := javaFunction("alpha", "run"), javaFunction("alpha", "hash"), javaFunction("alpha", "unused")
	seal := javaFunction("beta", "seal")
	wrap := javaFunction("delta", "wrap")
	fragments := map[ComponentKey]Fragment{
		alpha: {
			Component: alpha,
			Functions: []gf.Function{run, hash, unused},
			InternalEdges: []gf.InternalEdge{
				{Caller: run.Signature, Callee: hash.Signature, Resolution: gf.ResolutionExact, MethodName: "hash", CallSite: 4},
			},
			CryptoOperations: []gf.CryptoOperation{
				op(hash, "op-hash", "org/example/alpha/A.java", 9),
				op(unused, "op-unused", "org/example/alpha/A.java", 20),
			},
		},
		beta:  {Component: beta, Module: "org.example:beta-renamed", Functions: []gf.Function{seal}, CryptoOperations: []gf.CryptoOperation{op(seal, "op-seal", "B.java", 3)}},
		delta: {Component: delta, Functions: []gf.Function{wrap}, CryptoOperations: []gf.CryptoOperation{op(wrap, "op-wrap", "D.java", 7)}},
	}
	sites := &gf.GraphFragmentExport{
		SchemaVersion: gf.SchemaVersion,
		Functions: []gf.GraphFragmentFunction{
			{Key: "app.(Main).main#0", FunctionName: "app.Main.main", CanonicalSignature: "app.Main.main(): void"},
			{Key: "app.(Main).idle#0", FunctionName: "app.Main.idle", CanonicalSignature: "app.Main.idle(): void"},
		},
		ExternalCalls: []gf.GraphFragmentExternal{{
			CallerKey: "app.(Main).main#0", TargetKey: run.Signature, TargetFunctionName: run.FunctionName,
			TargetCanonicalSignature: run.CanonicalSignature, Resolution: string(gf.ResolutionExact), MethodName: "run", Line: 12,
		}},
	}
	return Input{
		Keys:      []ComponentKey{alpha, beta, gamma, delta},
		Direct:    []string{alpha.Purl, beta.Purl, gamma.Purl},
		Edges:     map[ComponentKey][]ComponentKey{gamma: {delta}},
		Fragments: fragments,
		CallSites: sites,
	}
}

func stitchID(key ComponentKey, module, file string, line int, id string) string {
	return ComputeFindingID(DepPrefixedPath(file, module, key.Version), line, "invented-"+id)
}

func TestClosureRun(t *testing.T) {
	t.Parallel()
	in := closureFixture()
	before := in.Fragments[alpha].Module
	c := NewClosure(in)
	if in.Fragments[alpha].Module != before {
		t.Fatal("NewClosure wrote its input's fragments")
	}
	if c.Root != Root || c.Meta.Ecosystem != "java" || c.Meta.RootModule != Root.Purl || c.Meta.SchemaVersion != gf.CallgraphSchemaVersion {
		t.Fatalf("root %v meta %+v", c.Root, c.Meta)
	}
	if got := c.Fragments[alpha].Module; got != "org.example:alpha" {
		t.Errorf("alpha module %q, want the purl's", got)
	}
	if got := c.Fragments[beta].Module; got != "org.example:beta-renamed" {
		t.Errorf("beta module %q, want its own", got)
	}
	if fns := c.Fragments[Root].Functions; len(fns) != 1 || fns[0].Signature != "app.(Main).main#0" {
		t.Errorf("application functions %v, want only the call-site caller", fns)
	}
	if !reflect.DeepEqual(c.ViaMissingOnly, map[ComponentKey]bool{delta: true}) {
		t.Errorf("via missing only %v, want delta", c.ViaMissingOnly)
	}

	out, err := c.Run(context.Background(), RunConfig{IncludeCallChains: true, MaxChains: 1})
	if err != nil {
		t.Fatal(err)
	}
	hashID := stitchID(alpha, "org.example:alpha", "org/example/alpha/A.java", 9, "op-hash")
	unusedID := stitchID(alpha, "org.example:alpha", "org/example/alpha/A.java", 20, "op-unused")
	if v := out.Verdicts[hashID]; v != (Verdict{Reachability: VerdictReachable}) {
		t.Errorf("op-hash verdict %+v, want reachable", v)
	}
	if v, ok := out.Verdicts[unusedID]; ok && v.Reachability != VerdictUnreachable {
		t.Errorf("op-unused verdict %+v, want unreachable or none", v)
	}
	var chain []ExportChainNode
	for _, g := range out.Callgraph.FindingGraphs {
		if g.FindingID == hashID {
			if len(g.CallChains) != 1 {
				t.Fatalf("op-hash chains %d, want 1", len(g.CallChains))
			}
			chain = g.CallChains[0]
		}
	}
	var names []string
	for _, n := range chain {
		names = append(names, n.FunctionName)
	}
	if want := []string{"app.Main.main", "org.example.alpha.A.run", "org.example.alpha.A.hash"}; !reflect.DeepEqual(names, want) {
		t.Errorf("op-hash chain %v, want %v", names, want)
	}
	if out.Result == nil {
		t.Error("no stitch result")
	}

	owners := FindingOwners(c.Root, c.Fragments)
	if owners[hashID] != alpha || owners[stitchID(delta, "org.example:delta", "D.java", 7, "op-wrap")] != delta {
		t.Errorf("owners %v", owners)
	}
	if ids := StitchIDs(alpha, c.Fragments[alpha]); ids["op-hash"] != hashID || ids["op-unused"] != unusedID {
		t.Errorf("stitch ids %v", ids)
	}

	// Without chains the export carries verdicts only.
	bare, err := NewClosure(closureFixture()).Run(context.Background(), RunConfig{})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bare.Verdicts, out.Verdicts) || bare.Callgraph.Functions != nil {
		t.Errorf("verdicts differ without chains, or functions kept: %+v", bare.Verdicts)
	}
	for _, g := range bare.Callgraph.FindingGraphs {
		if g.CallChains != nil || g.CallChainIndexes != nil {
			t.Errorf("%s keeps chains", g.FindingID)
		}
	}
}

// A canceled context fails the run at the stitch, with the context's error.
func TestClosureRunCanceled(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := NewClosure(closureFixture()).Run(ctx, RunConfig{})
	var runErr *RunError
	if !errors.As(err, &runErr) || runErr.Stage != "stitch" || !errors.Is(err, context.Canceled) {
		t.Fatalf("err %v, want a stitch RunError wrapping context.Canceled", err)
	}
	if err.Error() != "application reachability stitch: context canceled" {
		t.Errorf("message %q", err.Error())
	}
}

func TestFindingVerdicts(t *testing.T) {
	t.Parallel()
	partial := &gf.ExportFindingAnalysis{CallChains: "partial"}
	complete := &gf.ExportFindingAnalysis{CallChains: "complete"}
	got := FindingVerdicts([]ExportFindingGraph{
		{FindingID: "reach", Reachability: "reachable", CallChains: [][]gf.ExportChainNode{{{}, {}}}},
		{FindingID: "reach-interned", Reachability: "reachable", CallChainIndexes: [][]int{{0}, {1, 2}}},
		// Reachable only by the dependency's entry-point index: no call reaches the finding.
		{FindingID: "index", Reachability: "reachable", CallChains: [][]gf.ExportChainNode{{{}}}},
		{FindingID: "ambiguous", Reachability: "unknown", UnresolvedReason: gf.UnresolvedReasonAmbiguousDispatch},
		{FindingID: "nameonly", Reachability: "unknown", UnresolvedReason: gf.UnresolvedReasonDispatch},
		{FindingID: "capped", Reachability: "unknown", Analysis: partial},
		// The stitched export's closure-wide unknown: no route, nothing unresolved on the way.
		{FindingID: "global", Reachability: "unknown", Analysis: complete},
		{FindingID: "none", Reachability: "unreachable"},
		{FindingID: "field", Reachability: gf.ReachabilityNotApplicable},
	})
	want := map[string]Verdict{
		"reach":          {VerdictReachable, ""},
		"reach-interned": {VerdictReachable, ""},
		"index":          {VerdictUnknown, ReasonDependencyEntryPointOnly},
		"ambiguous":      {VerdictUnknown, ReasonAmbiguousDispatch},
		"nameonly":       {VerdictUnknown, ReasonUnresolvedDispatch},
		"capped":         {VerdictUnknown, ReasonSearchCapped},
		"global":         {VerdictUnreachable, ""},
		"none":           {VerdictUnreachable, ""},
		"field":          {VerdictUnknown, ReasonNoContainingFunction},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("verdicts %v, want %v", got, want)
	}
}

func TestBuildDependencyGraph(t *testing.T) {
	t.Parallel()
	key := func(name string) ComponentKey { return ComponentKey{Purl: "pkg:maven/g/" + name, Version: "1"} }
	a, b, c, d, gone := key("a"), key("b"), key("c"), key("d"), key("gone")
	present := map[ComponentKey]Fragment{a: {}, b: {}, c: {}, d: {}}
	// application -> a -> gone -> b; application -> c; d is pinned but no edge names it.
	edges := map[ComponentKey][]ComponentKey{a: {gone}, gone: {b}}
	deps, via := BuildDependencyGraph(Root, []ComponentKey{a, gone, b, c, d}, []string{a.Purl, c.Purl}, edges, present)
	want := DependencyGraph{Root: {a, c, d}, a: {b}, b: nil, c: nil, d: nil}
	if !reflect.DeepEqual(deps, want) {
		t.Errorf("graph %v, want %v (gone spliced out, d on the classpath)", deps, want)
	}
	if !reflect.DeepEqual(via, map[ComponentKey]bool{b: true}) {
		t.Errorf("reached only through a missing graph: %v, want only b", via)
	}
}

// servedChains is a finding graph as Run holds it after hydration: five
// chains, the first with a frame nothing could name.
func servedChains() []ExportFindingGraph {
	named := func(sig string) ExportChainNode { return ExportChainNode{FunctionKey: sig, CanonicalSignature: sig} }
	chains := [][]ExportChainNode{{{FunctionKey: "blank"}}}
	indexes := [][]int{{0}}
	for i, entry := range []string{"a.A.run(): void", "b.B.run(): void", "c.C.run(): void", "d.D.run(): void"} {
		chains = append(chains, []ExportChainNode{named(entry), named("example.Socket.connect(): void")})
		indexes = append(indexes, []int{i + 1, i + 1})
	}
	return []ExportFindingGraph{
		{FindingID: "many", CallChains: chains, CallChainIndexes: indexes},
		{FindingID: "one", CallChains: [][]ExportChainNode{{named("example.Other.run(): void")}}},
	}
}

func TestKeepServedChains(t *testing.T) {
	t.Parallel()
	graphs := servedChains()
	KeepServedChains(graphs, 2)
	if got, want := graphs[0].CallChainIndexes, [][]int{{1, 1}, {2, 2}}; !reflect.DeepEqual(got, want) {
		t.Errorf("indexes = %v, want %v (the named chains, in step)", got, want)
	}
	if len(graphs[0].CallChains) != 2 || graphs[0].CallChains[0][0].CanonicalSignature != "a.A.run(): void" {
		t.Errorf("chains %v", graphs[0].CallChains)
	}
	if len(graphs[1].CallChains) != 1 {
		t.Errorf("one-chain graph kept %d", len(graphs[1].CallChains))
	}

	// A nameless frame without indexes is left for the renderer to refuse.
	graphs = servedChains()
	graphs[0].CallChainIndexes = nil
	KeepServedChains(graphs, 1)
	if len(graphs[0].CallChains) != 5 {
		t.Errorf("kept %d chains, want all 5", len(graphs[0].CallChains))
	}
}

func TestComputeFindingID(t *testing.T) {
	t.Parallel()
	if got := ComputeFindingID("", 0, ""); got != "" {
		t.Errorf("empty id %q", got)
	}
	// sha256("m@1/F.java:3:r")[:8], the stitch's own derivation.
	if got := ComputeFindingID(DepPrefixedPath("F.java", "m", "1"), 3, "r"); got != "08992301" {
		t.Errorf("id %q", got)
	}
	if got := DepPrefixedPath("F.java", "", "1"); got != "F.java" {
		t.Errorf("unprefixed path %q", got)
	}
}
