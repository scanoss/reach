// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package appreach

import (
	"context"
	"errors"
	"math"
	"slices"

	gf "github.com/scanoss/reach/graphfrag"
)

// Reachability verdicts.
const (
	VerdictReachable   = "reachable"
	VerdictUnreachable = "unreachable"
	VerdictUnknown     = "unknown"
)

// Reasons an unknown verdict carries.
const (
	// ReasonAmbiguousDispatch: the application reaches the finding only
	// through an interface call with several implementations in the closure.
	ReasonAmbiguousDispatch = gf.UnresolvedReasonAmbiguousDispatch
	// ReasonUnresolvedDispatch: only through a call linked by name.
	ReasonUnresolvedDispatch = gf.UnresolvedReasonDispatch
	// ReasonSearchCapped: the route search hit a cap before it could decide.
	ReasonSearchCapped = "search_capped"
	// ReasonNoContainingFunction: the finding sits outside any function (a
	// field or static initializer), so no call can reach it.
	ReasonNoContainingFunction = "no_containing_function"
	// ReasonDependencyEntryPointOnly: the application reaches a function that
	// the dependency's own entry-point index says reaches the finding, but
	// the stitch holds no route of calls to it.
	ReasonDependencyEntryPointOnly = "dependency_entry_point_only"
	// ReasonDependencyWithoutGraph: every dependency path from the
	// application to the finding's dependency crosses a dependency with no
	// graph, whose calls are therefore not in the graph.
	ReasonDependencyWithoutGraph = "dependency_without_graph"
)

// Root is the default stitch root standing for the application.
var Root = ComponentKey{Purl: "pkg:generic/project"}

// Verdict is one finding's reachability, and why it is unknown when it is.
type Verdict struct {
	Reachability string
	Reason       string
}

// StitchWithContext runs gf.StitchWithOptions on its own goroutine so ctx's
// deadline can abort a pathologically large graph walk: StitchWithOptions
// itself takes no context and never checks cancellation, so without this a
// caller's timeout budget is unenforceable once the graphs are loaded.
func StitchWithContext(ctx context.Context, root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, opts StitchOptions) (*Result, error) {
	type outcome struct {
		res *Result
		err error
	}
	ch := make(chan outcome, 1)
	go func() {
		res, err := gf.StitchWithOptions(root, deps, fragments, opts)
		ch <- outcome{res, err}
	}()
	select {
	case o := <-ch:
		return o.res, o.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Input is an application and the loaded components of its pinned closure.
type Input struct {
	// Root is the stitch root standing for the application; zero is Root.
	Root ComponentKey
	// Keys are the pinned components, in order (Pins.Keys). The first one's
	// ecosystem names the export's.
	Keys []ComponentKey
	// Direct are the purls the application declares (Pins.Direct).
	Direct []string
	// Edges are the dependency edges among the pinned components
	// (Pins.RequestEdges or Pins.EdgesFrom).
	Edges map[ComponentKey][]ComponentKey
	// Fragments are the pinned components that have a graph. A fragment that
	// names no module is given the one its purl implies (PurlToModule).
	Fragments map[ComponentKey]Fragment
	// CallSites is the application's graph-fragment document; only its calls
	// into dependencies are read (see ApplicationFragment).
	CallSites *gf.GraphFragmentExport
}

// Closure is an application's closure ready to stitch.
type Closure struct {
	Root ComponentKey
	// Fragments are the input's fragments, modules named, and the
	// application's own under Root. A caller may read them (to plan selector
	// calls) but must not change them.
	Fragments map[ComponentKey]Fragment
	// Deps is the dependency graph the stitch walks (see BuildDependencyGraph).
	Deps DependencyGraph
	// ViaMissingOnly holds the components with a graph that the application
	// reaches only through components without one.
	ViaMissingOnly map[ComponentKey]bool
	// Meta is the scan metadata of the export.
	Meta ScanMeta
}

// NewClosure builds the closure the stitch walks from the application's call
// sites. Input's fragments are copied, never written.
func NewClosure(in Input) *Closure {
	root := in.Root
	if root == (ComponentKey{}) {
		root = Root
	}
	fragments := make(map[ComponentKey]Fragment, len(in.Fragments)+1)
	for k, frag := range in.Fragments {
		// A component indexed on its own may record no module. The callgraph
		// export then prefixes a finding's path with the purl, while a
		// findings envelope and the stitch's translation of a dependency's
		// entry-point index do not prefix it at all: the three would disagree
		// on every dependency finding id, and findings proven through the
		// index would be dropped. Name the module once, for all three.
		if frag.Module == "" {
			frag.Module = PurlToModule(k.Purl)
		}
		fragments[k] = frag
	}
	deps, viaMissingOnly := BuildDependencyGraph(root, in.Keys, in.Direct, in.Edges, fragments)
	fragments[root] = ApplicationFragment(root, in.CallSites)
	ecosystem := ""
	if len(in.Keys) > 0 {
		ecosystem = EcosystemForPurl(in.Keys[0].Purl)
	}
	return &Closure{
		Root:           root,
		Fragments:      fragments,
		Deps:           deps,
		ViaMissingOnly: viaMissingOnly,
		Meta:           ScanMeta{SchemaVersion: gf.CallgraphSchemaVersion, RootModule: root.Purl, Ecosystem: ecosystem},
	}
}

// RunConfig is what one run of a closure serves.
type RunConfig struct {
	// SelectorCalls are calls whose unresolved arguments the stitch traces
	// across the closure (StitchOptions.SelectorCalls); their values are
	// read from Outcome.Result.SelectorValues.
	SelectorCalls []gf.SelectorCall
	// IncludeCallChains keeps the chains in the export. Without it, the
	// export carries verdicts only: no functions and no chains.
	IncludeCallChains bool
	// MaxChains is how many chains a finding keeps: the first ones whose
	// frames all have identity. Zero or less keeps every one.
	MaxChains int
}

// Outcome is a run's result.
type Outcome struct {
	// Result is the stitch's own result.
	Result *Result
	// Callgraph is the stitched export, its chains trimmed to the served ones
	// (or dropped) and their frames hydrated.
	Callgraph CallgraphExport
	// Verdicts are the served verdicts by stitch finding id (FindingVerdicts).
	// A finding of the closure without one has no route: it is unreachable.
	Verdicts map[string]Verdict
}

// RunError is a failed run: the stage that failed (stitch or hydrate) and
// its error. A canceled or expired ctx fails as the stitch stage with ctx's
// error.
type RunError struct {
	Stage string
	Err   error
}

func (e *RunError) Error() string {
	return "application reachability " + e.Stage + ": " + e.Err.Error()
}

func (e *RunError) Unwrap() error { return e.Err }

// errInternedFrames is the hydrate stage's failure: an interned chain frame
// the export's function catalog cannot name.
var errInternedFrames = errors.New("interned callgraph frames")

// Run decides, for every annotated operation of the closure, whether the
// application's call sites reach it. The stitcher options were validated
// against labeled truth (a labeled Java benchmark): classpath targets,
// hierarchy from supertypes, and ambiguous dispatch served unknown. Closure
// targets stay off: on that benchmark they resolve the edges the Maven tree
// omits but cost a correct verdict and win none. A Python component resolves
// what its requires leave unresolved against the whole pinned environment
// (EnvironmentTargets): Python imports anything installed, and a lock's
// requires miss optional imports.
func (c *Closure) Run(ctx context.Context, cfg RunConfig) (*Outcome, error) {
	res, err := StitchWithContext(ctx, c.Root, c.Deps, c.Fragments, StitchOptions{
		EntryRootedOnly:          true,
		ClasspathTargets:         true,
		EnvironmentTargets:       []string{"python"},
		HierarchyFromSupertypes:  true,
		ServiceProviderDispatch:  true,
		AmbiguousDispatchUnknown: true,
		SelectorCalls:            cfg.SelectorCalls,
		SuppressedSummaryOnly:    true,
	})
	if err != nil {
		return nil, &RunError{Stage: "stitch", Err: err}
	}
	cg := res.ToCallgraphExport(c.Root, c.Meta)
	out := &Outcome{Result: res, Verdicts: FindingVerdicts(cg.FindingGraphs)}
	if !cfg.IncludeCallChains {
		// The verdicts are read; nothing serves a chain.
		cg.Functions = nil
		for i := range cg.FindingGraphs {
			cg.FindingGraphs[i].CallChains, cg.FindingGraphs[i].CallChainIndexes = nil, nil
		}
	} else {
		if !cg.HydrateChainIdentities() {
			return nil, &RunError{Stage: "hydrate", Err: errInternedFrames}
		}
		limit := cfg.MaxChains
		if limit <= 0 {
			limit = math.MaxInt
		}
		KeepServedChains(cg.FindingGraphs, limit)
	}
	out.Callgraph = cg
	return out, nil
}

// BuildDependencyGraph builds the stitch's dependency graph over the
// components that have a graph (present). A component without one is spliced
// out (its dependencies hang from its parents), so the classpath stays whole;
// the components reachable from the application only through such a
// component are returned in viaMissingOnly. A pinned dependency no edge
// reaches hangs from the application: it was resolved into the closure, so it
// is on the classpath.
func BuildDependencyGraph(root ComponentKey, keys []ComponentKey, direct []string, edges map[ComponentKey][]ComponentKey, present map[ComponentKey]Fragment) (DependencyGraph, map[ComponentKey]bool) {
	full := make(map[ComponentKey][]ComponentKey, len(keys)+1)
	versionOf := make(map[string]string, len(keys))
	for _, k := range keys {
		versionOf[k.Purl] = k.Version
	}
	for _, purl := range direct {
		full[root] = append(full[root], ComponentKey{Purl: purl, Version: versionOf[purl]})
	}
	for parent, children := range edges {
		full[parent] = append(full[parent], children...)
	}
	reach := func(skipMissing bool) map[ComponentKey]bool {
		seen := map[ComponentKey]bool{root: true}
		stack := []ComponentKey{root}
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			for _, c := range full[n] {
				if seen[c] {
					continue
				}
				seen[c] = true
				if _, ok := present[c]; ok || !skipMissing {
					stack = append(stack, c)
				}
			}
		}
		return seen
	}
	connected := reach(false)
	for _, k := range keys {
		if !connected[k] {
			full[root] = append(full[root], k)
		}
	}
	withMissing, withoutMissing := reach(false), reach(true)
	viaMissingOnly := make(map[ComponentKey]bool)
	for _, k := range keys {
		if _, ok := present[k]; ok && withMissing[k] && !withoutMissing[k] {
			viaMissingOnly[k] = true
		}
	}

	// Splice: the present children of a node, looking through missing ones.
	var kids func(n ComponentKey, seen map[ComponentKey]bool) []ComponentKey
	kids = func(n ComponentKey, seen map[ComponentKey]bool) []ComponentKey {
		var out []ComponentKey
		for _, c := range full[n] {
			if seen[c] {
				continue
			}
			seen[c] = true
			if _, ok := present[c]; ok {
				out = append(out, c)
			} else {
				out = append(out, kids(c, seen)...)
			}
		}
		return out
	}
	deps := make(DependencyGraph, len(present)+1)
	deps[root] = kids(root, map[ComponentKey]bool{root: true})
	for k := range present {
		deps[k] = kids(k, map[ComponentKey]bool{k: true})
	}
	return deps, viaMissingOnly
}

// ApplicationFragment is the root fragment the stitch walks from: the
// application's call-site functions and their calls into dependencies,
// nothing else. Internal edges, the application's own annotations and entry
// kinds are dropped, so every call-site function is a root and a verdict
// never depends on what else the caller sent. Which functions are call-site
// functions is the caller's decision: it leaves out the ones its own entry
// points do not reach.
func ApplicationFragment(root ComponentKey, doc *gf.GraphFragmentExport) Fragment {
	frag := doc.ToFragment(root)
	callers := make(map[string]bool, len(frag.ExternalCalls))
	for _, c := range frag.ExternalCalls {
		callers[c.Caller] = true
	}
	fns := frag.Functions[:0]
	for _, f := range frag.Functions {
		if callers[f.Signature] {
			fns = append(fns, f)
		}
	}
	frag.Functions, frag.InternalEdges = fns, nil
	frag.CryptoOperations, frag.SupportingCalls, frag.CryptoEntryPoints = nil, nil, nil
	frag.EntryKinds = nil
	return frag
}

// FindingVerdicts reads the stitched finding graphs as served verdicts. The
// stitched export reads every finding without a route as unknown as soon as
// the stitch suppressed any call anywhere in the closure, which on a real
// closure is every finding. Per finding, unknown is a route that needs a call
// the stitch could not resolve (the export names it in unresolved_reason) or a
// search that hit a cap; any other finding without a route is unreachable.
// A finding with no finding graph has no route either.
func FindingVerdicts(graphs []ExportFindingGraph) map[string]Verdict {
	out := make(map[string]Verdict, len(graphs))
	for i := range graphs {
		g := &graphs[i]
		v := Verdict{Reachability: VerdictUnreachable}
		switch {
		case g.Reachability == VerdictReachable && !hasRoute(g):
			v = Verdict{Reachability: VerdictUnknown, Reason: ReasonDependencyEntryPointOnly}
		case g.Reachability == VerdictReachable:
			v.Reachability = VerdictReachable
		case g.Reachability == VerdictUnknown && g.UnresolvedReason != "":
			v = Verdict{Reachability: VerdictUnknown, Reason: g.UnresolvedReason}
		case g.Reachability == VerdictUnknown && g.Analysis != nil && g.Analysis.CallChains == gf.AnalysisPartial:
			v = Verdict{Reachability: VerdictUnknown, Reason: ReasonSearchCapped}
		case g.Reachability == gf.ReachabilityNotApplicable:
			v = Verdict{Reachability: VerdictUnknown, Reason: ReasonNoContainingFunction}
		}
		out[g.FindingID] = v
	}
	return out
}

// hasRoute reports whether a finding graph holds a route of at least one call
// (two frames), interned or not.
func hasRoute(g *ExportFindingGraph) bool {
	for _, c := range g.CallChains {
		if len(c) >= 2 {
			return true
		}
	}
	for _, c := range g.CallChainIndexes {
		if len(c) >= 2 {
			return true
		}
	}
	return false
}

// KeepServedChains trims each finding graph to the first limit chains whose
// frames all have identity. The stitch keeps up to 128 chains per operation
// and a caller usually serves one; a renderer would marshal, parse and check
// every chain only to drop the rest. A graph with a nameless frame and no
// indexes is left whole, for the renderer to refuse.
func KeepServedChains(graphs []ExportFindingGraph, limit int) {
	for i := range graphs {
		g := &graphs[i]
		withIndexes := len(g.CallChainIndexes) > 0
		if !withIndexes && slices.ContainsFunc(g.CallChains, chainMissingIdentity) {
			continue
		}
		kept := 0
		for j := range g.CallChains {
			if kept == limit {
				break
			}
			if chainMissingIdentity(g.CallChains[j]) {
				continue
			}
			g.CallChains[kept] = g.CallChains[j]
			if withIndexes {
				g.CallChainIndexes[kept] = g.CallChainIndexes[j]
			}
			kept++
		}
		g.CallChains = g.CallChains[:kept]
		if withIndexes {
			g.CallChainIndexes = g.CallChainIndexes[:kept]
		}
	}
}

// chainMissingIdentity reports a chain with a frame that has neither
// function_name nor canonical_signature.
func chainMissingIdentity(chain []ExportChainNode) bool {
	for i := range chain {
		if chain[i].FunctionName == "" && chain[i].CanonicalSignature == "" {
			return true
		}
	}
	return false
}
