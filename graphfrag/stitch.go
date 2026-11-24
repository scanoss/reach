// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/scanoss/reach/graphwalk"
)

// StitchOptions tunes which root-fragment functions a stitch traces from. The
// zero value reproduces the historical Stitch behavior (trace from every
// root-fragment function), so adding fields here never changes existing callers.
type StitchOptions struct {
	// EntryRootedOnly, when true, traces only from root-fragment functions that
	// have NO incoming edge in the dependency-closure adjacency (in-degree 0) —
	// the graph's entry points. Tracing from every one of an 18k-function
	// library's functions is intractable and, for serving, redundant: a finding
	// reachable from a non-entry function is still reachable from the entry that
	// calls it, so the set of reachable terminal findings is preserved while the
	// number of traced roots collapses to the true entry points.
	EntryRootedOnly bool

	// ForwardClosure, when true, additionally computes a per-finding-anchor
	// forward reachability graph (see forwardClosure) and carries it on
	// Result.forwardClosures for ToCallgraphExport to project as the
	// `forward_calls` block. Zero value (false) is OFF: no forward traversal
	// runs, no allocation happens, and served output is byte-identical to the
	// pre-forward-closure shape (modulo the reviewed schema_version bump).
	ForwardClosure bool

	// MaxForwardDepth caps the forward BFS depth (hops from the anchor). Zero
	// resolves to defaultMaxForwardDepth.
	MaxForwardDepth int
	// MaxForwardNodesPerAnchor caps the number of distinct forward-reachable
	// nodes retained per anchor. Zero resolves to defaultMaxForwardNodesPerAnchor.
	MaxForwardNodesPerAnchor int
	// MaxForwardEdgesPerAnchor caps the number of forward edges retained per
	// anchor. Zero resolves to defaultMaxForwardEdgesPerAnchor.
	MaxForwardEdgesPerAnchor int

	// ChainEntrySignatures restricts CALL-CHAIN enumeration to routes that
	// terminate at one of the named functions, matched on
	// Function.CanonicalSignature or ErasedSignature — the spellings
	// crypto_entry_points publishes, so a consumer can feed any published entry
	// point straight back in, root or not. It carries the served request's
	// `entry_point_signatures`.
	//
	// It does NOT touch the entry-point index, which stays complete. The two
	// answer different questions: the index says which functions reach the
	// crypto, this says which routes are worth spending the chain budget on.
	// Restricting the index instead would reintroduce the bug #249 fixed.
	//
	// Why it is needed: chains are capped at DefaultMaxChainsPerOp per operation
	// and the enumeration spends that budget in traversal order — several routes
	// from one entry before any route from another. On a dense library the
	// emitted chains therefore start at a small fraction of the published
	// entries, and the entry a caller asked about is usually not among them.
	// Naming it here spends the whole budget on routes that reach it.
	//
	// Zero value (nil) enumerates from every entry, so the default serving path
	// is unchanged. A signature naming no function contributes nothing rather
	// than becoming a synthetic entry, and a function carrying neither signature
	// cannot be named.
	ChainEntrySignatures []string

	// AmbiguousDispatchAsTyped traverses an interface call site with several
	// implementations in the closure to every one of them, as the live tracer
	// does (reach-engine-v2: a client's call sites stitched over mined graphs
	// must give the verdicts a local scan gives). Zero value keeps the
	// fail-closed default: such a call site is suppressed.
	AmbiguousDispatchAsTyped bool

	// ClasspathTargets resolves a component's external calls against its whole
	// transitive dependency closure, not only its direct dependencies: a Java
	// component compiles and runs against its resolved classpath, so an
	// application may call a library it only gets transitively. Zero value:
	// direct dependencies only.
	ClasspathTargets bool
	// ClosureTargets resolves the external calls a component's dependency
	// closure leaves without a target against every other component of the
	// stitched closure, as a Java runtime classpath holds all of them: a
	// resolved Maven tree omits an edge whose artifact appears elsewhere
	// (bcpkix -> bcprov when the project declares bcprov itself). The declared
	// dependencies are tried first, so a call they resolve keeps its target;
	// a name-only call never widens. The edges are the stitch's own, under its
	// dispatch policy. Zero value: the declared dependencies only (and, with
	// ClasspathTargets, the selector value walk alone widens).
	ClosureTargets bool
	// EnvironmentTargets names the ecosystems ("python") whose components
	// resolve, as ClosureTargets does, the external calls their declared
	// dependencies leave without a target against every other component of
	// the stitched closure: a Python module imports whatever the environment
	// holds, declared or not (an optional import, a dependency an extra or a
	// lock without edges leaves unattributed). Declared dependencies first; a
	// name_only call never widens. A component's ecosystem is its graph
	// algorithm id's (GraphAlgoVersionFor), else its purl's. Components of
	// other ecosystems keep the rest of the options' targets.
	EnvironmentTargets []string

	// HierarchyFromSupertypes joins calls and dispatch through the fragments'
	// supertypes: a call on a type that only inherits the method resolves to
	// the nearest supertype declaring it, and a method of a subtype implements
	// the same method of its supertypes. For components mined alone, whose
	// hierarchy crosses component boundaries. Zero value: unchanged.
	HierarchyFromSupertypes bool
	// SupertypeDispatch additionally reads every method of a subtype as an
	// implementation of the same method of its supertypes (dispatch surfaces
	// the producer could not prove). Needs HierarchyFromSupertypes.
	SupertypeDispatch bool
	// ServiceProviderDispatch reads each class a closure fragment registers
	// for java.util.ServiceLoader (Fragment.ServiceProviders) as an
	// implementation of its service type's methods, so a call on the service
	// type dispatches to the registered implementations the closure declares
	// (stitch_service_providers.go). Needs HierarchyFromSupertypes.
	ServiceProviderDispatch bool

	// AmbiguousDispatchUnknown serves a finding the root reaches only through an
	// interface call site with several implementations as unknown
	// (unresolved_reason ambiguous_dispatch), never reachable: the receiver type
	// is known, the implementation is not. Ignored with AmbiguousDispatchAsTyped.
	AmbiguousDispatchUnknown bool

	// SelectorCalls are calls whose unresolved arguments the stitch traces
	// through the closure's callers; Result.SelectorValues answers them, in
	// order (stitch_selector_values.go). Nil traces nothing.
	SelectorCalls []SelectorCall

	// SuppressedSummaryOnly leaves Result.Suppressed empty: the stitch still
	// records that it refused an edge, which is all the callgraph export's
	// verdicts read, but not each edge. On a large closure the records are a
	// million edges, each with its caller frame and candidates, and the
	// largest part of the stitch's memory. Ignored with ForwardClosure, whose
	// ambiguities are read from the records.
	SuppressedSummaryOnly bool

	// MaxChains is the per-operation emit budget for condensed call_chains.
	// Zero uses DefaultMaxChainsPerOp (128). Local CLI defaults to 8 and may
	// explicitly request 128. Depth remains stitchMaxDepth (32).
	MaxChains int
}

// Defaults applied by forwardCapsFrom when the corresponding StitchOptions
// field is left at its zero value.
const (
	defaultMaxForwardDepth          = 4
	defaultMaxForwardNodesPerAnchor = 256
	defaultMaxForwardEdgesPerAnchor = 512
)

// forwardCaps is the resolved (zero-values-defaulted) cap set for one
// buildForwardClosures run.
type forwardCaps struct {
	maxDepth int
	maxNodes int
	maxEdges int
}

// forwardCapsFrom resolves opts' forward-closure caps, defaulting any
// zero-value field.
func forwardCapsFrom(opts StitchOptions) forwardCaps {
	caps := forwardCaps{
		maxDepth: opts.MaxForwardDepth,
		maxNodes: opts.MaxForwardNodesPerAnchor,
		maxEdges: opts.MaxForwardEdgesPerAnchor,
	}
	if caps.maxDepth == 0 {
		caps.maxDepth = defaultMaxForwardDepth
	}
	if caps.maxNodes == 0 {
		caps.maxNodes = defaultMaxForwardNodesPerAnchor
	}
	if caps.maxEdges == 0 {
		caps.maxEdges = defaultMaxForwardEdgesPerAnchor
	}
	return caps
}

// forwardClosure is the rooted forward call graph from ONE finding anchor
// node, computed once per distinct anchor (memoized in
// Result.forwardClosures). Pre-projection model — ToCallgraphExport projects
// it into the exported forward_calls shape.
type forwardClosure struct {
	anchor    CallFrame     // resolved anchor identity (depth 0); reuses buildFrame output
	nodes     []forwardNode // forward-reachable nodes, depth >= 1, deduped by graphNode
	edges     []forwardEdge // directed traversed edges (endpoints always in {anchor} ∪ nodes)
	ambiguous []SuppressedEdge
	maxDepth  int  // the depth CAP applied (== resolved MaxForwardDepth)
	truncated bool // any cap hit (depth/node/edge) -> true; never silent
}

// forwardNode is one forward-reachable node (depth >= 1) in a forwardClosure.
type forwardNode struct {
	node               graphNode // internal identity (Component+Function)
	frame              CallFrame // resolved via buildFrame (Function identity + Module)
	depth              int       // shortest-path hops from anchor (BFS layer)
	cryptoRelevant     bool      // node ∈ opsByNode OR has non-empty supporting Category
	supportingCategory string    // first non-empty supportingByNode[node].Category
}

// forwardEdge is one directed traversed edge (from -> to) in a forwardClosure.
type forwardEdge struct {
	from      graphNode
	to        graphNode
	entryCall *CallSite // the (from->to) call site: line + resolved-value Parameters
}

// Stitch composes reusable component graph fragments into root-to-crypto
// reachability chains for root.
//
// This is the pure graph algorithm. It deliberately does not know about
// storage, compression, or HTTP response DTOs. It traces from every
// root-fragment function; for entry-point-only rooting use StitchWithOptions.
func Stitch(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment) (*Result, error) {
	return StitchWithOptions(root, deps, fragments, StitchOptions{})
}

// StitchWithOptions is Stitch with an explicit rooting policy. See StitchOptions.
func StitchWithOptions(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment, opts StitchOptions) (*Result, error) {
	closure := dependencyClosure(root, deps)
	missing := missingFragments(closure, fragments)
	if len(missing) > 0 {
		return nil, &ErrMissingFragment{Components: missing}
	}

	var hierarchy *typeHierarchy
	if opts.HierarchyFromSupertypes {
		h := indexTypeHierarchy(closure, fragments)
		hierarchy = &h
		copied := make(map[ComponentKey]Fragment, len(fragments))
		for k, v := range fragments {
			copied[k] = v
		}
		if opts.SupertypeDispatch {
			addSupertypeCompatibility(closure, copied, h, nil)
		} else {
			// A Rust supertype is an `impl Trait for Type` the crate writes,
			// so the methods of the block implement the trait's: dispatch
			// through it is proven, not guessed.
			addSupertypeCompatibility(closure, copied, h, isRustFragment)
		}
		if opts.ServiceProviderDispatch {
			addServiceProviderCompatibility(closure, copied, h)
		}
		fragments = copied
	}
	functionsBySignature, functionsByCanonicalSignature, dispatchSurfaces, aliasByKey := indexFunctions(closure, fragments)
	functionsByNode := indexFunctionsByNode(closure, fragments)
	var classpath *classpathEdges
	if len(opts.SelectorCalls) > 0 && opts.ClasspathTargets && !opts.ClosureTargets {
		classpath = newClasspathEdges(closure)
	}
	suppressed := &suppressionLog{detail: !opts.SuppressedSummaryOnly || opts.ForwardClosure}
	closureTargets := func(key ComponentKey) bool {
		return opts.ClosureTargets || slices.Contains(opts.EnvironmentTargets, fragmentEcosystem(fragments[key]))
	}
	adjacency, ambiguousCandidates, nameOnly := buildAdjacency(closure, deps, fragments, functionsBySignature, functionsByCanonicalSignature, functionsByNode, dispatchSurfaces, aliasByKey, hierarchy, opts.ClasspathTargets, closureTargets, classpath, suppressed)
	if slices.Contains(opts.EnvironmentTargets, "python") {
		// The environment makes every installed method of a name a
		// candidate; only those of classes the root can hold stay.
		nameOnly = narrowPythonNameOnly(root, fragments[root], fragments, indexPythonInstantiation(closure, fragments), adjacency, ambiguousCandidates, nameOnly)
	}
	// A function of a module nothing loads is no candidate of a Node
	// name_only call.
	nameOnly = narrowNodeNameOnly(root, fragments[root], indexNodeModules(closure, fragments), adjacency, ambiguousCandidates, nameOnly)
	var ambiguousOnly map[graphNode]bool
	if opts.AmbiguousDispatchAsTyped {
		for caller, edges := range ambiguousCandidates {
			adjacency[caller] = append(adjacency[caller], edges...)
		}
	} else if opts.AmbiguousDispatchUnknown {
		ambiguousOnly = ambiguousDispatchOnlyNodes(root, fragments[root], adjacency, ambiguousCandidates)
	}
	opsByNode := indexCryptoOperations(closure, fragments)
	supportingByNode := indexSupportingCalls(closure, fragments)

	rootFragment := fragments[root]
	roots := rootNodes(root, rootFragment, adjacency, opts.EntryRootedOnly)

	out := Result{
		dependencyRoutes:     dependencyRoutes(root, deps, fragments),
		dependencyModules:    componentModules(closure, fragments),
		Suppressed:           suppressed.edges,
		suppressedAny:        suppressed.any,
		operationEntryPoints: indexOperationEntryPoints(closure, fragments),
		erasedByFunctionKey:  indexErasedSignatures(closure, fragments),
		unresolvedDispatchOps: unresolvedDispatchOps(root, rootFragment, opsByNode,
			adjacency, ambiguousCandidates, nameOnly),
		ambiguousOnlyNodes: ambiguousOnly,
	}
	if len(opts.SelectorCalls) > 0 {
		dispatch := ambiguousCandidates
		if opts.AmbiguousDispatchAsTyped {
			dispatch = nil // already in the adjacency
		}
		reach := selectorReach(root, fragments[root], adjacency, dispatch)
		walk, walkDispatch := []map[graphNode][]adjacencyEdge{adjacency}, []map[graphNode][]adjacencyEdge{dispatch}
		if classpath != nil {
			walk, walkDispatch = append(walk, classpath.adjacency), append(walkDispatch, classpath.ambiguous)
			if opts.AmbiguousDispatchAsTyped {
				walk = append(walk, classpath.ambiguous)
				walkDispatch = walkDispatch[:1]
			}
		}
		out.selectorValues = traceSelectorValues(opts.SelectorCalls, walk, walkDispatch, reach)
	}
	if opts.EntryRootedOnly {
		// Serving path. Mirror live `--export-callgraph` (TraceBackLimited): a
		// backward BFS from each crypto op with a per-op graph-global frontier set.
		// This is O(V+E) per op (no per-path visited clone) and collapses
		// re-convergent (diamond) branches to a single representative, so the served
		// callgraph matches live byte-for-byte (the parity contract) and stays
		// bounded on high-fan-in libraries (BouncyCastle, 18k functions) where the
		// old all-simple-paths forward DFS hangs.
		// Composition runs before the enumeration so a restricted request can tell
		// a signature naming nothing from one naming a composed entry point: the
		// latter proves reachability through a dependency's mine-time index, which
		// records a depth and no route, so no enumeration can confirm it.
		out.rootKinds = classifyRootKinds(&rootFragment, roots)
		callers := callerLists(adjacency)
		composeDependencyEntryPoints(root, closure, fragments, adjacency, callers, ambiguousCandidates, &out)
		composedRoutes := make(map[string][]graphNode)
		chainEntries := chainEntryNodes(functionsByNode, opts.ChainEntrySignatures)
		traceBackward(adjacency, callers, opsByNode, supportingByNode, fragments, functionsByNode, roots,
			chainEntries,
			composedChainEntryFindings(root, &out, functionsByNode, opts.ChainEntrySignatures, composedRoutes),
			composedRoutes, ambiguousCandidates, ResolveMaxChains(opts.MaxChains), &out)
		attachAnnotationSupportingCalls(closure, fragments, &out)
		if opts.ForwardClosure {
			out.forwardClosures = buildForwardClosures(adjacency, suppressed.edges, opsByNode, supportingByNode, fragments, functionsByNode, forwardCapsFrom(opts))
		}
		return &out, nil
	}

	// Historical full-rooting path (Stitch / EntryRootedOnly=false): trace forward
	// from every root-fragment function, emitting a chain rooted at each ancestor of
	// each op. This is the documented zero-value behavior pinned by the resolution
	// fail-closed and parallel-edge tests; it is NOT under the live parity contract
	// (that contract is the serving path above) and keeps its exact prior output.
	// The chains below keep their exact historical shape; the entry-point index,
	// however, is a question about the graph and is answered the same way on both
	// stitch paths (issue #249).
	historicalEntries := make(map[graphNode]bool, len(roots))
	for _, r := range roots {
		historicalEntries[r] = true
	}
	recordAllReachEntries(
		callersWithoutCallSites(reverseAdjacency(adjacency)),
		opsByNode, historicalEntries, fragments, functionsByNode, &out)

	for _, start := range roots {
		trace(start, adjacency, opsByNode, supportingByNode, fragments, functionsByNode, inbound{}, nil, map[graphNode]bool{}, &out)
	}
	attachAnnotationSupportingCalls(closure, fragments, &out)
	if opts.ForwardClosure {
		out.forwardClosures = buildForwardClosures(adjacency, suppressed.edges, opsByNode, supportingByNode, fragments, functionsByNode, forwardCapsFrom(opts))
	}
	return &out, nil
}

// attachAnnotationSupportingCalls resolves each surviving finding's
// supporting_call_ids (the per-finding FK the fragment's crypto annotation
// declares) against the closure's supporting-call pool, adding any the chain
// traversal did not already emit.
//
// flushSupportingCalls only emits supporting calls for nodes that appear on a
// backward chain to a crypto op. Contract/lifecycle supporting calls — e.g.
// Password4J's Password.hash / addRandomSalt / Hash.getResult, attached to a
// synthesized terminal by deriveContractSupportingCalls at export time — are
// upstream public-API callers that are NOT on any backward chain from the
// terminal (the terminal has in-degree 0), so traversal alone silently drops
// them and their supporting_call_ids dangle against an empty pool. Honoring the
// fragment's pre-computed FK here is what makes the served callgraph match a
// live --export-callgraph (which carries them in supporting_calls).
func attachAnnotationSupportingCalls(closure []ComponentKey, fragments map[ComponentKey]Fragment, out *Result) {
	byID := indexAnnotationSupportingCalls(closure, fragments)
	if len(byID) == 0 {
		return
	}
	seen := indexResultSupportingCalls(out)
	attachMissingAnnotationSupportingCalls(byID, seen, out)
}

func indexAnnotationSupportingCalls(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[string]SupportingCall {
	byID := make(map[string]SupportingCall)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.SupportingCalls {
			sc := fragment.SupportingCalls[i]
			if sc.SupportingID == "" {
				continue
			}
			if _, ok := byID[sc.SupportingID]; !ok {
				byID[sc.SupportingID] = sc
			}
		}
	}
	return byID
}

func indexResultSupportingCalls(out *Result) map[string]bool {
	seen := make(map[string]bool, len(out.SupportingCalls))
	for i := range out.SupportingCalls {
		if id := out.SupportingCalls[i].SupportingID; id != "" {
			seen[id] = true
		}
	}
	return seen
}

func attachMissingAnnotationSupportingCalls(
	byID map[string]SupportingCall,
	seen map[string]bool,
	out *Result,
) {
	for i := range out.Chains {
		op := out.Chains[i].CryptoOp
		if op == nil || out.Chains[i].IndexOnly {
			continue
		}
		appendMissingSupportingCalls(op.SupportingCallIDs, byID, seen, out)
	}
}

func appendMissingSupportingCalls(
	ids []string,
	byID map[string]SupportingCall,
	seen map[string]bool,
	out *Result,
) {
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		sc, ok := byID[id]
		if !ok {
			continue
		}
		seen[id] = true
		out.SupportingCalls = append(out.SupportingCalls, sc)
	}
}

// rootNodes selects the set of root-fragment functions to start traces from.
// With entryRootedOnly false this is every root-fragment function (historical
// behavior). With it true, only root-fragment functions with no incoming edge
// in the closure adjacency (in-degree 0) are kept.
func rootNodes(root ComponentKey, rootFragment Fragment, adjacency map[graphNode][]adjacencyEdge, entryRootedOnly bool) []graphNode {
	roots := make([]graphNode, 0, len(rootFragment.Functions))
	if !entryRootedOnly {
		for i := range rootFragment.Functions {
			roots = append(roots, graphNode{Component: root, Function: rootFragment.Functions[i].Signature})
		}
		return roots
	}

	hasIncoming := incomingNodes(adjacency)
	for i := range rootFragment.Functions {
		node := graphNode{Component: root, Function: rootFragment.Functions[i].Signature}
		if hasIncoming[node] {
			continue
		}
		roots = append(roots, node)
	}
	return roots
}

// incomingNodes returns the set of nodes that are the target of at least one
// traversable edge in the adjacency — i.e. every node with in-degree >= 1.
func incomingNodes(adjacency map[graphNode][]adjacencyEdge) map[graphNode]bool {
	incoming := make(map[graphNode]bool)
	for _, edges := range adjacency {
		for _, edge := range edges {
			incoming[edge.target] = true
		}
	}
	return incoming
}

type graphNode struct {
	Component ComponentKey
	Function  string
}

type adjacencyEdge struct {
	target    graphNode
	entryCall *CallSite
	// resolution and declaredType describe how this edge was established. They
	// travel to the served frame because a route is only evidence if a reader
	// can tell a certain hop from an inferred one: a dispatch edge expands to
	// every compatible implementation, and a shortest route prefers whichever
	// of them is the shortcut.
	resolution   ResolutionKind
	declaredType string
}

// DependencyClosure returns root and every component deps reaches from it,
// in breadth-first order (root first, each component once).
func DependencyClosure(root ComponentKey, deps DependencyGraph) []ComponentKey {
	return dependencyClosure(root, deps)
}

func dependencyClosure(root ComponentKey, deps DependencyGraph) []ComponentKey {
	seen := map[ComponentKey]bool{root: true}
	queue := []ComponentKey{root}
	out := []ComponentKey{root}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		for _, dep := range deps[current] {
			if seen[dep] {
				continue
			}
			seen[dep] = true
			queue = append(queue, dep)
			out = append(out, dep)
		}
	}
	return out
}

// dependencyRoutes is a breadth-first walk of the dependency graph from root:
// each component's shortest route, root excluded and the component included.
// Children are visited in module order, the order the live export's resolved
// dependency graph walk uses, so both name the same route.
func dependencyRoutes(root ComponentKey, deps DependencyGraph, fragments map[ComponentKey]Fragment) map[ComponentKey][]ComponentKey {
	routes := make(map[ComponentKey][]ComponentKey)
	queue := []ComponentKey{root}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		children := append([]ComponentKey(nil), deps[current]...)
		sort.Slice(children, func(i, j int) bool {
			left, right := componentSortKey(children[i], fragments), componentSortKey(children[j], fragments)
			if left != right {
				return left < right
			}
			return children[i].String() < children[j].String()
		})
		for _, child := range children {
			if _, seen := routes[child]; seen || child == root {
				continue
			}
			route := make([]ComponentKey, 0, len(routes[current])+1)
			route = append(route, routes[current]...)
			routes[child] = append(route, child)
			queue = append(queue, child)
		}
	}
	return routes
}

func componentSortKey(key ComponentKey, fragments map[ComponentKey]Fragment) string {
	if module := fragments[key].Module; module != "" {
		return module
	}
	return key.String()
}

func componentModules(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[ComponentKey]string {
	modules := make(map[ComponentKey]string, len(closure))
	for _, key := range closure {
		modules[key] = fragments[key].Module
	}
	return modules
}

func missingFragments(closure []ComponentKey, fragments map[ComponentKey]Fragment) []ComponentKey {
	var missing []ComponentKey
	for _, key := range closure {
		if _, ok := fragments[key]; !ok {
			missing = append(missing, key)
		}
	}
	return missing
}

func indexFunctions(closure []ComponentKey, fragments map[ComponentKey]Fragment) (map[string][]graphNode, map[string][]graphNode, map[graphNode][]graphNode, map[string][]graphNode) {
	byKey := make(map[string][]graphNode)
	byCanonicalSignature := make(map[string][]graphNode)
	byOwnCanonical := make(map[string][]graphNode)
	implsByCompatible := make(map[string][]graphNode)
	// aliasByKey maps an overload-suffixed function key ("(C).<init>#3$Map,...")
	// to its nodes under the unsuffixed spelling ("(C).<init>#3") a call site
	// emits when the producer could not disambiguate the overload. Alias joins
	// are served through the dispatch policy, never as silent exact edges.
	aliasByKey := make(map[string][]graphNode)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.Functions {
			node := graphNode{Component: key, Function: fragment.Functions[i].Signature}
			fn := fragment.Functions[i]
			byKey[fn.Signature] = append(byKey[fn.Signature], node)
			if dollar := strings.Index(fn.Signature, "$"); dollar > 0 {
				aliasByKey[fn.Signature[:dollar]] = append(aliasByKey[fn.Signature[:dollar]], node)
			}
			if fn.CanonicalSignature != "" {
				byCanonicalSignature[fn.CanonicalSignature] = append(byCanonicalSignature[fn.CanonicalSignature], node)
				byOwnCanonical[fn.CanonicalSignature] = append(byOwnCanonical[fn.CanonicalSignature], node)
			}
			for _, compatible := range fn.CompatibleCanonicalSignatures {
				if compatible != "" {
					byCanonicalSignature[compatible] = append(byCanonicalSignature[compatible], node)
					implsByCompatible[compatible] = append(implsByCompatible[compatible], node)
				}
			}
		}
	}

	return byKey, byCanonicalSignature, buildDispatchSurfaces(implsByCompatible, byOwnCanonical), aliasByKey
}

// buildDispatchSurfaces maps each dispatch surface — a function other
// functions declare as their hierarchy parent via
// CompatibleCanonicalSignatures (an interface method or an overridden base
// method) — to its implementations. An exact edge landing on a surface is a
// call the producer could only anchor to the declared type; the
// implementations are the traversable continuations (expanded under the
// standard dispatch policy in applyImmediateEdgePolicy).
func buildDispatchSurfaces(implsByCompatible, byOwnCanonical map[string][]graphNode) map[graphNode][]graphNode {
	surfaces := make(map[graphNode][]graphNode)
	for compatible, impls := range implsByCompatible {
		for _, parent := range byOwnCanonical[compatible] {
			seen := make(map[graphNode]bool, len(impls))
			for _, impl := range impls {
				if impl != parent && !seen[impl] {
					seen[impl] = true
					surfaces[parent] = append(surfaces[parent], impl)
				}
			}
		}
	}
	return surfaces
}

func indexFunctionsByNode(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[graphNode]*Function {
	out := make(map[graphNode]*Function, closureFunctionCount(closure, fragments))
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.Functions {
			fn := &fragment.Functions[i]
			out[graphNode{Component: key, Function: fn.Signature}] = fn
		}
	}
	return out
}

// closureFunctionCount sizes the per-node indexes up front.
func closureFunctionCount(closure []ComponentKey, fragments map[ComponentKey]Fragment) int {
	n := 0
	for _, key := range closure {
		n += len(fragments[key].Functions)
	}
	return n
}

// dispatchGroupKey identifies one interface call site so that the sibling
// candidate edges the producer emitted for it can be grouped and judged
// together: a single source call expression that the producer expanded into N
// concrete implementations.
type dispatchGroupKey struct {
	Component  ComponentKey
	Caller     string
	CallSite   int
	StartCol   int
	EndCol     int
	MethodName string
	Arity      int
}

// callEdge is the scope-agnostic view of one resolved call edge. Internal and
// external edges are normalised into this shape so the resolution policy — and
// crucially the per-call-site ambiguity check — can span both: an interface
// call site whose implementations straddle the component boundary must be judged
// as one group, not two.
type callEdge struct {
	caller                   string
	target                   string
	targetCanonicalSignature string
	resolution               ResolutionKind
	method                   string
	arity                    int
	callSite                 int
	startCol                 int
	endCol                   int
	internal                 bool
	entryCall                *CallSite
	resolvedReceiverType     string
	// receiverVar and chainID are the external call's receiver local and
	// fluent chain (Python name_only candidates, stitch_python_untyped.go).
	receiverVar string
	chainID     string
	// declaredType is the static type the call was written against. On a
	// dispatch edge it names what the walk could not narrow, which is the whole
	// reason a consumer would want to see it.
	declaredType string
	// receiverProducer is the external call's ReceiverProducer. When it
	// constructs one class, typeConstructedReceivers sets resolvedReceiverType
	// to that class's simple name, receiverPackage to its package and
	// receiverConstructed.
	receiverProducer    string
	receiverPackage     string
	receiverConstructed bool
}

// buildAdjacency composes the traversable call graph from the fragment closure
// while applying the edge-resolution policy. It returns the adjacency map plus
// the list of edges/call sites it refused to traverse (fail-closed audit trail).
//
// Policy (tiered, fail-closed by default):
//   - exact              -> always traversed.
//   - interface_dispatch -> traversed only if exactly one concrete impl is
//     present in the current component's direct dependencies for that call
//     site; >1 is ambiguous and fails closed (recorded). 0 is simply
//     unreachable.
//   - name_only          -> never traversed (recorded, and returned apart so
//     the export can tell a finding reached only through one).
//   - unknown (zero)     -> never traversed (recorded); usually a producer bug.
func buildAdjacency(
	closure []ComponentKey,
	deps DependencyGraph,
	fragments map[ComponentKey]Fragment,
	functionsBySignature map[string][]graphNode,
	functionsByCanonicalSignature map[string][]graphNode,
	functionsByNode map[graphNode]*Function,
	dispatchSurfaces map[graphNode][]graphNode,
	aliasByKey map[string][]graphNode,
	hierarchy *typeHierarchy,
	classpath bool,
	closureTargets func(ComponentKey) bool,
	fallback *classpathEdges,
	suppressed *suppressionLog,
) (adjacency, ambiguous, nameOnly map[graphNode][]adjacencyEdge) {
	adjacency = make(map[graphNode][]adjacencyEdge)
	ambiguous = make(map[graphNode][]adjacencyEdge)
	nameOnly = make(map[graphNode][]adjacencyEdge)
	ownerTypes := indexOwnerTypes(closure, fragments)
	byMethodArity := indexFunctionsByMethodArity(functionsByNode)
	public := indexPythonPublicNames(closure, fragments)
	modules := indexPythonModules(closure, fragments)
	nodePkgs := indexNodePackages(closure, fragments)
	var nodeLinks *nodeNameOnlyLinks

	for _, key := range closure {
		fragment := fragments[key]
		componentSigs := indexComponentSignatures(key, fragment, adjacency)
		edges := collectCallEdges(fragment)
		targetSet := componentSet(deps[key])
		if classpath {
			targetSet = componentSet(dependencyClosure(key, deps))
			delete(targetSet, key)
		}
		resolve := callEdgeResolver(key, componentSigs, targetSet, functionsBySignature, functionsByCanonicalSignature, aliasByKey, byMethodArity, public, hierarchy)
		if closureTargets(key) {
			others := componentSet(closure)
			delete(others, key)
			resolve = preferDeclared(resolve, callEdgeResolver(key, componentSigs, others, functionsBySignature, functionsByCanonicalSignature, aliasByKey, byMethodArity, public, hierarchy))
		}
		typeConstructedReceivers(edges, resolve, functionsByNode)
		if fragmentEcosystem(fragment) == "python" {
			scope := targetSet
			if closureTargets(key) {
				scope = componentSet(closure)
				delete(scope, key)
			}
			resolve = pythonNameOnlyCandidates(pythonUnresolvedAsNameOnly(resolve, key, modules, byMethodArity), key, fragment, modules, byMethodArity, scope)
		}
		switch fragmentEcosystem(fragment) {
		case "go":
			resolve = goInterfaceCandidates(resolve, byMethodArity, targetSet)
		case "rust":
			resolve = rustUntypedCandidates(resolve, key, fragment, byMethodArity, targetSet)
		}
		if fragmentEcosystem(fragment) == "node" {
			scope := targetSet
			if closureTargets(key) {
				if nodeLinks == nil {
					nodeLinks = newNodeNameOnlyLinks(closure, deps)
				}
				scope = nodeLinks.scope(key)
			}
			resolve = nodeNameOnlyCandidates(nodeUnresolvedAsNameOnly(resolve, key, nodePkgs, byMethodArity, scope), key, byMethodArity, scope)
		}

		immediate, unresolved := fallback.tracking(resolve)
		dispatchGroups := applyImmediateEdgePolicy(key, edges, immediate, adjacency, suppressed, dispatchSurfaces, ownerTypes, fragments, functionsByNode, ambiguous, nameOnly)
		applyDispatchGroups(key, dispatchGroups, resolve, ownerTypes, fragments, functionsByNode, adjacency, suppressed, ambiguous)
		if fallback != nil && len(*unresolved) > 0 {
			full := callEdgeResolver(key, componentSigs, fallback.others(key), functionsBySignature, functionsByCanonicalSignature, aliasByKey, byMethodArity, public, hierarchy)
			// The fallback's refusals are not the stitch's: nil records none.
			groups := applyImmediateEdgePolicy(key, *unresolved, full, fallback.adjacency, nil, dispatchSurfaces, ownerTypes, fragments, functionsByNode, fallback.ambiguous, make(map[graphNode][]adjacencyEdge))
			applyDispatchGroups(key, groups, full, ownerTypes, fragments, functionsByNode, fallback.adjacency, nil, fallback.ambiguous)
		}
	}
	return adjacency, ambiguous, nameOnly
}

// preferDeclared resolves an edge with declared and, when that finds no
// target for a typed call to another component, with closure.
func preferDeclared(declared, closure edgeResolver) edgeResolver {
	return func(e callEdge) edgeTargets {
		targets := declared(e)
		if len(targets.nodes) == 0 && !e.internal && e.resolution != ResolutionNameOnly {
			return closure(e)
		}
		return targets
	}
}

// suppressionLog collects the edges the policy refuses to traverse. Without
// detail it only remembers that it refused one; a nil log records nothing.
type suppressionLog struct {
	edges  []SuppressedEdge
	any    bool
	detail bool
}

// keep marks a refused edge and reports whether its record is wanted, so a
// caller builds the record only then.
func (l *suppressionLog) keep() bool {
	if l == nil {
		return false
	}
	l.any = true
	return l.detail
}

// indexOwnerTypes maps each node to the declaring type of its function, derived
// from Function.FunctionName (the fully-qualified, dotted, customer-facing name
// e.g. "com.password4j.PBKDF2Function.hash" -> "com.password4j.PBKDF2Function").
// This is ecosystem-agnostic: every producer populates FunctionName in this
// "<owner>.<method>" shape (see ConstructorDisplayFromSymbol for the same
// convention used elsewhere in this package). Used only to disambiguate an
// otherwise-ambiguous interface-dispatch group against a resolved receiver type
// (see applyDispatchGroups); absent or malformed names simply never match.
func indexOwnerTypes(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[graphNode]string {
	out := make(map[graphNode]string)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.Functions {
			fn := &fragment.Functions[i]
			if owner := ownerTypeFromFunctionName(fn.FunctionName); owner != "" {
				out[graphNode{Component: key, Function: fn.Signature}] = owner
			}
		}
	}
	return out
}

// ownerTypeFromFunctionName strips the trailing ".<method>" segment from a
// fully-qualified function name, returning the declaring type. Returns "" when
// name has no dot (no owner to derive).
func ownerTypeFromFunctionName(name string) string {
	dot := strings.LastIndex(name, ".")
	if dot <= 0 {
		return ""
	}
	return name[:dot]
}

func componentSet(closure []ComponentKey) map[ComponentKey]bool {
	out := make(map[ComponentKey]bool, len(closure))
	for _, key := range closure {
		out[key] = true
	}
	return out
}

func indexComponentSignatures(key ComponentKey, fragment Fragment, adjacency map[graphNode][]adjacencyEdge) map[string]bool {
	componentSigs := make(map[string]bool, len(fragment.Functions))
	for i := range fragment.Functions {
		node := graphNode{Component: key, Function: fragment.Functions[i].Signature}
		if _, ok := adjacency[node]; !ok {
			adjacency[node] = nil
		}
		componentSigs[fragment.Functions[i].Signature] = true
	}
	return componentSigs
}

func collectCallEdges(fragment Fragment) []callEdge {
	edges := make([]callEdge, 0, len(fragment.InternalEdges)+len(fragment.ExternalCalls))
	for i := range fragment.InternalEdges {
		e := &fragment.InternalEdges[i]
		edges = append(edges, callEdge{
			caller: e.Caller, target: e.Callee, resolution: e.Resolution,
			method: e.MethodName, arity: e.Arity, callSite: e.CallSite, startCol: e.StartCol, endCol: e.EndCol, internal: true, entryCall: e.EntryCall,
			resolvedReceiverType: e.ResolvedReceiverType, declaredType: e.DeclaredType,
		})
	}
	for i := range fragment.ExternalCalls {
		c := &fragment.ExternalCalls[i]
		edges = append(edges, callEdge{
			caller: c.Caller, target: c.TargetSignature, targetCanonicalSignature: c.TargetCanonicalSignature, resolution: c.Resolution,
			method: c.MethodName, arity: c.Arity, callSite: c.CallSite, startCol: c.StartCol, endCol: c.EndCol, internal: false, entryCall: c.EntryCall,
			resolvedReceiverType: c.ResolvedReceiverType, declaredType: c.DeclaredType,
			receiverVar: c.ReceiverVar, chainID: c.ChainID, receiverProducer: c.ReceiverProducer,
		})
	}
	return edges
}

type edgeTargets struct {
	nodes         []graphNode
	compatibility bool
	// nameOnly marks candidates found by name for a call whose target the
	// stitch could not resolve (stitch_python_untyped.go): the edge is
	// treated as a name_only one, never traversed.
	nameOnly bool
}

type edgeResolver func(callEdge) edgeTargets

// callEdgeResolver maps one edge to the concrete target nodes it could reach.
// Internal edges resolve within the component; external edges resolve to other
// components that are direct dependencies of the current component.
func callEdgeResolver(
	key ComponentKey,
	componentSigs map[string]bool,
	directDeps map[ComponentKey]bool,
	functionsBySignature map[string][]graphNode,
	functionsByCanonicalSignature map[string][]graphNode,
	aliasByKey map[string][]graphNode,
	byMethodArity map[string][]graphNode,
	public pythonPublicNames,
	hierarchy *typeHierarchy,
) edgeResolver {
	return func(e callEdge) edgeTargets {
		if e.internal {
			if componentSigs[e.target] {
				return edgeTargets{nodes: []graphNode{{Component: key, Function: e.target}}}
			}
			// Unsuffixed reference to overloaded declarations of this component:
			// candidates go through the dispatch policy, never a silent edge.
			var aliased []graphNode
			for _, node := range aliasByKey[e.target] {
				if node.Component == key {
					aliased = append(aliased, node)
				}
			}
			aliased = filterOverloadCandidates(aliased, e.targetCanonicalSignature)
			return edgeTargets{nodes: aliased, compatibility: len(aliased) > 0}
		}
		targets := externalTargets(e.target, e.targetCanonicalSignature, directDeps, functionsBySignature, functionsByCanonicalSignature, aliasByKey)
		if len(targets.nodes) == 0 && hierarchy != nil {
			// The target type only inherits the method: the declaration sits in a
			// supertype, possibly in a component deeper in the closure.
			if nodes := filterOverloadCandidates(hierarchy.inheritedTargets(e.target), e.targetCanonicalSignature); len(nodes) > 0 {
				targets = edgeTargets{nodes: nodes, compatibility: len(nodes) > 1}
			}
		}
		if len(targets.nodes) == 0 {
			// A Python call spelled with the dependency's public names
			// (`jwt.encode`), or a Node call through a package specifier
			// (`acme-sign.sign`), joins the declaration its exports name. A
			// name_only call is never spelled so.
			targets.nodes = public.targets(e.target, key, directDeps, functionsBySignature, hierarchy)
		}
		if len(targets.nodes) == 0 && e.resolution == ResolutionNameOnly && e.method != "" {
			// A call whose receiver type the caller could not name (a client
			// scan that holds no dependency graph): its candidates are the
			// direct dependencies' methods of that name and arity. The edge
			// stays name_only, so it never proves reachability; it only lets
			// the export say unknown (unresolved_dispatch) instead of nothing.
			for _, callee := range byMethodArity[nameOnlyLookupKey(e)] {
				if directDeps[callee.Component] {
					targets.nodes = append(targets.nodes, callee)
				}
			}
		}
		return targets
	}
}

// methodArityKey is the name#arity part of a function key.
func methodArityKey(method string, arity int) string {
	return method + "#" + strconv.Itoa(arity)
}

// arityFreeMethodKey indexes a function whose key carries no arity: a Python
// function (`jwt.algorithms.(RSAAlgorithm).sign`). Python matches a call to
// a method by name alone (defaults, *args and keywords make a count
// meaningless); the marker keeps it apart from a Java name#arity.
func arityFreeMethodKey(method string) string {
	return method + "#*"
}

// nameOnlyLookupKey is the index key a name_only call's candidates are found
// under: name#arity for a target key with an arity (Java), the method name
// alone for one without (Python, `app.(sink).write`).
func nameOnlyLookupKey(e callEdge) string {
	if !strings.Contains(e.target, "#") {
		return arityFreeMethodKey(e.method)
	}
	return methodArityKey(e.method, e.arity)
}

// indexFunctionsByMethodArity indexes every function of the closure by its
// simple method name and arity, the only identity a name_only call carries.
func indexFunctionsByMethodArity(functionsByNode map[graphNode]*Function) map[string][]graphNode {
	out := make(map[string][]graphNode)
	for node := range functionsByNode {
		key := node.Function
		if i := strings.LastIndex(key, ")."); i >= 0 {
			key = key[i+2:]
		} else if i := strings.LastIndex(key, "."); i >= 0 {
			key = key[i+1:]
		}
		if i := strings.Index(key, "$"); i >= 0 {
			key = key[:i]
		}
		if !strings.Contains(node.Function, "#") {
			key = arityFreeMethodKey(nodeUnnumberedName(key))
		}
		out[key] = append(out[key], node)
	}
	for k := range out {
		sort.Slice(out[k], func(i, j int) bool {
			if out[k][i].Component != out[k][j].Component {
				return componentKeyLess(out[k][i].Component, out[k][j].Component)
			}
			return out[k][i].Function < out[k][j].Function
		})
	}
	return out
}

func externalTargets(
	target string,
	targetCanonicalSignature string,
	directDeps map[ComponentKey]bool,
	functionsBySignature map[string][]graphNode,
	functionsByCanonicalSignature map[string][]graphNode,
	aliasByKey map[string][]graphNode,
) edgeTargets {
	var targets []graphNode
	for _, callee := range functionsBySignature[target] {
		if !directDeps[callee.Component] {
			continue
		}
		targets = append(targets, callee)
	}
	if len(targets) > 0 {
		return edgeTargets{nodes: targets}
	}
	if targetCanonicalSignature != "" {
		for _, callee := range functionsByCanonicalSignature[targetCanonicalSignature] {
			if directDeps[callee.Component] {
				targets = append(targets, callee)
			}
		}
		if len(targets) > 0 {
			return edgeTargets{nodes: targets, compatibility: true}
		}
	}
	// Unsuffixed reference to overloaded declarations: dispatch policy decides.
	for _, callee := range aliasByKey[target] {
		if directDeps[callee.Component] {
			targets = append(targets, callee)
		}
	}
	targets = filterOverloadCandidates(targets, targetCanonicalSignature)
	return edgeTargets{nodes: targets, compatibility: len(targets) > 0}
}

// filterOverloadCandidates narrows overload-suffixed alias candidates using
// the call's canonical parameter types. Candidates are scored by how many
// known (non-"?") parameter types match the candidate's suffix types by erased
// simple name; the unique best-scoring candidate wins. Caller-side types can
// be imprecise (a call-result argument may carry its receiver's type), so a
// single mismatched position must not disqualify the only overload the other
// positions clearly select — but a tie stays ambiguous and the dispatch policy
// fails closed exactly as before.
func filterOverloadCandidates(candidates []graphNode, targetCanonicalSignature string) []graphNode {
	if len(candidates) < 2 {
		return candidates
	}
	params, ok := canonicalParamSimpleNames(targetCanonicalSignature)
	if !ok {
		return candidates
	}
	best := -1
	var narrowed []graphNode
	for _, candidate := range candidates {
		score := overloadMatchScore(candidate.Function, params)
		switch {
		case score < 0:
			continue
		case score > best:
			best = score
			narrowed = narrowed[:0]
			narrowed = append(narrowed, candidate)
		case score == best:
			narrowed = append(narrowed, candidate)
		}
	}
	if len(narrowed) == 0 {
		return candidates
	}
	return narrowed
}

// canonicalParamSimpleNames extracts the erased simple parameter type names
// from a canonical signature's parameter list.
func canonicalParamSimpleNames(signature string) ([]string, bool) {
	open := strings.Index(signature, "(")
	closeIdx := strings.LastIndex(signature, ")")
	if open < 0 || closeIdx <= open {
		return nil, false
	}
	inner := strings.TrimSpace(signature[open+1 : closeIdx])
	if inner == "" {
		return []string{}, true
	}
	parts := splitTopLevelCanonicalArgs(inner)
	names := make([]string, len(parts))
	for i, part := range parts {
		names[i] = erasedSimpleTypeName(part)
	}
	return names, true
}

// splitTopLevelCanonicalArgs splits a canonical parameter list on top-level
// commas, respecting generic-argument nesting.
func splitTopLevelCanonicalArgs(inner string) []string {
	var parts []string
	depth, start := 0, 0
	for i := 0; i < len(inner); i++ {
		switch inner[i] {
		case '<':
			depth++
		case '>':
			depth--
		case ',':
			if depth == 0 {
				parts = append(parts, strings.TrimSpace(inner[start:i]))
				start = i + 1
			}
		}
	}
	parts = append(parts, strings.TrimSpace(inner[start:]))
	return parts
}

// erasedSimpleTypeName reduces a (possibly qualified, possibly generic) type
// text to the erased simple name an overload suffix uses. "?" is preserved.
func erasedSimpleTypeName(typeText string) string {
	typeText = strings.TrimSpace(typeText)
	if angle := strings.Index(typeText, "<"); angle >= 0 {
		suffix := ""
		if closeIdx := strings.LastIndex(typeText, ">"); closeIdx >= 0 && closeIdx+1 < len(typeText) {
			suffix = typeText[closeIdx+1:]
		}
		typeText = typeText[:angle] + suffix
	}
	arraySuffix := ""
	for strings.HasSuffix(typeText, "[]") {
		typeText = typeText[:len(typeText)-2]
		arraySuffix += "[]"
	}
	if dot := strings.LastIndex(typeText, "."); dot >= 0 {
		typeText = typeText[dot+1:]
	}
	return typeText + arraySuffix
}

// overloadMatchScore counts how many known (non-"?") call parameter types
// match an overload-suffixed function key's suffix types. Returns -1 when the
// candidate has no suffix to compare or a different arity.
func overloadMatchScore(functionKey string, params []string) int {
	dollar := strings.Index(functionKey, "$")
	if dollar < 0 {
		return -1
	}
	have := strings.Split(functionKey[dollar+1:], ",")
	if len(have) != len(params) {
		return -1
	}
	score := 0
	for i := range have {
		if params[i] == "?" {
			continue
		}
		if strings.TrimSpace(have[i]) == params[i] {
			score++
		}
	}
	return score
}

func applyImmediateEdgePolicy(
	key ComponentKey,
	edges []callEdge,
	resolve edgeResolver,
	adjacency map[graphNode][]adjacencyEdge,
	suppressed *suppressionLog,
	dispatchSurfaces map[graphNode][]graphNode,
	ownerTypes map[graphNode]string,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	ambiguous map[graphNode][]adjacencyEdge,
	nameOnly map[graphNode][]adjacencyEdge,
) map[dispatchGroupKey][]callEdge {
	// Interface-dispatch candidates are deferred and grouped per call site so
	// ambiguity (>1 impl in closure) is detected across all sibling edges,
	// including siblings that cross the internal/external boundary.
	dispatchGroups := make(map[dispatchGroupKey][]callEdge)
	for i := range edges {
		e := &edges[i]
		caller := graphNode{Component: key, Function: e.caller}
		targets := resolve(*e)
		resolution := e.resolution
		if targets.nameOnly {
			resolution = ResolutionNameOnly
		}
		switch resolution {
		case ResolutionExact:
			if targets.compatibility && len(targets.nodes) > 1 {
				gk := dispatchKey(key, *e)
				dispatchGroups[gk] = append(dispatchGroups[gk], *e)
				continue
			}
			appendAdjacencyEdges(adjacency, caller, targets.nodes, e)
			expandDispatchSurfaces(key, e, caller, targets.nodes, dispatchSurfaces, ownerTypes, fragments, functionsByNode, adjacency, suppressed, ambiguous)
		case ResolutionInterfaceDispatch:
			gk := dispatchKey(key, *e)
			dispatchGroups[gk] = append(dispatchGroups[gk], *e)
		case ResolutionNameOnly:
			appendAdjacencyEdges(nameOnly, caller, targets.nodes, e)
			if suppressed.keep() {
				suppressed.edges = append(suppressed.edges, suppressedEdge(key, *e, SuppressReasonNameOnly, candidateComponents(targets.nodes)))
			}
		default: // ResolutionUnknown, or a future unhandled kind: fail closed.
			if suppressed.keep() {
				suppressed.edges = append(suppressed.edges, suppressedEdge(key, *e, SuppressReasonUnknown, candidateComponents(targets.nodes)))
			}
		}
	}
	return dispatchGroups
}

// expandDispatchSurfaces bridges an exact edge that lands on a dispatch
// surface: the surface node keeps its direct edge (a default/base method body
// stays traversable), and its implementations are added under the standard
// dispatch policy — a single candidate traverses, several fail closed unless
// receiver-type provenance narrows them to exactly one (the same contract
// applyDispatchGroups enforces for producer-marked dispatch edges). A surface
// with a body of its own (concreteSurface) is itself a candidate: a call on a
// PdfWriter runs PdfWriter's method unless the receiver is a PdfCopy, so a
// sole override is no more the target than the base method is.
func expandDispatchSurfaces(
	key ComponentKey,
	e *callEdge,
	caller graphNode,
	targets []graphNode,
	dispatchSurfaces map[graphNode][]graphNode,
	ownerTypes map[graphNode]string,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	adjacency map[graphNode][]adjacencyEdge,
	suppressed *suppressionLog,
	ambiguous map[graphNode][]adjacencyEdge,
) {
	for _, target := range targets {
		impls := dispatchSurfaces[target]
		if len(impls) == 0 {
			continue
		}
		concrete := concreteSurface(target, fragments, functionsByNode)
		if len(impls) == 1 && !concrete {
			appendAdjacencyEdges(adjacency, caller, impls, e)
			continue
		}
		implEdges := make([]adjacencyEdge, 0, len(impls))
		for _, impl := range impls {
			implEdges = append(implEdges, adjacencyEdge{target: impl, entryCall: e.entryCall, resolution: e.resolution, declaredType: e.declaredType})
		}
		candidates := implEdges
		if concrete {
			// The surface's own edge is already in the adjacency.
			candidates = append([]adjacencyEdge{{target: target}}, implEdges...)
		}
		if resolved, ok := disambiguateByReceiverType([]callEdge{*e}, candidates, ownerTypes); ok {
			if resolved.target != target {
				adjacency[caller] = append(adjacency[caller], resolved)
			}
			continue
		}
		ambiguous[caller] = append(ambiguous[caller], implEdges...)
		if suppressed.keep() {
			suppressed.edges = append(suppressed.edges, ambiguousDispatchEdge(key, dispatchKey(key, *e), implEdges, fragments, functionsByNode))
		}
	}
}

// concreteSurface reports whether a dispatch surface has a body of its own,
// which only a fragment that marks its abstract methods can say: in one that
// does not, every surface reads as abstract, as before graph-fragment-1.24.
func concreteSurface(surface graphNode, fragments map[ComponentKey]Fragment, functionsByNode map[graphNode]*Function) bool {
	fn := functionsByNode[surface]
	return fn != nil && !fn.Abstract && fragments[surface.Component].AbstractMethods
}

func dispatchKey(key ComponentKey, e callEdge) dispatchGroupKey {
	return dispatchGroupKey{
		Component:  key,
		Caller:     e.caller,
		CallSite:   e.callSite,
		StartCol:   e.startCol,
		EndCol:     e.endCol,
		MethodName: e.method,
		Arity:      e.arity,
	}
}

func applyDispatchGroups(
	key ComponentKey,
	groups map[dispatchGroupKey][]callEdge,
	resolve edgeResolver,
	ownerTypes map[graphNode]string,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	adjacency map[graphNode][]adjacencyEdge,
	suppressed *suppressionLog,
	ambiguous map[graphNode][]adjacencyEdge,
) {
	for _, gk := range sortedDispatchKeys(groups) {
		group := groups[gk]
		targets := distinctTargetEdges(group, resolve)
		caller := graphNode{Component: key, Function: gk.Caller}
		switch {
		case len(targets) == 1:
			adjacency[caller] = append(adjacency[caller], targets[0])
		case len(targets) > 1:
			if resolved, ok := disambiguateByReceiverType(group, targets, ownerTypes); ok {
				adjacency[caller] = append(adjacency[caller], resolved)
				continue
			}
			ambiguous[caller] = append(ambiguous[caller], targets...)
			if suppressed.keep() {
				suppressed.edges = append(suppressed.edges, ambiguousDispatchEdge(key, gk, targets, fragments, functionsByNode))
			}
			// len(targets) == 0: no implementation in closure -> unreachable,
			// nothing to traverse and nothing to record.
		}
	}
}

// disambiguateByReceiverType narrows an ambiguous dispatch group (>1 candidate
// target) to a single edge when the call site carries resolved receiver-type
// provenance (see InternalEdge.ResolvedReceiverType) that matches EXACTLY ONE
// candidate's declaring type. This is the mine-time KB-contract/return-type
// inference paying off at stitch time: an interface call site the producer
// could not resolve structurally (name+arity expansion still finds every
// sibling implementation) is disambiguated using the concrete type inference
// already determined for that specific receiver.
//
// The match is by SIMPLE (unqualified) type name: ownerTypes indexes the full
// "<package>.<Type>" (from Function.FunctionName), while ResolvedReceiverType
// is typically the erased/simple name the producer's inference works with
// (e.g. FunctionDecl.ReturnType) — mirroring the same simple-name convention
// resolveParameterPassthroughDispatch already uses on the mine side.
//
// Returns ok=false — leaving the group to fail closed exactly as before — when:
//   - no candidate edge carries receiver-type provenance, or
//   - the resolved type matches zero candidates (stale/foreign type), or
//   - the resolved type matches more than one candidate (should not happen for
//     a well-formed KB, but never assumed).
//
// This never changes the fail-closed default for a call site inference did not
// resolve: it only ever narrows an already-ambiguous group to at most one
// survivor, never invents a candidate that resolve() did not already produce.
func disambiguateByReceiverType(group []callEdge, targets []adjacencyEdge, ownerTypes map[graphNode]string) (adjacencyEdge, bool) {
	receiver := firstTypedReceiver(group)
	if receiver == nil {
		return adjacencyEdge{}, false
	}
	resolvedType := simpleTypeName(receiver.resolvedReceiverType)

	var match adjacencyEdge
	matches := 0
	for _, t := range targets {
		if simpleTypeName(ownerTypes[t.target]) == resolvedType {
			match = t
			matches++
		}
	}
	if matches != 1 {
		return adjacencyEdge{}, false
	}
	// A class read off the receiver's producer names its package too: a
	// candidate of that simple name in another package is another class.
	if receiver.receiverConstructed && !declaredIn(ownerTypes[match.target], receiver.receiverPackage) {
		return adjacencyEdge{}, false
	}
	return match, true
}

// simpleTypeName returns the trailing, unqualified segment of a (possibly
// fully-qualified) type name, e.g. "com.password4j.PBKDF2Function" ->
// "PBKDF2Function". A name with no dot is returned unchanged.
func simpleTypeName(typeName string) string {
	if idx := strings.LastIndex(typeName, "."); idx >= 0 {
		return typeName[idx+1:]
	}
	return typeName
}

// firstTypedReceiver is the first edge of group whose receiver type is
// resolved, nil when none is.
func firstTypedReceiver(group []callEdge) *callEdge {
	for i := range group {
		if group[i].resolvedReceiverType != "" {
			return &group[i]
		}
	}
	return nil
}

func appendAdjacencyEdges(
	adjacency map[graphNode][]adjacencyEdge,
	caller graphNode,
	targets []graphNode,
	edge *callEdge,
) {
	for _, target := range targets {
		adjacency[caller] = append(adjacency[caller], adjacencyEdge{
			target:       target,
			entryCall:    edge.entryCall,
			resolution:   edge.resolution,
			declaredType: edge.declaredType,
		})
	}
}

func distinctTargetEdges(edges []callEdge, resolve edgeResolver) []adjacencyEdge {
	distinct := map[graphNode]bool{}
	var targets []adjacencyEdge
	for i := range edges {
		e := &edges[i]
		for _, t := range resolve(*e).nodes {
			if distinct[t] {
				continue
			}
			distinct[t] = true
			targets = append(targets, adjacencyEdge{target: t, entryCall: e.entryCall, resolution: e.resolution, declaredType: e.declaredType})
		}
	}
	return targets
}

func ambiguousDispatchEdge(
	key ComponentKey,
	gk dispatchGroupKey,
	targets []adjacencyEdge,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
) SuppressedEdge {
	targets = sortedAdjacencyEdges(targets)
	frames := make([]CallFrame, 0, len(targets))
	for _, target := range targets {
		frames = append(frames, buildFrame(target.target, inbound{
			entryCall:    target.entryCall,
			resolution:   target.resolution,
			declaredType: target.declaredType,
		}, fragments, functionsByNode))
	}
	return SuppressedEdge{
		Caller:          buildFrame(graphNode{Component: key, Function: gk.Caller}, inbound{}, fragments, functionsByNode),
		MethodName:      gk.MethodName,
		Arity:           gk.Arity,
		CallSite:        gk.CallSite,
		StartCol:        gk.StartCol,
		EndCol:          gk.EndCol,
		Reason:          SuppressReasonAmbiguousDispatch,
		Candidates:      candidateComponentsFromEdges(targets),
		CandidateFrames: frames,
	}
}

func candidateComponentsFromEdges(edges []adjacencyEdge) []ComponentKey {
	candidates := make([]ComponentKey, 0, len(edges))
	for _, edge := range edges {
		candidates = append(candidates, edge.target.Component)
	}
	return candidates
}

func candidateComponents(targets []graphNode) []ComponentKey {
	candidates := make([]ComponentKey, 0, len(targets))
	for _, t := range targets {
		candidates = append(candidates, t.Component)
	}
	return candidates
}

func suppressedEdge(from ComponentKey, e callEdge, reason string, candidates []ComponentKey) SuppressedEdge {
	return SuppressedEdge{
		Caller:     CallFrame{Component: from, Signature: e.caller},
		MethodName: e.method,
		Arity:      e.arity,
		Reason:     reason,
		Candidates: candidates,
	}
}

func sortedDispatchKeys(groups map[dispatchGroupKey][]callEdge) []dispatchGroupKey {
	keys := make([]dispatchGroupKey, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Caller != b.Caller {
			return a.Caller < b.Caller
		}
		if a.CallSite != b.CallSite {
			return a.CallSite < b.CallSite
		}
		if a.StartCol != b.StartCol {
			return a.StartCol < b.StartCol
		}
		if a.EndCol != b.EndCol {
			return a.EndCol < b.EndCol
		}
		if a.MethodName != b.MethodName {
			return a.MethodName < b.MethodName
		}
		return a.Arity < b.Arity
	})
	return keys
}

func indexCryptoOperations(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[graphNode][]CryptoOperation {
	out := make(map[graphNode][]CryptoOperation)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.CryptoOperations {
			node := graphNode{Component: key, Function: fragment.CryptoOperations[i].Function}
			out[node] = append(out[node], fragment.CryptoOperations[i])
		}
	}
	return out
}

func indexSupportingCalls(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[graphNode][]SupportingCall {
	out := make(map[graphNode][]SupportingCall)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.SupportingCalls {
			node := graphNode{Component: key, Function: fragment.SupportingCalls[i].Function}
			out[node] = append(out[node], fragment.SupportingCalls[i])
		}
	}
	return out
}

// indexOperationEntryPoints collects the role-bearing crypto_entry_points
// carried on the stored fragments (issue-103 WU2/WU3), keyed by their
// FunctionKey — the bare-signature string the served path joins on everywhere
// else (ExportCryptoEntryPoint.FunctionKey, ExportSupportingCall.FunctionKey).
// Only entries with role data (MethodRole set OR ParameterRoles present) are
// carried, since the served crypto_entry_points are otherwise rebuilt from
// reachability; operation-only catalog entries remain dropped. Returns nil when
// none carry role data, so the merge pass and its allocations are skipped.
func indexOperationEntryPoints(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[string][]CryptoEntryPoint {
	var out map[string][]CryptoEntryPoint
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.CryptoEntryPoints {
			ep := fragment.CryptoEntryPoints[i]
			if ep.MethodRole == "" && len(ep.ParameterRoles) == 0 {
				continue
			}
			if out == nil {
				out = make(map[string][]CryptoEntryPoint)
			}
			out[ep.FunctionKey] = append(out[ep.FunctionKey], ep)
		}
	}
	return out
}

// stitchMaxFrontier caps the backward-BFS queue size as a safety valve against
// pathological graphs. It mirrors callgraph.traceMaxFrontier: with the
// per-op graph-global frontier set each function is enqueued at most once, so the
// queue is bounded by the number of functions and this cap should never fire in
// practice — it exists purely to guarantee bounded memory if that invariant is
// ever violated.
const stitchMaxFrontier = 1_000_000

// Stitch preserves the SDK depth and sample defaults. Local CLI shares the
// depth cap but selects its own smaller export profile; callers can align
// MaxChains explicitly when comparing sampled routes across both surfaces.
const (
	stitchMaxDepth        = 32
	DefaultMaxChainsPerOp = 128
)

// ResolveMaxChains maps a caller-supplied emit budget onto DefaultMaxChainsPerOp
// when the value is omitted (zero) or invalid (negative).
func ResolveMaxChains(n int) int {
	if n <= 0 {
		return DefaultMaxChainsPerOp
	}
	return n
}

// reverseEdge is one backward step: from a node to one of its callers, carrying
// the entryCall of the FORWARD edge (caller -> node) so frame EntryCall stamping
// stays byte-identical to the old forward DFS.
type reverseEdge struct {
	caller graphNode
	inbound
}

// inbound describes the edge that arrives at a frame: its call site, how it was
// established, and the static type it was written against. Grouped because the
// three always travel together, from the adjacency to the served frame.
type inbound struct {
	entryCall    *CallSite
	resolution   ResolutionKind
	declaredType string
}

// backwardChain is the chain being grown by the BFS, in entry->...->op order.
// inbounds[i] describes the edge that ARRIVES at nodes[i] from nodes[i-1]: its
// call site, how it was established, and the type it was written against. The
// head frame has no inbound edge and carries the zero value.
type backwardChain struct {
	nodes    []graphNode
	inbounds []inbound
}

// chainEntryNodes resolves StitchOptions.ChainEntrySignatures to the functions
// they name, on either spelling the index publishes. Any function can be named,
// not only a root: the index publishes every function that reaches the crypto.
// It returns nil when no signature was supplied — the signal to enumerate from
// every entry, keeping the default path unchanged — and an empty (non-nil) set
// when signatures were supplied but none names a function, which correctly
// yields no chains rather than falling back to all of them.
func chainEntryNodes(functionsByNode map[graphNode]*Function, signatures []string) map[graphNode]bool {
	if len(signatures) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(signatures))
	for _, sig := range signatures {
		if sig != "" {
			wanted[sig] = true
		}
	}
	out := make(map[graphNode]bool, len(wanted))
	for node, fn := range functionsByNode {
		if (fn.CanonicalSignature != "" && wanted[fn.CanonicalSignature]) ||
			(fn.ErasedSignature != "" && wanted[fn.ErasedSignature]) {
			out[node] = true
		}
	}
	return out
}

// traceBackward mirrors callgraph.Tracer.TraceBackLimited: for each
// crypto-op node it runs a backward BFS over a reverse adjacency with a PER-OP
// graph-global frontier set (each function enqueued at most once -> O(V+E)).
// Re-convergent (diamond) branches collapse to the first caller reached; distinct
// entries are preserved (one chain per entry). This replaces the old forward DFS
// that enumerated all simple paths (O(paths)) and emitted the extra re-convergent
// chains live never produces.
func traceBackward(
	adjacency map[graphNode][]adjacencyEdge,
	callers map[graphNode][]graphNode,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	roots []graphNode,
	chainEntries map[graphNode]bool,
	composedFindings map[string]bool,
	composedRoutes map[string][]graphNode,
	ambiguousCandidates map[graphNode][]adjacencyEdge,
	maxChains int,
	out *Result,
) {
	reverse := reverseAdjacency(adjacency)
	entrySet := make(map[graphNode]bool, len(roots))
	for _, r := range roots {
		entrySet[r] = true
	}

	// The index is built from entrySet (every entry, always); only the chain
	// enumeration honors the caller's restriction. See ChainEntrySignatures.
	chainEntrySet := entrySet
	if chainEntries != nil {
		chainEntrySet = chainEntries
	}

	// supportingSeen dedupes supporting-call emission across surviving chains so a
	// node shared by several chains emits its supporting calls once. On diamond-free
	// graphs each node appears on exactly one chain, so behavior is unchanged.
	supportingSeen := make(map[graphNode]bool)

	// backwardDistances walks the plain caller lists; the chain walk needs the
	// call sites too. Index them once rather than per operation.
	recordAllReachEntries(callers, opsByNode, entrySet, fragments, functionsByNode, out)

	// callers/inbounds back every condensedBackwardChainsFast call below; built
	// once here instead of once per operation (condensedBackwardChains rebuilt
	// them from reverse on every call, which dominated runtime on components
	// with thousands of crypto operations — e.g. bcpg-jdk18on pulling in
	// bcprov-jdk18on's full graph).
	inbounds := reverseInbounds(reverse)
	direct := flattenDirectReverse(reverse)

	// reachableFromChainEntry is every node some entry in chainEntrySet can
	// reach by forward calls. An entry reaches opNode forward iff opNode's
	// backward walk (condensedBackwardChainsFast) reaches that entry, so this
	// single O(V+E) pass tells us in advance, for every operation, whether that
	// walk can possibly find a boundary — without running it. On a component
	// scoped to a few requested entries (ChainEntrySignatures), most operations
	// are not downstream of any of them; skipping the walk for those is what
	// turns an O(operations × graph size) worst case back into O(graph size).
	reachableFromChainEntry := forwardReachableSet(adjacency, chainEntrySet)
	// A request naming anything keeps unreached operations in the index; one
	// naming nothing yields nothing.
	keepIndex := len(chainEntries) > 0 || composedFindings != nil

	for _, opNode := range sortedNodes(opsByNode) {
		// Enumerate the routes over the collapsed graph, so the served chains
		// report the same routes live does for the same map.
		// The route total is counted before enumerating (condensedBackwardChains
		// returns it) but is not published: the served contract has no field for
		// it, and this package stays free of a logger by design.
		var chains []backwardChain
		var truncated bool
		if reachableFromChainEntry[opNode] {
			chains, _, truncated = condensedBackwardChainsFast(opNode, callers, inbounds, direct, chainEntrySet, maxChains)
		}
		if len(chains) == 0 {
			if truncated {
				// Path-count ceiling (#292): Count proved entry-reaching routes
				// exist but Routes was skipped. Emit one finding carrier per op
				// with PathCountTruncated so ToCallgraphExport can stamp
				// unknown/partial with empty call_chains — do not fabricate the
				// self-entry chain that asserts the op is its own entry.
				emitPathCountTruncatedFindings(opNode, opsByNode, fragments, functionsByNode, out)
				continue
			}
			if chainEntries != nil && !chainEntries[opNode] &&
				!composedReaches(composedFindings, opsByNode[opNode]) {
				// Restricted enumeration and no requested entry reaches this
				// operation. The self-chain fallback below exists for a crypto call
				// nothing calls at all; synthesizing it here would assert the
				// operation is reachable from an entry that does not reach it.
				emitIndexOnlyFindings(keepIndex, opNode, opsByNode, fragments, functionsByNode, out)
				continue
			}
			// The op node's own frame is the terminal frame of the self-chain
			// below, and a crypto op the parser attributed to NO containing
			// function -- a match inside a `#[cfg(test)] mod`, a macro body, a
			// static initializer -- has nothing to build one from. That chain
			// would assert a frame with no identity at all: no function key, no
			// name, no signature.
			//
			// Such a frame cannot be expressed in the interned form: identity
			// lives only in the functions catalog, so the entry holds nothing
			// to hydrate from, and a consumer that requires hydrated frames
			// rejects the whole component over one unattributable op.
			//
			// SCOPE. This is the empty-key case only. An op whose function key
			// NAMES a signature the fragment does not declare produces the same
			// identity-less frame, and is deliberately left alone:
			// TestComposedRouteFallsBackWithoutADependencyLeg pins that shape
			// as the documented degradation ("a fragment that named no route
			// still answers, with the single frame holding the crypto"), so
			// changing it is a separate decision with its own measurement.
			if opNode.Function == "" {
				frame := buildFrame(opNode, inbound{}, fragments, functionsByNode)
				emitUnattributedFindings(opNode, &frame, opsByNode, supportingByNode, supportingSeen, out)
				continue
			}
			// No backward chain reached an entry (the op node has no callers, or none
			// of its callers are entries). Mirror live's buildBaseCallChains fallback:
			// emit a single-node chain so a self-contained crypto call is still
			// reported. The op node IS its own entry in this case.
			chains = []backwardChain{composedRouteChain(opNode, opsByNode[opNode], composedRoutes, adjacency, ambiguousCandidates, out)}
		}
		for _, chain := range chains {
			emitChain(opNode, chain, opsByNode, supportingByNode, fragments, functionsByNode, supportingSeen, truncated, out)
		}
	}
}

// emitUnattributedFindings records each crypto op on opNode as a finding
// carrier marked Unattributed. The frame is carried but never exported as a
// chain (see FindingChain.Unattributed): keeping it is what preserves the
// finding's purl and its dependency-prefixed finding_id, both of which are
// derived from the terminal frame's component. Supporting calls on the node are
// flushed exactly as emitChain would, since they carry their own identity and
// nothing about them is unexpressible.
func emitUnattributedFindings(
	opNode graphNode,
	frame *CallFrame,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	supportingSeen map[graphNode]bool,
	out *Result,
) {
	if !supportingSeen[opNode] {
		supportingSeen[opNode] = true
		flushSupportingCalls(opNode, frame, supportingByNode, out)
	}
	for i := range opsByNode[opNode] {
		op := opsByNode[opNode][i]
		opCopy := op
		out.Chains = append(out.Chains, FindingChain{
			FindingID:    op.FindingID,
			RuleID:       op.RuleID,
			Symbol:       op.Symbol,
			Frames:       []CallFrame{*frame},
			Confidence:   ConfidenceHigh,
			CryptoOp:     &opCopy,
			Unattributed: true,
		})
	}
}

// emitIndexOnlyFindings records each crypto op on opNode as an IndexOnly
// carrier when keep is set: the index needs the finding's served identity,
// not a route.
func emitIndexOnlyFindings(
	keep bool,
	opNode graphNode,
	opsByNode map[graphNode][]CryptoOperation,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	out *Result,
) {
	if !keep {
		return
	}
	frame := buildFrame(opNode, inbound{}, fragments, functionsByNode)
	for i := range opsByNode[opNode] {
		opCopy := opsByNode[opNode][i]
		out.Chains = append(out.Chains, FindingChain{
			FindingID:  opCopy.FindingID,
			RuleID:     opCopy.RuleID,
			Symbol:     opCopy.Symbol,
			Frames:     []CallFrame{frame},
			Confidence: ConfidenceHigh,
			CryptoOp:   &opCopy,
			IndexOnly:  true,
		})
	}
}

// emitPathCountTruncatedFindings records each crypto op on opNode as a finding
// carrier after the condensed path-count ceiling skipped route materialization.
// Frames hold only the op node so anchor identity survives; PathCountTruncated
// tells the export converter not to treat that frame as a genuine self-chain.
func emitPathCountTruncatedFindings(
	opNode graphNode,
	opsByNode map[graphNode][]CryptoOperation,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	out *Result,
) {
	frame := buildFrame(opNode, inbound{}, fragments, functionsByNode)
	for i := range opsByNode[opNode] {
		op := opsByNode[opNode][i]
		opCopy := op
		out.Chains = append(out.Chains, FindingChain{
			FindingID:          op.FindingID,
			RuleID:             op.RuleID,
			Symbol:             op.Symbol,
			Frames:             []CallFrame{frame},
			Confidence:         ConfidenceHigh,
			CryptoOp:           &opCopy,
			PathCountTruncated: true,
		})
	}
}

// composedChainEntryFindings resolves the caller's entry-point signatures against
// the composed entry points and returns the mine-time finding IDs they reach.
// Nil when no signature was supplied or none names a composed entry point, which
// keeps a signature naming nothing yielding nothing.
func composedChainEntryFindings(
	root ComponentKey,
	out *Result,
	functionsByNode map[graphNode]*Function,
	signatures []string,
	routes map[string][]graphNode,
) map[string]bool {
	if len(signatures) == 0 || len(out.composedEntryPoints) == 0 {
		return nil
	}
	wanted := make(map[string]bool, len(signatures))
	for _, sig := range signatures {
		if sig != "" {
			wanted[sig] = true
		}
	}
	findings := make(map[string]bool)
	for i := range out.composedEntryPoints {
		ep := &out.composedEntryPoints[i]
		sig := ep.CanonicalSignature
		if sig == "" {
			if fn := functionsByNode[graphNode{Component: root, Function: ep.FunctionKey}]; fn != nil {
				sig = fn.CanonicalSignature
			}
		}
		if sig == "" || !wanted[sig] {
			continue
		}
		for id := range out.composedRawFindings[ep.FunctionKey] {
			findings[id] = true
		}
		for id, route := range out.composedRoutes[ep.FunctionKey] {
			if existing, seen := routes[id]; !seen || len(route) < len(existing) {
				routes[id] = route
			}
		}
	}
	if len(findings) == 0 {
		return nil
	}
	return findings
}

// composedRouteChain is the chain emitted when no route could be enumerated.
// A requested composed entry point that named its whole route to one of this
// node's operations supplies its frames; otherwise the chain degrades to the
// single node, which is what a crypto call nothing calls reports.
func composedRouteChain(
	opNode graphNode,
	ops []CryptoOperation,
	composedRoutes map[string][]graphNode,
	adjacency, ambiguousCandidates map[graphNode][]adjacencyEdge,
	out *Result,
) backwardChain {
	for i := range ops {
		route := composedRoutes[ops[i].FindingID]
		if len(route) < 2 || route[len(route)-1] != opNode {
			continue
		}
		if out.composedRouteChains == nil {
			out.composedRouteChains = make(map[graphNode]bool)
		}
		out.composedRouteChains[opNode] = true
		return backwardChain{nodes: route, inbounds: composedRouteInbounds(route, adjacency, ambiguousCandidates)}
	}
	return backwardChain{nodes: []graphNode{opNode}, inbounds: []inbound{{}}}
}

// composedRouteInbounds resolves, for each hop of a composed route, the edge
// that arrives at it. The stitched leg is in the adjacency; the leg the
// dependency's fragment recorded is not, and its hops report no resolution
// rather than borrowing one they were not given.
func composedRouteInbounds(
	route []graphNode,
	adjacency map[graphNode][]adjacencyEdge,
	ambiguousCandidates map[graphNode][]adjacencyEdge,
) []inbound {
	out := make([]inbound, len(route))
	for i := 1; i < len(route); i++ {
		// The ambiguous candidates are searched too, and deliberately: an edge
		// lands there because its dispatch could not be narrowed, so those are
		// the least certain hops of all. Leaving exactly those unlabelled would
		// invert the point of labeling.
		out[i] = lookupInbound(route[i-1], route[i], adjacency, ambiguousCandidates)
	}
	return out
}

func lookupInbound(
	caller, callee graphNode,
	adjacency, ambiguousCandidates map[graphNode][]adjacencyEdge,
) inbound {
	for _, group := range [2][]adjacencyEdge{adjacency[caller], ambiguousCandidates[caller]} {
		for _, edge := range group {
			if edge.target == callee {
				return inbound{
					entryCall:    edge.entryCall,
					resolution:   edge.resolution,
					declaredType: edge.declaredType,
				}
			}
		}
	}
	return inbound{}
}

// composedReaches reports whether a requested composed entry point proves it
// reaches an operation at this node. The route cannot be enumerated, so the
// self-chain below carries the finding graph its verdict attaches to.
func composedReaches(composedFindings map[string]bool, ops []CryptoOperation) bool {
	for i := range ops {
		if composedFindings[ops[i].FindingID] {
			return true
		}
	}
	return false
}

// reverseAdjacency inverts the forward adjacency: target node -> list of callers,
// each carrying the entryCall of the forward edge (caller -> target). Callers are
// stably sorted by signature so the BFS collapses re-convergent branches to the
// same representative as live (which we also sort — see enqueueCallers in
// callgraph/tracer.go).
func reverseAdjacency(adjacency map[graphNode][]adjacencyEdge) map[graphNode][]reverseEdge {
	reverse := make(map[graphNode][]reverseEdge)
	for caller, edges := range adjacency {
		for _, edge := range edges {
			reverse[edge.target] = append(reverse[edge.target], reverseEdge{
				caller: caller,
				inbound: inbound{
					entryCall:    edge.entryCall,
					resolution:   edge.resolution,
					declaredType: edge.declaredType,
				},
			})
		}
	}
	for target := range reverse {
		edges := reverse[target]
		sort.SliceStable(edges, func(i, j int) bool {
			if edges[i].caller.Function != edges[j].caller.Function {
				return edges[i].caller.Function < edges[j].caller.Function
			}
			return componentKeyLess(edges[i].caller.Component, edges[j].caller.Component)
		})
	}
	return reverse
}

// forwardReachableSet returns every node reachable by forward calls from any
// node in sources, via a single multi-source BFS over adjacency. Used to test,
// in O(1) after one O(V+E) pass, whether some entry can reach a given crypto
// operation — the same question a per-operation backward walk answers, but
// without paying for a full walk on every operation that turns out to have no
// path at all.
func forwardReachableSet(adjacency map[graphNode][]adjacencyEdge, sources map[graphNode]bool) map[graphNode]bool {
	seen := make(map[graphNode]bool, len(sources))
	queue := make([]graphNode, 0, len(sources))
	for n := range sources {
		if !seen[n] {
			seen[n] = true
			queue = append(queue, n)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, edge := range adjacency[n] {
			if !seen[edge.target] {
				seen[edge.target] = true
				queue = append(queue, edge.target)
			}
		}
	}
	return seen
}

// forwardReachableSetAll is forwardReachableSet over adjacency plus
// ambiguousCandidates — the forward-edge counterpart of withAmbiguousCallers, for callers that need the "may reach via ambiguous dispatch"
// question answered instead of the precise one.
func forwardReachableSetAll(adjacency, ambiguousCandidates map[graphNode][]adjacencyEdge, sources map[graphNode]bool) map[graphNode]bool {
	seen := make(map[graphNode]bool, len(sources))
	queue := make([]graphNode, 0, len(sources))
	for n := range sources {
		if !seen[n] {
			seen[n] = true
			queue = append(queue, n)
		}
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, edge := range adjacency[n] {
			if !seen[edge.target] {
				seen[edge.target] = true
				queue = append(queue, edge.target)
			}
		}
		for _, edge := range ambiguousCandidates[n] {
			if !seen[edge.target] {
				seen[edge.target] = true
				queue = append(queue, edge.target)
			}
		}
	}
	return seen
}

// emitChain materializes one completed backward chain into a FindingChain and
// flushes the supporting calls of its nodes (entry->op order, deduped via
// supportingSeen). Frame construction is byte-identical to the previous forward
// DFS: same Function identity resolution, same EntryCall, same supporting-call
// field backfill.
func emitChain(
	opNode graphNode,
	chain backwardChain,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	supportingSeen map[graphNode]bool,
	chainsTruncated bool,
	out *Result,
) {
	frames := make([]CallFrame, len(chain.nodes))
	for i, node := range chain.nodes {
		frames[i] = buildFrame(node, chain.inbounds[i], fragments, functionsByNode)
	}

	// Flush supporting calls in entry->op order so output ordering matches the old
	// forward (top-down) DFS on diamond-free graphs.
	for i, node := range chain.nodes {
		if supportingSeen[node] {
			continue
		}
		supportingSeen[node] = true
		flushSupportingCalls(node, &frames[i], supportingByNode, out)
	}

	for i := range opsByNode[opNode] {
		op := opsByNode[opNode][i]
		chainCopy := FindingChain{
			FindingID:       op.FindingID,
			RuleID:          op.RuleID,
			Symbol:          op.Symbol,
			Frames:          append([]CallFrame(nil), frames...),
			Confidence:      ConfidenceHigh,
			ChainsTruncated: chainsTruncated,
		}
		// Carry the full CryptoOperation so the converter can emit crypto_call
		// without re-reading the original fragments.
		opCopy := op
		chainCopy.CryptoOp = &opCopy
		out.Chains = append(out.Chains, chainCopy)
	}
}

// buildFrame resolves one node into a CallFrame, stamping the resolved Function
// identity from the fragment and the EntryCall of the edge that led to this frame.
func buildFrame(
	node graphNode,
	in inbound,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
) CallFrame {
	frame := CallFrame{
		Component:         node.Component,
		Signature:         node.Function,
		EntryCall:         in.entryCall,
		EntryResolution:   in.resolution,
		EntryDeclaredType: in.declaredType,
	}
	if frag, ok := fragments[node.Component]; ok {
		frame.Module = frag.Module
	}
	if fn, ok := functionsByNode[node]; ok {
		frame.Function = *fn
	}
	return frame
}

// flushSupportingCalls appends the supporting calls of one node to out, stamping
// frame identity exactly as the previous forward DFS did.
func flushSupportingCalls(node graphNode, frame *CallFrame, supportingByNode map[graphNode][]SupportingCall, out *Result) {
	for i := range supportingByNode[node] {
		support := supportingByNode[node][i]
		support.Function = frame.Signature
		if support.FunctionName == "" {
			support.FunctionName = frame.Function.FunctionName
		}
		if support.CanonicalSignature == "" {
			support.CanonicalSignature = frame.Function.CanonicalSignature
		}
		if support.DisplaySymbol == "" {
			support.DisplaySymbol = frame.Function.DisplaySymbol
		}
		if len(support.Aliases) == 0 {
			support.Aliases = append([]string(nil), frame.Function.Aliases...)
		}
		out.SupportingCalls = append(out.SupportingCalls, support)
	}
}

// trace is the historical full-rooting forward DFS used only by Stitch
// (EntryRootedOnly=false). It enumerates root-to-crypto paths from each root,
// using a per-path visiting set for cycle prevention. The serving path uses
// traceBackward instead (see StitchWithOptions). Kept verbatim in behavior so the
// resolution fail-closed and parallel-edge tests stay byte-equivalent.
func trace(
	current graphNode,
	adjacency map[graphNode][]adjacencyEdge,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	traversedEdge inbound,
	path []CallFrame,
	visiting map[graphNode]bool,
	out *Result,
) {
	if visiting[current] {
		return
	}
	visiting[current] = true
	defer delete(visiting, current)

	frame := buildFrame(current, traversedEdge, fragments, functionsByNode)

	path = append(path, frame)
	flushSupportingCalls(current, &frame, supportingByNode, out)
	for i := range opsByNode[current] {
		op := opsByNode[current][i]
		chain := FindingChain{
			FindingID:  op.FindingID,
			RuleID:     op.RuleID,
			Symbol:     op.Symbol,
			Frames:     append([]CallFrame(nil), path...),
			Confidence: ConfidenceHigh,
		}
		// Carry the full CryptoOperation so the converter can emit crypto_call
		// without re-reading the original fragments.
		opCopy := op
		chain.CryptoOp = &opCopy
		out.Chains = append(out.Chains, chain)
	}
	for _, edge := range adjacency[current] {
		// Carry this edge's call site and resolution to the next frame.
		trace(edge.target, adjacency, opsByNode, supportingByNode, fragments, functionsByNode,
			inbound{entryCall: edge.entryCall, resolution: edge.resolution, declaredType: edge.declaredType},
			path, visiting, out)
	}
}

// forwardEdgeKey dedupes forward-closure edges: the same (from,to) pair at
// distinct call sites (line) is a distinct edge (multi-edge, e.g. an
// overloaded call site invoked twice); the same (from,to,line) collapses.
type forwardEdgeKey struct {
	from graphNode
	to   graphNode
	line int
}

func entryCallLine(cs *CallSite) int {
	if cs == nil {
		return 0
	}
	return cs.Line
}

// sortedAdjacencyEdges returns a stable-sorted copy of edges (by target
// Function, then target Component, then entryCall line) so forward-BFS
// frontier expansion — and therefore discovery order/depth assignment — is
// deterministic regardless of the order buildAdjacency appended them in.
func sortedAdjacencyEdges(edges []adjacencyEdge) []adjacencyEdge {
	sorted := append([]adjacencyEdge(nil), edges...)
	sort.SliceStable(sorted, func(i, j int) bool {
		a, b := sorted[i], sorted[j]
		if a.target.Function != b.target.Function {
			return a.target.Function < b.target.Function
		}
		if a.target.Component != b.target.Component {
			if less := componentKeyLess(a.target.Component, b.target.Component); less || componentKeyLess(b.target.Component, a.target.Component) {
				return less
			}
		}
		return entryCallLine(a.entryCall) < entryCallLine(b.entryCall)
	})
	return sorted
}

// buildForwardClosures computes one memoized forward BFS per DISTINCT finding
// anchor (opsByNode key) — cross-finding dedup falls out of iterating the
// anchor set rather than the finding set. Iteration order is sortedNodes'
// deterministic order (irrelevant to output content — the memo is
// anchor-keyed — but kept for determinism-in-spirit with the rest of the
// package).
func buildForwardClosures(
	adjacency map[graphNode][]adjacencyEdge,
	suppressed []SuppressedEdge,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	caps forwardCaps,
) map[graphNode]*forwardClosure {
	memo := make(map[graphNode]*forwardClosure, len(opsByNode))
	for _, anchor := range sortedNodes(opsByNode) {
		if _, ok := memo[anchor]; ok {
			continue
		}
		fc := forwardBFS(anchor, adjacency, opsByNode, supportingByNode, fragments, functionsByNode, caps)
		fc.ambiguous = reachableAmbiguities(anchor, fc.nodes, suppressed)
		memo[anchor] = fc
	}
	return memo
}

func reachableAmbiguities(anchor graphNode, nodes []forwardNode, suppressed []SuppressedEdge) []SuppressedEdge {
	reachable := map[graphNode]bool{anchor: true}
	for i := range nodes {
		reachable[nodes[i].node] = true
	}
	var out []SuppressedEdge
	for i := range suppressed {
		edge := suppressed[i]
		caller := graphNode{Component: edge.Caller.Component, Function: edge.Caller.Signature}
		if edge.Reason == SuppressReasonAmbiguousDispatch && reachable[caller] {
			out = append(out, edge)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Caller.Signature != b.Caller.Signature {
			return a.Caller.Signature < b.Caller.Signature
		}
		if a.CallSite != b.CallSite {
			return a.CallSite < b.CallSite
		}
		if a.StartCol != b.StartCol {
			return a.StartCol < b.StartCol
		}
		if a.EndCol != b.EndCol {
			return a.EndCol < b.EndCol
		}
		if a.MethodName != b.MethodName {
			return a.MethodName < b.MethodName
		}
		return a.Arity < b.Arity
	})
	return out
}

// forwardBFS computes the rooted forward reachability graph from anchor: a
// breadth-first traversal of the SAME adjacency the backward pass uses (so
// the fail-closed edge-resolution policy applies for free — suppressed/
// ambiguous/name_only/unknown edges are already absent from adjacency), node-
// deduped via a visited set (cycle-safe: each node expands at most once), with
// explicit depth/node/edge caps. See design doc section 2 for the full
// contract; cap enforcement order is depth (gates expansion) > node (gates
// new-node admission) > edge.
func forwardBFS(
	anchor graphNode,
	adjacency map[graphNode][]adjacencyEdge,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	caps forwardCaps,
) *forwardClosure {
	fc := &forwardClosure{
		anchor:   buildFrame(anchor, inbound{}, fragments, functionsByNode),
		maxDepth: caps.maxDepth,
	}

	st := &forwardBFSState{
		fc:               fc,
		caps:             caps,
		fragments:        fragments,
		functionsByNode:  functionsByNode,
		opsByNode:        opsByNode,
		supportingByNode: supportingByNode,
		visited:          map[graphNode]bool{anchor: true},
		depth:            map[graphNode]int{anchor: 0},
		edgeSeen:         map[forwardEdgeKey]bool{},
	}
	queue := []graphNode{anchor}

	for len(queue) > 0 {
		// Safety valve mirroring the backward pass (stitch.go stitchMaxFrontier):
		// each node is enqueued at most once, bounded by caps.maxNodes, so this
		// should never fire in practice.
		if len(queue) >= stitchMaxFrontier {
			fc.truncated = true
			break
		}

		cur := queue[0]
		queue = queue[1:]
		d := st.depth[cur]

		if d >= caps.maxDepth {
			if len(adjacency[cur]) > 0 {
				// There was more forward story beyond the depth budget; we did not
				// walk it. Never silent.
				fc.truncated = true
			}
			continue
		}

		for _, edge := range sortedAdjacencyEdges(adjacency[cur]) {
			if target, enqueue := st.visitEdge(cur, d, edge); enqueue {
				queue = append(queue, target)
			}
		}
	}

	return fc
}

// forwardBFSState carries the mutable working set of one forwardBFS run so the
// per-edge admission logic can live in visitEdge, keeping the BFS driver loop
// flat.
type forwardBFSState struct {
	fc               *forwardClosure
	caps             forwardCaps
	fragments        map[ComponentKey]Fragment
	functionsByNode  map[graphNode]*Function
	opsByNode        map[graphNode][]CryptoOperation
	supportingByNode map[graphNode][]SupportingCall
	visited          map[graphNode]bool
	depth            map[graphNode]int
	edgeSeen         map[forwardEdgeKey]bool
}

// visitEdge processes one cur->target edge at BFS depth d, enforcing the caps
// (node cap gates admission before any edge is emitted, so no edge ever points
// at an absent node). It returns (target, true) when target is newly admitted
// and must be enqueued; (_, false) otherwise (cap hit, or an
// already-visited target — cycle back-edge / diamond re-convergence — whose
// edge is recorded once but whose node is neither re-added nor re-expanded).
func (s *forwardBFSState) visitEdge(cur graphNode, d int, edge adjacencyEdge) (graphNode, bool) {
	target := edge.target
	key := forwardEdgeKey{from: cur, to: target, line: entryCallLine(edge.entryCall)}

	if !s.visited[target] {
		if len(s.fc.nodes) >= s.caps.maxNodes {
			s.fc.truncated = true
			return graphNode{}, false
		}
		if !s.edgeSeen[key] && len(s.fc.edges) >= s.caps.maxEdges {
			s.fc.truncated = true
			return graphNode{}, false
		}
		s.visited[target] = true
		s.depth[target] = d + 1
		s.fc.nodes = append(s.fc.nodes, buildForwardNode(target, d+1, s.fragments, s.functionsByNode, s.opsByNode, s.supportingByNode))
		s.edgeSeen[key] = true
		s.fc.edges = append(s.fc.edges, forwardEdge{from: cur, to: target, entryCall: edge.entryCall})
		return target, true
	}

	if s.edgeSeen[key] {
		return graphNode{}, false
	}
	if len(s.fc.edges) >= s.caps.maxEdges {
		s.fc.truncated = true
		return graphNode{}, false
	}
	s.edgeSeen[key] = true
	s.fc.edges = append(s.fc.edges, forwardEdge{from: cur, to: target, entryCall: edge.entryCall})
	return graphNode{}, false
}

// buildForwardNode resolves one forward-reachable node into its annotated
// forwardNode shape: identity (via buildFrame), shortest-path depth, and the
// annotate-never-filter crypto relevance signals (Fork 2): cryptoRelevant is
// true when the node is itself a finding anchor OR has a non-empty
// supporting-call category; supportingCategory is the first non-empty
// Category among the node's supporting calls (stable fragment order).
func buildForwardNode(
	node graphNode,
	depth int,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	opsByNode map[graphNode][]CryptoOperation,
	supportingByNode map[graphNode][]SupportingCall,
) forwardNode {
	category := firstSupportingCategory(supportingByNode[node])
	return forwardNode{
		node:               node,
		frame:              buildFrame(node, inbound{}, fragments, functionsByNode),
		depth:              depth,
		cryptoRelevant:     len(opsByNode[node]) > 0 || category != "",
		supportingCategory: category,
	}
}

func firstSupportingCategory(supports []SupportingCall) string {
	for i := range supports {
		if supports[i].Category != "" {
			return supports[i].Category
		}
	}
	return ""
}

// sortedNodes returns the op-bearing nodes in a deterministic order (by signature,
// then component) so chain emission is stable across runs and map iterations.
func sortedNodes(opsByNode map[graphNode][]CryptoOperation) []graphNode {
	nodes := make([]graphNode, 0, len(opsByNode))
	for node := range opsByNode {
		nodes = append(nodes, node)
	}
	sort.SliceStable(nodes, func(i, j int) bool {
		if nodes[i].Function != nodes[j].Function {
			return nodes[i].Function < nodes[j].Function
		}
		return componentKeyLess(nodes[i].Component, nodes[j].Component)
	})
	return nodes
}

// composeDependencyEntryPoints projects each dependency's OWN mine-time
// entry-point knowledge back onto the root component's call surface. A
// dependency fragment carries crypto_entry_points whose reachable_findings and
// chain depths were computed at scan time with full inference — evidence the
// stitch-time trace cannot always reproduce (reflective instantiation,
// ambiguous dispatch). When the stitched adjacency shows a root-component
// function transitively calling one of those entry points, the root function
// provably reaches the entry point's findings; the composed depth is the
// stitched hop count plus the entry point's own mine-time chain depth.
//
// Only the root component's externally callable surface (public function on a
// public owner) plus its in-degree-zero graph roots are emitted — that is the
// join surface a consumer resolves its own code against by canonical_signature.
//
// composeOneDependencyEntryPoint handles a single dependency entry point:
// projectEntryPoint (below) discards every reachFrom(seed, ...) result node
// whose Component isn't root — on a dependency with a large mined entry-point
// surface (a crypto provider can easily publish thousands), a per-seed
// backward walk over the WHOLE closure usually produces nothing but discarded
// non-root ancestors. An entry reaches root some.Function iff some.Function
// forward-reaches that entry (same graph, opposite direction), so the
// caller's shared forward pass from root's own functions (provenFromRoot /
// mayReachFromRoot) tells this function in advance whether the backward walk
// could possibly hit root at all — skipping it entirely when it can't.
func composeOneDependencyEntryPoint(
	root, dep ComponentKey,
	ep *CryptoEntryPoint,
	translate map[string]string,
	reverse, reverseAll map[graphNode][]graphNode,
	provenFromRoot, mayReachFromRoot map[graphNode]bool,
	rootFunctions map[string]Function,
	hasIncoming map[graphNode]bool,
	composed map[string]*composedEntry,
) {
	if len(ep.ReachableFindings) == 0 {
		return
	}
	seed := graphNode{Component: dep, Function: ep.FunctionKey}
	var proven graphwalk.Reachable[graphNode]
	if provenFromRoot[seed] {
		proven = reachFrom(seed, reverse)
		projectEntryPoint(root, dep, ep, translate, proven, true, rootFunctions, hasIncoming, composed)
	}
	if mayReachFromRoot[seed] {
		mayReach := reachFrom(seed, reverseAll)
		for node := range proven.Depth {
			delete(mayReach.Depth, node)
		}
		projectEntryPoint(root, dep, ep, translate, mayReach, false, rootFunctions, hasIncoming, composed)
	}
}

func composeDependencyEntryPoints(
	root ComponentKey,
	closure []ComponentKey,
	fragments map[ComponentKey]Fragment,
	adjacency map[graphNode][]adjacencyEdge,
	reverse map[graphNode][]graphNode,
	ambiguousCandidates map[graphNode][]adjacencyEdge,
	out *Result,
) {
	reverseAll := withAmbiguousCallers(reverse, ambiguousCandidates)

	rootFunctions := make(map[string]Function)
	rootFragment := fragments[root]
	for i := range rootFragment.Functions {
		rootFunctions[rootFragment.Functions[i].Signature] = rootFragment.Functions[i]
	}
	hasIncoming := incomingNodes(adjacency)

	// projectEntryPoint (below) discards every reachFrom(seed, ...) result node
	// whose Component isn't root — on a dependency with a large mined entry-point
	// surface (a crypto provider can easily publish thousands), most of those
	// per-seed backward walks over the WHOLE closure end up producing nothing
	// but discarded non-root ancestors. An entry reaches root some.Function iff
	// some.Function forward-reaches that entry (same graph, opposite direction),
	// so one shared forward pass from root's own functions tells us in advance,
	// for every seed, whether its backward walk could possibly hit root at
	// all — skipping the walk entirely for every seed it can't.
	rootSeeds := make(map[graphNode]bool, len(rootFragment.Functions))
	for i := range rootFragment.Functions {
		rootSeeds[graphNode{Component: root, Function: rootFragment.Functions[i].Signature}] = true
	}
	provenFromRoot := forwardReachableSet(adjacency, rootSeeds)
	mayReachFromRoot := forwardReachableSetAll(adjacency, ambiguousCandidates, rootSeeds)

	composed := make(map[string]*composedEntry)
	for _, dep := range closure {
		if dep == root {
			continue
		}
		fragment := fragments[dep]
		translate := servedFindingIDs(dep, &fragment)
		for i := range fragment.CryptoEntryPoints {
			composeOneDependencyEntryPoint(root, dep, &fragment.CryptoEntryPoints[i], translate,
				reverse, reverseAll, provenFromRoot, mayReachFromRoot, rootFunctions, hasIncoming, composed)
		}
	}
	if len(composed) == 0 {
		return
	}

	keys := make([]string, 0, len(composed))
	for key := range composed {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out.composedFindingDepths = make(map[string]int)
	out.composedRawFindings = make(map[string]map[string]bool)
	out.composedRoutes = make(map[string]map[string][]graphNode)
	for _, key := range keys {
		fn := rootFunctions[key]
		appendComposedResult(root, &fn, composed[key], hasIncoming, out)
	}
}

// publicVisibility is the visibility string producers emit for public members.
const publicVisibility = "public"

// withAmbiguousCallers is the caller lists reverse plus the callers across
// fail-closed ambiguous dispatch groups: the entry-point index is may-reach by
// design, so a consumer-facing entry point may be discovered THROUGH an
// ambiguous call, while finding-level reachability only ever upgrades on
// proven paths.
func withAmbiguousCallers(reverse map[graphNode][]graphNode, ambiguousCandidates map[graphNode][]adjacencyEdge) map[graphNode][]graphNode {
	reverseAll := make(map[graphNode][]graphNode, len(reverse))
	for target, callers := range reverse {
		reverseAll[target] = append([]graphNode(nil), callers...)
	}
	for caller, candidates := range ambiguousCandidates {
		for _, candidate := range candidates {
			reverseAll[candidate.target] = append(reverseAll[candidate.target], caller)
		}
	}
	return reverseAll
}

// callerLists is adjacency reversed: each called function's callers, one per
// call edge, in node order. It is callersWithoutCallSites(reverseAdjacency(
// adjacency)) without the call sites, which the walks that read it do not
// need: the compose walks, the reach index and the chain walk share it.
func callerLists(adjacency map[graphNode][]adjacencyEdge) map[graphNode][]graphNode {
	callers := make(map[graphNode][]graphNode)
	for caller, edges := range adjacency {
		for _, edge := range edges {
			callers[edge.target] = append(callers[edge.target], caller)
		}
	}
	for _, list := range callers {
		sort.Slice(list, func(i, j int) bool { return nodeLess(list[i], list[j]) })
	}
	return callers
}

// indexErasedSignatures maps every fragment function key to its erased join
// signature (1.9+ fragments; absent keys resolve to the empty string).
func indexErasedSignatures(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[string]string {
	out := make(map[string]string)
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.Functions {
			if erased := fragment.Functions[i].ErasedSignature; erased != "" {
				out[fragment.Functions[i].Signature] = erased
			}
		}
	}
	return out
}

// composedEntry accumulates min-depth reachable records for one root function.
type composedEntry struct {
	findings   map[string]ReachableFinding
	supporting map[string]ReachableSupportingCall
	// provenIDs marks findings reached without crossing an ambiguous dispatch
	// group; only these feed the finding-level reachability upgrade.
	provenIDs map[string]bool
	// rawIDs are the untranslated mine-time finding IDs, kept so a restricted
	// enumeration can recognize the operations this entry point reaches.
	rawIDs map[string]bool
	// routes are the whole route to each finding, per untranslated finding id:
	// the stitched frames to the dependency entry point followed by the frames
	// the dependency's fragment recorded from there to the crypto. Absent for a
	// finding whose dependency leg the fragment did not name.
	routes map[string][]graphNode
}

// projectEntryPoint records, for every root-component function that reaches
// one dependency entry point, the composed (hops + mine-time depth) records.
func projectEntryPoint(
	root, dep ComponentKey,
	ep *CryptoEntryPoint,
	translate map[string]string,
	reach graphwalk.Reachable[graphNode],
	proven bool,
	rootFunctions map[string]Function,
	hasIncoming map[graphNode]bool,
	composed map[string]*composedEntry,
) {
	for node, distance := range reach.Depth {
		if node.Component != root {
			continue
		}
		fn, ok := rootFunctions[node.Function]
		if !ok {
			continue
		}
		callable := fn.Visibility == publicVisibility && fn.OwnerVisibility == publicVisibility
		if !callable && hasIncoming[node] {
			continue
		}
		entry := composed[node.Function]
		if entry == nil {
			entry = &composedEntry{
				findings:   make(map[string]ReachableFinding),
				supporting: make(map[string]ReachableSupportingCall),
				provenIDs:  make(map[string]bool),
				rawIDs:     make(map[string]bool),
				routes:     make(map[string][]graphNode),
			}
			composed[node.Function] = entry
		}
		entry.merge(dep, ep, translate, distance, proven, reach.Route(node))
	}
}

// joinComposedRoute splices the two legs of a cross-component route: the
// stitched frames from the consumer function to the dependency's entry point,
// then the frames the dependency's fragment recorded from that entry point to
// the crypto. Both legs name that entry point, so one copy is dropped.
//
// Nil when either leg is missing. Half a route is not a shorter route — it
// would place the crypto somewhere it is not — and the depth still reports the
// distance.
func joinComposedRoute(dep ComponentKey, stitched []graphNode, mined []string) []graphNode {
	if len(stitched) == 0 || len(mined) == 0 {
		return nil
	}
	// The shared frame must actually be shared, or the legs describe different
	// routes and splicing them invents a call.
	if stitched[len(stitched)-1].Function != mined[0] {
		return nil
	}
	route := make([]graphNode, 0, len(stitched)+len(mined)-1)
	route = append(route, stitched...)
	for _, key := range mined[1:] {
		route = append(route, graphNode{Component: dep, Function: key})
	}
	return route
}

// servedFindingIDs maps a dependency's mine-time (annotation-local) finding
// IDs to the IDs the stitched export serves: the same hash recomputed over the
// "module@version/"-prefixed file path, mirroring buildExportChain.
func servedFindingIDs(dep ComponentKey, fragment *Fragment) map[string]string {
	translate := make(map[string]string, len(fragment.CryptoOperations))
	for i := range fragment.CryptoOperations {
		op := &fragment.CryptoOperations[i]
		if op.FindingID == "" {
			continue
		}
		served := computeFindingID(depPrefixedPath(op.FilePath, fragment.Module, dep.Version), op.StartLine, op.RuleID)
		if served != "" {
			translate[op.FindingID] = served
		}
	}
	return translate
}

// translateFindingID maps an annotation-local finding ID to its served form,
// falling back to the original when the operation is unknown (legacy data).
func translateFindingID(translate map[string]string, findingID string) string {
	if served, ok := translate[findingID]; ok {
		return served
	}
	return findingID
}

// merge folds one entry point's reachable records into the composed entry,
// keeping the minimum depth per finding/supporting id.
func (c *composedEntry) merge(
	dep ComponentKey,
	ep *CryptoEntryPoint,
	translate map[string]string,
	distance int,
	proven bool,
	stitched []graphNode,
) {
	for _, rf := range ep.ReachableFindings {
		findingID := translateFindingID(translate, rf.FindingID)
		c.rawIDs[rf.FindingID] = true
		depth := distance + rf.ChainDepth
		if existing, seen := c.findings[findingID]; !seen || depth < existing.ChainDepth {
			c.findings[findingID] = ReachableFinding{
				FindingID:       findingID,
				ChainDepth:      depth,
				FindingGraphRef: translateFindingID(translate, rf.FindingGraphRef),
			}
			if route := joinComposedRoute(dep, stitched, rf.Route); route != nil {
				c.routes[rf.FindingID] = route
			} else {
				delete(c.routes, rf.FindingID)
			}
		}
		if proven {
			c.provenIDs[findingID] = true
		}
	}
	for _, sc := range ep.ReachableSupportingCalls {
		depth := distance + sc.ChainDepth
		if existing, seen := c.supporting[sc.SupportingID]; !seen || depth < existing.ChainDepth {
			c.supporting[sc.SupportingID] = ReachableSupportingCall{
				SupportingID:      sc.SupportingID,
				ChainDepth:        depth,
				SupportingCallRef: sc.SupportingCallRef,
			}
		}
	}
}

// appendComposedResult converts one composed entry into the Result's served
// form, tracking per-finding minimum composed depth and root classification.
func appendComposedResult(root ComponentKey, fn *Function, entry *composedEntry, hasIncoming map[graphNode]bool, out *Result) {
	ep := CryptoEntryPoint{
		FunctionKey:        fn.Signature,
		FunctionName:       fn.FunctionName,
		CanonicalSignature: fn.CanonicalSignature,
		DisplaySymbol:      fn.DisplaySymbol,
		Aliases:            append([]string(nil), fn.Aliases...),
		ReturnType:         fn.ReturnType,
		ParameterTypes:     append([]string(nil), fn.ParameterTypes...),
		Visibility:         fn.Visibility,
		OwnerVisibility:    fn.OwnerVisibility,
	}
	for _, findingID := range sortedComposedIDs(entry.findings) {
		rf := entry.findings[findingID]
		ep.ReachableFindings = append(ep.ReachableFindings, rf)
		if !entry.provenIDs[findingID] {
			continue
		}
		if existing, seen := out.composedFindingDepths[rf.FindingID]; !seen || rf.ChainDepth < existing {
			out.composedFindingDepths[rf.FindingID] = rf.ChainDepth
		}
	}
	supportingIDs := make([]string, 0, len(entry.supporting))
	for id := range entry.supporting {
		supportingIDs = append(supportingIDs, id)
	}
	sort.Strings(supportingIDs)
	for _, id := range supportingIDs {
		ep.ReachableSupportingCalls = append(ep.ReachableSupportingCalls, entry.supporting[id])
	}
	out.composedEntryPoints = append(out.composedEntryPoints, ep)
	if len(entry.rawIDs) > 0 {
		out.composedRawFindings[fn.Signature] = entry.rawIDs
	}
	if len(entry.routes) > 0 {
		out.composedRoutes[fn.Signature] = entry.routes
	}
	if !hasIncoming[graphNode{Component: root, Function: fn.Signature}] {
		if out.composedRoots == nil {
			out.composedRoots = make(map[string]bool)
		}
		out.composedRoots[fn.Signature] = true
	}
}

func sortedComposedIDs(findings map[string]ReachableFinding) []string {
	ids := make([]string, 0, len(findings))
	for id := range findings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// reachFrom walks callers backward from seed over a plain caller map. It is the
// shared walker rather than a local BFS so the route it names is the one the
// depth it reports measures — the two cannot drift apart.
func reachFrom(seed graphNode, reverse map[graphNode][]graphNode) graphwalk.Reachable[graphNode] {
	return graphwalk.Reach(seed, graphwalk.Options[graphNode]{
		Callers: func(n graphNode) []graphNode { return reverse[n] },
		Less:    nodeLess,
	})
}
