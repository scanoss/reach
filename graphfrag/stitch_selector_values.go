// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"slices"
	"sort"
	"strings"
)

// stitch_selector_values.go finds the values a call's unresolved arguments
// take across the stitched closure (StitchOptions.SelectorCalls). A component
// mined alone cannot see them: bcprov's DefaultJcaJceHelper passes its
// `algorithm` parameter to SecretKeyFactory.getInstance, and the literals that
// fill it ("PBKDF2with8BIT", "SCRYPT") are written in bcpkix, a component that
// depends on it. The stitch holds both.
//
// The walk is the one a scan runs over its live graph (internal/scan's
// conditioned value enumerator): it follows an argument's PARAMETER provenance
// up through every caller, at every call site reads the argument the caller
// passes, and stops at a resolved value. Its bounds are the scan's: 32 callers
// deep and 256 distinct values per argument; hitting either marks the call's
// values Truncated. With classpath targets, a call the dependency tree leaves
// without a target resolves against the whole closure for the walk
// (classpathEdges).

// Bounds of the selector value walk, the same as a scan's.
const (
	selectorMaxDepth  = 32
	selectorMaxValues = 256
)

// Source node types the walk reads.
const (
	sourceNodeValue     = "VALUE"
	sourceNodeVariable  = "VARIABLE"
	sourceNodeField     = "FIELD"
	sourceNodeParameter = "PARAMETER"
)

// SelectorCall is a call whose unresolved arguments the stitch traces through
// the closure's callers: the function it is made in and its arguments as the
// fragment records them (CryptoOperation.CryptoCall.Parameters).
type SelectorCall struct {
	Component  ComponentKey
	Function   string
	Parameters []Parameter
}

// SelectorVariant is one argument list a SelectorCall receives: its
// Parameters with the argument at Index resolved to the value a caller passes.
type SelectorVariant struct {
	Index      int
	Parameters []Parameter
	// Reachability says whether the root reaches a call site that passes the
	// value, over calls the stitch traverses (reachable), only over an
	// interface call with several implementations (unknown, with
	// UnresolvedReason ambiguous_dispatch), or not at all (unreachable).
	Reachability     string
	UnresolvedReason string
}

// SelectorValues is what the closure passes one SelectorCall.
type SelectorValues struct {
	Variants []SelectorVariant
	// Truncated says the depth cap or the value bound cut the walk, so a value
	// may be missing.
	Truncated bool
}

// SelectorValues returns, index-aligned with StitchOptions.SelectorCalls,
// the values the closure passes each call. Nil when none were asked.
func (r *Result) SelectorValues() []SelectorValues {
	return r.selectorValues
}

// Reach ranks of a value: how the root reaches a call site passing it.
const (
	reachNone      = 0
	reachAmbiguous = 1
	reachTyped     = 2
)

type selectorInbound struct {
	caller    graphNode
	entryCall *CallSite
	ambiguous bool
}

// selectorKey is a parameter of a function: its position, and its name when
// the provenance gives one (what a Python keyword argument is passed under).
type selectorKey struct {
	node  graphNode
	index int
	name  string
}

// selectorParameter is a parameter of the enclosing function an argument's
// provenance names.
type selectorParameter struct {
	index int
	name  string
}

type selectorValue struct {
	value string
	rank  int
}

type selectorTracer struct {
	callers map[graphNode][]selectorInbound
	// ordered marks the callers lists already sorted (inbound).
	ordered map[graphNode]bool
	reach   map[graphNode]int
	memo    map[selectorKey][]selectorValue
	// walkMemo holds every result of the current top-level walk, partial ones
	// included, as the scan's enumerator does: without it every function below
	// a recursion is walked again once per path.
	walkMemo  map[selectorKey][]selectorValue
	onStack   map[selectorKey]bool
	truncated bool
}

// selectorReach ranks every node by how the root reaches it: over calls the
// stitch traverses, or only across interface calls with several
// implementations (ambiguous).
func selectorReach(root ComponentKey, rootFragment Fragment, adjacency, ambiguous map[graphNode][]adjacencyEdge) map[graphNode]int {
	seeds := make(map[graphNode]bool, len(rootFragment.Functions))
	for i := range rootFragment.Functions {
		seeds[graphNode{Component: root, Function: rootFragment.Functions[i].Signature}] = true
	}
	reach := make(map[graphNode]int)
	for node := range forwardReachableSetOver(seeds, adjacency, ambiguous) {
		reach[node] = reachAmbiguous
	}
	for node := range forwardReachableSetOver(seeds, adjacency) {
		reach[node] = reachTyped
	}
	return reach
}

// classpathEdges are the edges the calls a component's own dependencies leave
// without a target get when they resolve against the whole pinned closure, a
// Java runtime classpath: a resolved dependency tree leaves out the edges
// Maven omits as duplicates (bcpkix -> bcprov when the project declares
// bcprov itself). Only the selector value walk reads them; the stitch's
// routes do not change.
type classpathEdges struct {
	closure   []ComponentKey
	adjacency map[graphNode][]adjacencyEdge
	ambiguous map[graphNode][]adjacencyEdge
}

func newClasspathEdges(closure []ComponentKey) *classpathEdges {
	return &classpathEdges{closure: closure, adjacency: make(map[graphNode][]adjacencyEdge), ambiguous: make(map[graphNode][]adjacencyEdge)}
}

// others is every component of the closure but key.
func (c *classpathEdges) others(key ComponentKey) map[ComponentKey]bool {
	set := componentSet(c.closure)
	delete(set, key)
	return set
}

// tracking wraps resolve to collect the calls to another component it finds
// no target for, a name-only guess aside. Without c it is resolve itself.
func (c *classpathEdges) tracking(resolve edgeResolver) (edgeResolver, *[]callEdge) {
	unresolved := new([]callEdge)
	if c == nil {
		return resolve, unresolved
	}
	return func(e callEdge) edgeTargets {
		targets := resolve(e)
		if len(targets.nodes) == 0 && !e.internal && e.resolution != ResolutionNameOnly {
			*unresolved = append(*unresolved, e)
		}
		return targets
	}, unresolved
}

// traceSelectorValues answers every call of calls by walking callers over
// the typed edge maps, and over the ambiguous ones: the candidates of
// interface call sites with several implementations. reach ranks the call
// sites a value is passed at.
func traceSelectorValues(calls []SelectorCall, typed, ambiguous []map[graphNode][]adjacencyEdge, reach map[graphNode]int) []SelectorValues {
	t := &selectorTracer{
		callers: make(map[graphNode][]selectorInbound),
		ordered: make(map[graphNode]bool),
		reach:   reach,
		memo:    make(map[selectorKey][]selectorValue),
		onStack: make(map[selectorKey]bool),
	}
	for i, edgeMaps := range [][]map[graphNode][]adjacencyEdge{typed, ambiguous} {
		for _, edges := range edgeMaps {
			for caller, out := range edges {
				for _, edge := range out {
					t.callers[edge.target] = append(t.callers[edge.target], selectorInbound{caller: caller, entryCall: edge.entryCall, ambiguous: i == 1})
				}
			}
		}
	}
	out := make([]SelectorValues, len(calls))
	for i := range calls {
		out[i] = t.trace(&calls[i])
	}
	return out
}

// trace resolves each unresolved argument of call through the callers of the
// function it is made in: one variant per distinct value.
func (t *selectorTracer) trace(call *SelectorCall) SelectorValues {
	t.truncated = false
	var out SelectorValues
	owner := graphNode{Component: call.Component, Function: call.Function}
	for index := range call.Parameters {
		param := &call.Parameters[index]
		if strings.TrimSpace(param.ResolvedValue) != "" {
			continue
		}
		t.walkMemo = make(map[selectorKey][]selectorValue)
		var values []selectorValue
		position := make(map[string]int)
		t.resolveFromCallers(owner, param.SourceNodes, reachTyped, 0, func(value string, rank int) bool {
			if i, known := position[value]; known {
				values[i].rank = max(values[i].rank, rank)
			} else {
				position[value] = len(values)
				values = append(values, selectorValue{value: value, rank: rank})
			}
			return true
		})
		for _, v := range values {
			out.Variants = append(out.Variants, selectorVariant(call.Parameters, index, v.value, v.rank))
		}
	}
	out.Truncated = t.truncated
	return out
}

// resolveFromCallers resolves an argument whose provenance names parameters
// of owner: each value owner's callers pass such a parameter, propagated into
// the argument, goes to add with its rank capped at edgeRank. add returns
// false to stop. complete is false when the walk was cut.
func (t *selectorTracer) resolveFromCallers(owner graphNode, nodes []SourceNode, edgeRank, depth int, add func(string, int) bool) (complete, more bool) {
	complete = true
	for _, parameter := range selectorParameters(nodes) {
		upstream, upstreamComplete := t.callerValues(owner, parameter, depth)
		complete = complete && upstreamComplete
		for _, u := range upstream {
			if resolved, ok := resolveBoundSourceNodes(nodes, parameter, u.value, true); ok && !add(resolved, min(u.rank, edgeRank)) {
				return false, false
			}
		}
	}
	return complete, true
}

func selectorVariant(params []Parameter, index int, value string, rank int) SelectorVariant {
	variant := SelectorVariant{Index: index, Parameters: append([]Parameter(nil), params...), Reachability: ReachabilityUnreachable}
	variant.Parameters[index].ResolvedValue = value
	switch rank {
	case reachTyped:
		variant.Reachability = ReachabilityReachable
	case reachAmbiguous:
		variant.Reachability, variant.UnresolvedReason = ReachabilityUnknown, UnresolvedReasonAmbiguousDispatch
	}
	return variant
}

// callerValues returns the distinct values the callers of node pass its
// parameter, each with how the root reaches a call site passing it.
// complete is false when a cycle, the depth cap or the value bound cut the
// walk.
func (t *selectorTracer) callerValues(node graphNode, parameter selectorParameter, depth int) ([]selectorValue, bool) {
	key := selectorKey{node: node, index: parameter.index, name: parameter.name}
	if cached, ok := t.memo[key]; ok {
		return cached, true
	}
	if cached, ok := t.walkMemo[key]; ok {
		return cached, false
	}
	if t.onStack[key] {
		return nil, false
	}
	if depth >= selectorMaxDepth {
		t.truncated = true
		return nil, false
	}
	t.onStack[key] = true
	values, complete := t.collectCallerValues(node, parameter, depth)
	delete(t.onStack, key)
	if complete {
		t.memo[key] = values
	} else {
		t.walkMemo[key] = values
	}
	return values, complete
}

func (t *selectorTracer) collectCallerValues(node graphNode, parameter selectorParameter, depth int) ([]selectorValue, bool) {
	complete := true
	position := make(map[string]int)
	var values []selectorValue
	add := func(value string, rank int) bool {
		if i, known := position[value]; known {
			values[i].rank = max(values[i].rank, rank)
			return true
		}
		if len(values) >= selectorMaxValues {
			t.truncated = true
			return false
		}
		position[value] = len(values)
		values = append(values, selectorValue{value: value, rank: rank})
		return true
	}
	for _, in := range t.inbound(node) {
		arg, ok := argumentFor(in.entryCall, parameter)
		if !ok {
			continue
		}
		edgeRank := reachTyped
		if in.ambiguous {
			edgeRank = reachAmbiguous
		}
		if value := strings.TrimSpace(arg.ResolvedValue); value != "" {
			if !add(value, min(t.reach[in.caller], edgeRank)) {
				return values, false
			}
			continue
		}
		upstreamComplete, more := t.resolveFromCallers(in.caller, arg.SourceNodes, edgeRank, depth+1, add)
		if !more {
			return values, false
		}
		complete = complete && upstreamComplete
	}
	return values, complete
}

// inbound is node's callers in caller order. The lists are built from the
// edge maps in map order, and the order a walk reads callers in decides the
// order of the values and which ones a bound cuts: unsorted, the variants of
// a call differed run to run. A caller's own calls keep the order its edges
// have. Sorted on first use, so only the callers a walk reads.
func (t *selectorTracer) inbound(node graphNode) []selectorInbound {
	in := t.callers[node]
	if !t.ordered[node] {
		sort.SliceStable(in, func(i, j int) bool { return nodeLess(in[i].caller, in[j].caller) })
		t.ordered[node] = true
	}
	return in
}

// argumentFor is the argument a call passes for a parameter: the Python
// keyword argument of its name, wherever it is written
// (`sign(p, k, alg="RS256")`), else the argument at its position. A spread
// argument at or before the position means no argument provably fills it,
// and neither does a keyword argument standing there: it binds the
// parameter its own name gives. A keyword-only parameter (position -1) is
// passed by name alone.
func argumentFor(call *CallSite, parameter selectorParameter) (*Parameter, bool) {
	if call == nil {
		return nil, false
	}
	if parameter.name != "" {
		for i := range call.Parameters {
			if call.Parameters[i].Keyword == parameter.name {
				return &call.Parameters[i], true
			}
		}
	}
	index := parameter.index
	if index < 0 || index >= len(call.Parameters) {
		return nil, false
	}
	for i := 0; i <= index; i++ {
		expr := strings.TrimSpace(call.Parameters[i].ArgumentExpression)
		if strings.HasPrefix(expr, "*") || strings.HasPrefix(expr, "...") {
			return nil, false
		}
	}
	arg := &call.Parameters[index]
	for i := range call.Parameters {
		if call.Parameters[i].ParameterIndex == index {
			arg = &call.Parameters[i]
			break
		}
	}
	if arg.Keyword != "" {
		return nil, false
	}
	return arg, true
}

// selectorParameters lists the parameters of the enclosing function an
// argument's top-level provenance names: the PARAMETER nodes a caller's value
// is propagated into. A Python keyword-only parameter has position -1 and is
// told by its name.
func selectorParameters(nodes []SourceNode) []selectorParameter {
	var out []selectorParameter
	for i := range nodes {
		p := nodes[i].ParameterIndex
		if nodes[i].Type != sourceNodeParameter || p == nil {
			continue
		}
		parameter := selectorParameter{index: *p, name: nodes[i].Name}
		if *p < 0 && (*p != -1 || parameter.name == "") {
			continue
		}
		if !slices.ContainsFunc(out, func(seen selectorParameter) bool { return parameter.is(seen.index, seen.name) }) {
			out = append(out, parameter)
		}
	}
	return out
}

// is reports that a PARAMETER node at index, named name, is this parameter:
// the same position, and for a keyword-only one (no position) the same name.
func (p selectorParameter) is(index int, name string) bool {
	return index == p.index && (index >= 0 || name == p.name)
}

// resolveBoundSourceNodes is the single value nodes resolve to when the
// enclosing function's parameter holds value, as a scan resolves an
// argument once a caller's value is propagated into it: every node must
// resolve, and to the same value. bind applies the binding to top-level
// PARAMETER nodes only, the ones a scan propagates into; a call result
// resolves to nothing here.
func resolveBoundSourceNodes(nodes []SourceNode, parameter selectorParameter, value string, bind bool) (string, bool) {
	resolved := ""
	for i := range nodes {
		v, ok := resolveBoundSourceNode(&nodes[i], parameter, value, bind)
		if !ok || (resolved != "" && resolved != v) {
			return "", false
		}
		resolved = v
	}
	return resolved, resolved != ""
}

func resolveBoundSourceNode(node *SourceNode, parameter selectorParameter, value string, bind bool) (string, bool) {
	switch node.Type {
	case sourceNodeValue:
		v := strings.TrimSpace(node.Value)
		if v == "" {
			v = strings.TrimSpace(node.Name)
		}
		return v, v != ""
	case sourceNodeParameter:
		if bind && node.ParameterIndex != nil && parameter.is(*node.ParameterIndex, node.Name) {
			return value, value != ""
		}
		return resolveBoundSourceNodes(node.SourceNodes, parameter, value, false)
	case sourceNodeVariable, sourceNodeField:
		return resolveBoundSourceNodes(node.SourceNodes, parameter, value, false)
	default:
		return "", false
	}
}
