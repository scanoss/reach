// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"sort"
	"strings"
)

// javaNestedTypeDepth bounds how many trailing segments of a qualified type
// name typeJavaChainLinks tries as nested types ("a.b.Outer.Inner" may be
// bytecode's a.b.Outer$Inner).
const javaNestedTypeDepth = 3

// typeJavaChainLinks types the links of Java method chains whose receiver is
// the value of a previous link, now that bytecode type resolution has recorded
// the return types of platform and dependency methods. The parser types a
// chain link only from a declared receiver or an in-graph return type, so in
// `holder.getObjectDigestInfo().getDigestAlgorithm()` with holder a dependency
// type, the second link was left as a bare name#arity: a name_only call. When
// the previous link's result type is certain (see qualifiedCallResultType) and
// that type declares or inherits the method with the call's arity, the link is
// retyped to it. A link the parser already typed is left alone.
func typeJavaChainLinks(graph *CallGraph) int {
	if graph == nil || len(graph.ExternalMethodSignatures) == 0 {
		return 0
	}
	groups := indexMethodsByQualifiedArity(graph)
	selector := newOverloadSelector(graph, newDispatchHierarchy(graph))
	resolutions := indexEdgeResolutionsByPair(graph)
	keys := make([]string, 0, len(graph.Functions))
	for key := range graph.Functions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	typed := 0
	for _, key := range keys {
		typed += typeJavaChainLinksIn(graph, groups, selector, resolutions, key, graph.Functions[key])
	}
	return typed
}

func typeJavaChainLinksIn(graph *CallGraph, groups map[string][]string, selector *overloadSelector, resolutions map[string][]string, callerKey string, fn *FunctionDecl) int {
	chains := make(map[string][]int)
	var order []string
	for i := range fn.Calls {
		cid := fn.Calls[i].ChainID
		if cid == "" {
			continue
		}
		if _, seen := chains[cid]; !seen {
			order = append(order, cid)
		}
		chains[cid] = append(chains[cid], i)
	}
	typed := 0
	for _, cid := range order {
		idxs := chains[cid]
		// Innermost first: an outer link's Raw extends its receiver's Raw.
		sort.SliceStable(idxs, func(a, b int) bool {
			return len(fn.Calls[idxs[a]].Raw) < len(fn.Calls[idxs[b]].Raw)
		})
		for pos := 1; pos < len(idxs); pos++ {
			receiver, call := &fn.Calls[idxs[pos-1]], &fn.Calls[idxs[pos]]
			if call.Callee.Package != "" || call.Callee.Type != "" || !strings.HasPrefix(call.Raw, receiver.Raw+"(") {
				continue
			}
			resultType := selector.qualifiedCallResultType(receiver.Callee, fn)
			if resultType == "" {
				continue
			}
			target, ok := javaChainLinkTarget(graph, groups, resultType, call)
			if !ok {
				continue
			}
			retypeJavaCall(graph, resolutions, callerKey, fn, call, target)
			typed++
		}
	}
	return typed
}

// javaChainLinkTarget finds the method call invokes on a value of the fully
// qualified type owner: a method the graph declares on it, or one the bytecode
// index records for it (declared or inherited) with the call's arity.
func javaChainLinkTarget(graph *CallGraph, groups map[string][]string, owner string, call *FunctionCall) (FunctionID, bool) {
	cut := len(owner)
	for range javaNestedTypeDepth {
		dot := strings.LastIndex(owner[:cut], ".")
		if dot <= 0 {
			break
		}
		cut = dot
		pkg, nested := owner[:dot], owner[dot+1:]
		if !strings.Contains(nested, ".") {
			if id, fn := findBestQualifiedMethodCandidate(graph, pkg, nested, call, groups); fn != nil {
				return id, true
			}
		}
		id := FunctionID{Package: pkg, Type: strings.ReplaceAll(nested, ".", "$"), Name: call.Callee.Name}
		if len(graph.ExternalMethodSignatures[ExternalMethodSignatureKey(id)]) > 0 {
			return id, true
		}
	}
	return FunctionID{}, false
}

// indexEdgeResolutionsByPair lists the EdgeResolutions keys of each
// caller-callee pair, keyed by EdgeResolutionKeyPrefix.
func indexEdgeResolutionsByPair(graph *CallGraph) map[string][]string {
	out := make(map[string][]string)
	for key, res := range graph.EdgeResolutions {
		if callerKey, calleeKey, ok := EdgeResolutionEndpoints(key, res); ok {
			prefix := EdgeResolutionKeyPrefix(callerKey, calleeKey)
			out[prefix] = append(out[prefix], key)
		}
	}
	return out
}

// retypeJavaCall points call at target and moves its edge with it. The caller
// stays on the old callee's caller list while another of its calls still names
// that callee. A resolution recorded for this call site on the old pair goes;
// the export enumerates a pair's recorded resolutions instead of its calls once
// it has any, so this site is recorded on the new pair when that pair has some.
func retypeJavaCall(graph *CallGraph, resolutions map[string][]string, callerKey string, fn *FunctionDecl, call *FunctionCall, target FunctionID) {
	old := call.Callee.String()
	call.Callee = target
	oldPrefix := EdgeResolutionKeyPrefix(callerKey, old)
	kept := resolutions[oldPrefix][:0]
	for _, key := range resolutions[oldPrefix] {
		res := graph.EdgeResolutions[key]
		if res.CallSite == call.Line && res.StartCol == call.StartCol && res.EndCol == call.EndCol {
			delete(graph.EdgeResolutions, key)
			continue
		}
		kept = append(kept, key)
	}
	resolutions[oldPrefix] = kept
	stillCalled := false
	for i := range fn.Calls {
		if fn.Calls[i].Callee.String() == old {
			stillCalled = true
			break
		}
	}
	if stillCalled {
		addCaller(graph.Callers, target.String(), callerKey)
	} else {
		addCaller(graph.Callers, target.String(), callerKey, old)
	}
	if len(resolutions[EdgeResolutionKeyPrefix(callerKey, target.String())]) > 0 {
		recordCallEdgeResolution(graph, callerKey, target.String(), EdgeKindExact, "", call)
	}
}
