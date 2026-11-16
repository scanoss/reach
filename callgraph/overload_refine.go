// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// javaLangPackage is the package every Java file imports implicitly.
const javaLangPackage = "java.lang"

// refineOverloadEdgesAfterTypes re-selects the overloads of every call whose
// callee names a same-arity overload group, now that bytecode type resolution
// has recorded the return types of platform and dependency methods.
// buildCallerIndex selected them before those types existed, so an argument
// such as `key.getEncoded()` was untyped and every overload of the group was
// linked. A call now links exactly the overloads selectOverloads keeps: an
// edge it no longer justifies loses this call site's resolution, and the
// caller leaves the callee's caller list when no other call site of the
// caller still resolves to it.
func refineOverloadEdgesAfterTypes(graph *CallGraph) {
	if graph == nil || len(graph.ExternalMethodSignatures) == 0 {
		return
	}
	groups := indexMethodsByQualifiedArity(graph)
	selector := newOverloadSelector(graph, newDispatchHierarchy(graph))
	dropped := make(map[string]bool)
	for callerKey, fn := range graph.Functions {
		for i := range fn.Calls {
			refineCallOverloads(graph, groups, selector, callerKey, fn, &fn.Calls[i], dropped)
		}
		for i := range fn.ImplicitCalls {
			if !fn.ImplicitCalls[i].Reference {
				refineCallOverloads(graph, groups, selector, callerKey, fn, &fn.ImplicitCalls[i], dropped)
			}
		}
	}
	if len(dropped) == 0 {
		return
	}
	for key := range graph.EdgeResolutions {
		res := graph.EdgeResolutions[key]
		delete(dropped, EdgeResolutionKeyPrefix(res.callerKey, res.calleeKey))
	}
	for prefix := range dropped {
		callerKey, calleeKey, _ := strings.Cut(strings.TrimSuffix(prefix, "\x00"), "\x00")
		removeCaller(graph.Callers, calleeKey, callerKey)
	}
}

func refineCallOverloads(graph *CallGraph, groups map[string][]string, selector *overloadSelector, callerKey string, caller *FunctionDecl, call *FunctionCall, dropped map[string]bool) {
	calleeKey := call.Callee.String()
	if graph.Functions[calleeKey] != nil {
		return
	}
	candidates := groups[qualifiedMethodArityKey(call.Callee.Package, call.Callee.Type, call.Callee.Name)]
	if len(candidates) < 2 {
		return
	}
	kept := selector.selectOverloads(graph, call, caller, candidates)
	if len(kept) == len(candidates) {
		return
	}
	keep := make(map[string]bool, len(kept))
	for _, target := range kept {
		keep[target] = true
		if !hasCallerKey(graph.Callers[target], callerKey) {
			addCaller(graph.Callers, target, callerKey)
		}
		recordCallEdgeResolution(graph, callerKey, target, EdgeKindExact, "", call)
	}
	for _, target := range candidates {
		if keep[target] {
			continue
		}
		method, arity := "", 0
		if id, err := ParseFunctionID(target); err == nil {
			method, arity = BaseFunctionName(id.Name), functionArity(id.Name)
		}
		key := EdgeResolutionKey(callerKey, target, EdgeResolution{
			CallSite: call.Line, StartCol: call.StartCol, EndCol: call.EndCol,
			MethodName: method, Arity: arity,
		})
		if res, ok := graph.EdgeResolutions[key]; ok && res.Kind == EdgeKindExact {
			delete(graph.EdgeResolutions, key)
			dropped[EdgeResolutionKeyPrefix(callerKey, target)] = true
		}
	}
}

func hasCallerKey(callers []string, callerKey string) bool {
	for _, c := range callers {
		if c == callerKey {
			return true
		}
	}
	return false
}
