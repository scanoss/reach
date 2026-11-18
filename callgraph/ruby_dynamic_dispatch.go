// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// ruby_dynamic_dispatch.go reaches what a Ruby call on a receiver nothing
// types may run. `@algorithm.sign(data:, signing_key:)` in the jwt gem runs
// whichever algorithm the registry picked at run time, and no static type
// names it; the component declares a handful of `sign` methods, and the call
// runs one of them. Each is added as a candidate, name-only, so a consumer
// reads the findings behind them as unknown rather than unreachable -- which
// would be a claim the graph cannot make.

// rubyMaxDispatchCandidates bounds the guess. A name a component declares
// everywhere (`call`, `each`) says nothing about which one runs, and adding
// them all would bury the graph in edges that carry no information. A
// crypto library's algorithm family is what the bound has to clear: jwt
// declares `sign` ten times, once per algorithm.
const rubyMaxDispatchCandidates = 16

// resolveRubyDynamicDispatch adds the candidate edges of every call whose
// receiver is named but untyped.
func resolveRubyDynamicDispatch(graph *CallGraph) {
	byName := indexRubyDeclsByName(graph)
	if len(byName) == 0 {
		return
	}
	for _, fn := range graph.Functions {
		if fn == nil {
			continue
		}
		var added []FunctionCall
		for i := range fn.Calls {
			added = append(added, rubyDispatchCandidates(graph, byName, &fn.Calls[i])...)
		}
		fn.Calls = append(fn.Calls, added...)
	}
}

// indexRubyDeclsByName groups the component's methods by their bare name.
func indexRubyDeclsByName(graph *CallGraph) map[string][]*FunctionDecl {
	out := make(map[string][]*FunctionDecl)
	for _, fn := range graph.Functions {
		if fn == nil || fn.ID.Type == "" || !strings.HasSuffix(fn.FilePath, ".rb") {
			continue
		}
		name := BaseFunctionName(fn.ID.Name)
		if name == "" || strings.HasPrefix(name, "<") {
			continue
		}
		out[name] = append(out[name], fn)
	}
	return out
}

// rubyDispatchCandidates is the declarations one call may run. A call the
// graph already resolved has none: the candidates are a guess, and a guess
// beside a resolution only weakens it.
func rubyDispatchCandidates(graph *CallGraph, byName map[string][]*FunctionDecl, call *FunctionCall) []FunctionCall {
	if call.RubySelfCandidate || call.RubyDispatchCandidate {
		return nil
	}
	if call.Callee.Type != "" || call.ResolvedReceiverType != "" || call.ReceiverVar == "" {
		return nil
	}
	if _, resolved := graph.Functions[call.Callee.String()]; resolved {
		return nil
	}
	name := BaseFunctionName(call.Callee.Name)
	decls := byName[name]
	if len(decls) == 0 || len(decls) > rubyMaxDispatchCandidates {
		return nil
	}
	out := make([]FunctionCall, 0, len(decls))
	for _, decl := range decls {
		candidate := *call
		candidate.Callee = decl.ID
		candidate.RubyDispatchCandidate = true
		out = append(out, candidate)
	}
	return out
}
