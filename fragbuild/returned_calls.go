// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"sort"

	"github.com/scanoss/reach/callgraph"
)

// returnedCallees lists, sorted, the callees whose call result fn returns
// under ReturnsCallResult. Each names one call, since ReturnsCallResult only
// accepts a callee fn calls once. A graph fragment records the list on the
// function as returns_calls, which is all the walk needs to run on the
// fragment.
func returnedCallees(fn *callgraph.FunctionDecl) []string {
	if fn == nil || len(fn.ReturnSources) == 0 {
		return nil
	}
	var out []string
	for i := range fn.Calls {
		if ReturnsCallResult(fn, &fn.Calls[i]) {
			out = append(out, fn.Calls[i].Callee.String())
		}
	}
	sort.Strings(out)
	return out
}

// ReturnsCallResult reports whether fn returns the object call produces:
// `return f()`, or `x = f(); ... return x`. A return source names its producer
// by callee only, so the producer must be the one call to that callee in fn;
// with two, the returned object could be either.
func ReturnsCallResult(fn *callgraph.FunctionDecl, call *callgraph.FunctionCall) bool {
	if fn == nil || call == nil || len(fn.ReturnSources) == 0 {
		return false
	}
	callee := call.Callee.String()
	count := 0
	for i := range fn.Calls {
		if fn.Calls[i].Callee.String() == callee {
			count++
		}
	}
	if count != 1 {
		return false
	}
	for i := range fn.ReturnSources {
		if returnSourceIsCall(&fn.ReturnSources[i], call) {
			return true
		}
	}
	return false
}

func returnSourceIsCall(node *callgraph.SourceNode, call *callgraph.FunctionCall) bool {
	switch node.Type {
	case SourceNodeTypeCallResult:
		return node.CallTarget != nil && node.CallTarget.String() == call.Callee.String()
	case SourceNodeTypeVariable:
		if call.AssignedVar == "" || node.Name != call.AssignedVar {
			return false
		}
		for i := range node.SourceNodes {
			nested := &node.SourceNodes[i]
			if nested.Type == SourceNodeTypeCallResult && nested.CallTarget != nil && nested.CallTarget.String() == call.Callee.String() {
				return true
			}
		}
	}
	return false
}
