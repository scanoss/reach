// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"
	"testing"
)

// nodeCandidatesByLine indexes a function's calls by line, as
// `callee [candidates]`.
func nodeCandidatesByLine(t *testing.T, graph *CallGraph, fnName string) map[int]string {
	t.Helper()
	for _, fn := range graph.Functions {
		if fn.ID.Name != fnName {
			continue
		}
		out := map[int]string{}
		for i := range fn.Calls {
			call := &fn.Calls[i]
			out[call.Line] = call.Callee.String() + " [" + strings.Join(call.CandidateModules, " ") + "]"
		}
		return out
	}
	t.Fatalf("function %s not found", fnName)
	return nil
}

// A call on a variable bound to an object merging modules keeps its
// caller-local key and lists the modules it may hold the member from: an
// Object.assign of requires or module bindings, or a spread of them, at module
// level or in the use's function. A non-module argument, a shadowing name and
// a reassigned variable list none; Object.assign's own call and the requires
// list none either.
func TestNodeMergedModuleObjectListsCandidateModules(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `import * as a from 'acme-a';
const b = require('acme-b');
const H = Object.assign({}, require('acme-h/sha256'), require('acme-h/sha3'));
const M = Object.assign({}, a, b, { extra: 1 });
const S = { ...require('acme-c'), ...b, own: 2 };
const N = Object.assign({}, require('acme-a'), helpers);
let R = Object.assign({}, a, b);
R = other;
H.sha256(1);
M.f(2);
S.g(3);
N.f(4);
R.f(5);
function run(x) {
  const L = Object.assign({}, require('acme-x'), await import('acme-y'));
  L.f(x);
  H.sha3(x);
}
function shadowed(H) {
  H.sha256(1);
}
`)
	assertNodeCallees(t, nodeCandidatesByLine(t, graph, moduleInitMethodName), map[int]string{
		3:  "app.assign []",
		4:  "app.assign []",
		6:  "app.assign []",
		7:  "app.assign []",
		9:  "app.sha256 [acme-h/sha256 acme-h/sha3]",
		10: "app.f [acme-a acme-b]",
		11: "app.g [acme-b acme-c]",
		12: "app.f []",
		13: "app.f []",
	})
	assertNodeCallees(t, nodeCandidatesByLine(t, graph, "run"), map[int]string{
		15: "app.assign []",
		16: "app.f [acme-x acme-y]",
		17: "app.sha3 [acme-h/sha256 acme-h/sha3]",
	})
	assertNodeCallees(t, nodeCandidatesByLine(t, graph, "shadowed"), map[int]string{
		20: "app.sha256 []",
	})
}

// A read on a merged module object lists the same candidate modules as a
// call of it, its key caller-local.
func TestNodeMergedModuleObjectReadListsCandidateModules(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `const H = Object.assign({}, require('acme-h/sha256'), require('acme-h/sha3'));
const hash = H.sha256;
`)
	var got []NodePropertyRead
	for _, reads := range graph.NodePropertyReads {
		got = append(got, reads...)
	}
	if len(got) != 1 {
		t.Fatalf("reads = %+v, want one", got)
	}
	if got[0].TargetKey != "app.sha256" || strings.Join(got[0].CandidateModules, " ") != "acme-h/sha256 acme-h/sha3" {
		t.Errorf("read = %+v, want app.sha256 with candidates acme-h/sha256 acme-h/sha3", got[0])
	}
}
