// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
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

// A call or read on a chain the merged variable heads, whatever its length,
// lists the same candidate modules as a call on the variable itself, its key
// unchanged. A chain headed by another variable lists none.
func TestNodeMergedModuleChainListsCandidateModules(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `const H = Object.assign({}, require('acme-h/sha256'), require('acme-h/sha3'));
const other = makeOther();
H.sha256.create();
H.sha256.create().update(1);
H.sha3.keccak_256(2);
other.sha256.create();
const n = H.sha256.outputLen;
const m = other.sha256.outputLen;
`)
	calls := map[string]string{}
	for _, fn := range graph.Functions {
		for _, call := range fn.Calls {
			calls[fmt.Sprintf("%d:%s", call.Line, call.Callee.Name)] = call.Callee.String() + " [" + strings.Join(call.CandidateModules, " ") + "]"
		}
	}
	want := map[string]string{
		"3:create":     "app.create [acme-h/sha256 acme-h/sha3]",
		"4:create":     "app.create [acme-h/sha256 acme-h/sha3]",
		"4:update":     "app.update [acme-h/sha256 acme-h/sha3]",
		"5:keccak_256": "app.keccak_256 [acme-h/sha256 acme-h/sha3]",
		"6:create":     "app.create []",
	}
	for at, w := range want {
		if calls[at] != w {
			t.Errorf("call %s = %q, want %q", at, calls[at], w)
		}
	}
	reads := map[int]string{}
	for _, list := range graph.NodePropertyReads {
		for _, read := range list {
			reads[read.Line] = read.TargetKey + " [" + strings.Join(read.CandidateModules, " ") + "]"
		}
	}
	assertNodeCallees(t, reads, map[int]string{
		7: "app.outputLen [acme-h/sha256 acme-h/sha3]",
		8: "app.outputLen []",
	})
}
