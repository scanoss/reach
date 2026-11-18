// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"
)

// calleesOf lists the callee keys of fn's calls.
func calleesOf(fn *FunctionDecl) []string {
	var out []string
	for i := range fn.Calls {
		out = append(out, fn.Calls[i].Callee.String())
	}
	return out
}

// Two functions assigned as the same property of different objects in one
// module (`hotp.gen`, `totp.gen`) each keep a key and their calls: the first
// one's were dropped when both were app/index.gen. A member call on the
// object targets that object's function.
func TestNodeFunctionKeys_PropertyFunctionsOfTwoObjects(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{"index.js": `const crypto = require('crypto');
var hotp = {}, totp = {};
hotp.gen = function (key) { return crypto.createHmac('sha1', key); };
totp.gen = function (key) { return hotp.gen(key); };
module.exports = { hotp, totp };
`})
	hotp, hotpFn := graphFunction(t, graph, "app/index", "hotp", "gen")
	totp, totpFn := graphFunction(t, graph, "app/index", "totp", "gen")
	if graph.Functions["app/index.gen"] != nil {
		t.Errorf("app/index.gen still declared; functions: %v", functionKeys(graph))
	}
	if !slices.Contains(calleesOf(hotpFn), "crypto.createHmac") {
		t.Errorf("%s calls %v, want crypto.createHmac", hotp, calleesOf(hotpFn))
	}
	if hotpFn.StartLine != 3 || totpFn.StartLine != 4 {
		t.Errorf("hotp.gen at line %d, totp.gen at line %d, want 3 and 4", hotpFn.StartLine, totpFn.StartLine)
	}
	if !hasCaller(graph, hotp, totp) {
		t.Errorf("Callers[%s] = %v, want %s (hotp.gen(key) targets hotp's)", hotp, graph.Callers[hotp], totp)
	}
	if hasCaller(graph, totp, totp) {
		t.Errorf("%s calls itself", totp)
	}
}

// Same-named functions that no object owns keep a key each: the last
// module-level one (else the last one) keeps the shared key, which is the one
// the graph held before, and each other one takes its start as a suffix.
func TestNodeFunctionKeys_SameNamedFunctionsWithoutOwner(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{"index.js": `const crypto = require('crypto');
function hmacSigner(bits) {
  return function sign(thing, secret) { return crypto.createHmac('sha' + bits, secret); };
}
function keySigner(bits) {
  return function sign(thing, key) { return crypto.createSign('RSA-SHA' + bits); };
}
module.exports = { hmacSigner, keySigner };
`})
	_, hmac := graphFunction(t, graph, "app/index", "", "sign@3:10")
	_, key := graphFunction(t, graph, "app/index", "", "sign")
	if !slices.Contains(calleesOf(hmac), "crypto.createHmac") {
		t.Errorf("sign@3:10 calls %v, want crypto.createHmac", calleesOf(hmac))
	}
	if !slices.Contains(calleesOf(key), "crypto.createSign") {
		t.Errorf("sign calls %v, want crypto.createSign", calleesOf(key))
	}

	// A module-level function keeps the name over a nested one after it.
	graph = buildNodeFiles(t, map[string]string{"index.js": `exports.sign = function sign(a) { return a; };
function factory() { return function sign(b) { return b; }; }
`})
	if fn := graph.Functions["app/index.sign"]; fn == nil || fn.StartLine != 1 {
		t.Errorf("app/index.sign = %+v, want the exported function at line 1; functions: %v", fn, functionKeys(graph))
	}
	graphFunction(t, graph, "app/index", "", "sign@2:29")
}

// A module without two functions of one key keys each function as before:
// a property function alone is not qualified by its object, and a
// property function beside a module function of its name leaves that one
// its key.
func TestNodeFunctionKeys_NoCollisionKeepsKeys(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{"index.js": `var hotp = {};
hotp.gen = function (key) { return key; };
exports.sign = function sign(a) { return a; };
`})
	graphFunction(t, graph, "app/index", "", "gen")
	graphFunction(t, graph, "app/index", "", "sign")

	graph = buildNodeFiles(t, map[string]string{"index.js": `function gen(k) { return k; }
var hotp = {};
hotp.gen = function (key) { return gen(key); };
function run() { return gen(1); }
`})
	gen, _ := graphFunction(t, graph, "app/index", "", "gen")
	hotp, _ := graphFunction(t, graph, "app/index", "hotp", "gen")
	run, _ := graphFunction(t, graph, "app/index", "", "run")
	if !hasCaller(graph, gen, run) || !hasCaller(graph, gen, hotp) {
		t.Errorf("Callers[%s] = %v, want %s and %s", gen, graph.Callers[gen], run, hotp)
	}
}

// A member call on a local that shadows the owning object does not target
// the object's function.
func TestNodeFunctionKeys_ShadowedReceiverKeepsItsKey(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{"index.js": `var hotp = {}, totp = {};
hotp.gen = function (key) { return key; };
totp.gen = function (key) { return key; };
function run(hotp) { return hotp.gen(1); }
`})
	hotp, _ := graphFunction(t, graph, "app/index", "hotp", "gen")
	run, _ := graphFunction(t, graph, "app/index", "", "run")
	if hasCaller(graph, hotp, run) {
		t.Errorf("run's parameter hotp reached %s", hotp)
	}
}
