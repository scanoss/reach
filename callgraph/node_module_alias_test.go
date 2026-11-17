// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"testing"
)

// A promise of a dynamic import, awaited or not and with a rejection handler
// or not, holds the module: a member call on it names the module's export.
// The promise's own methods are not the module's.
func TestNodeDynamicImportBindingKeysTheModule(t *testing.T) {
	t.Parallel()

	src := `async function run(x) {
  const lazy = await import('acme-crypto').catch(() => null);
  lazy.hash(x);
  const eager = import('acme-crypto').catch(() => null);
  eager.hash(x);
  const plain = await import('acme-crypto');
  plain.sub.sign(x);
  const pending = import('acme-crypto');
  pending.then(x);
  const handled = await import('acme-crypto').catch(() => null, 2);
  handled.hash(x);
}
`
	got := nodeCalleesOf(t, "run.js", src, "run")
	assertNodeCallees(t, got, map[int]string{
		2:  "app/run.catch",
		3:  "acme-crypto.hash",
		4:  "app/run.catch",
		5:  "acme-crypto.hash",
		7:  "acme-crypto.sub.sign",
		9:  "app/run.then",
		10: "app/run.catch",
		11: "app/run.hash",
	})
}

// A name that holds a module binding, at module scope or in a function body,
// is the module: `const s = sodium; s.f(x)` calls the module's f.
func TestNodeAliasOfModuleBindingKeysTheModule(t *testing.T) {
	t.Parallel()

	src := `const sodium = require('acme-sodium');
import * as ns from 'acme-ns';
const s = sodium;
const lib = ns;
s.seal(1);
lib.open(2);
function run(x) {
  const s2 = sodium;
  const lib2 = lib;
  s2.seal(x);
  lib2.box.open(x);
  s2(x);
  new lib2.Key(x);
  let moved = sodium;
  moved = other;
  moved.seal(x);
}
function shadowed(sodium) {
  sodium.seal(1);
}
`
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, moduleInitMethodName), map[int]string{
		5: "acme-sodium.seal",
		6: "acme-ns.open",
	})
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, "run"), map[int]string{
		10: "acme-sodium.seal",
		11: "acme-ns.box.open",
		12: "acme-sodium.default",
		13: "acme-ns.(Key).<init>",
		16: "app/run.seal",
	})
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, "shadowed"), map[int]string{
		19: "app/run.seal",
	})
}

// Destructuring a require or a module binding inside a function body binds
// the member, as it does at module scope; `const { sm2 } = smCrypto` keys
// sm2's calls as `smCrypto.sm2.x()` keys them.
func TestNodeDestructuredModuleMemberKeysTheModule(t *testing.T) {
	t.Parallel()

	src := `import smCrypto from 'acme-sm';
const { sm2 } = smCrypto;
sm2.doEncrypt(1);
smCrypto.sm2.doEncrypt(2);
function connect() {
  const { tls } = require('acme-net');
  const { sm3: hasher, sm4 } = smCrypto;
  const conn = require('acme-conn');
  hasher.digest(3);
  sm4.encrypt(4);
  conn.open(5);
  return tls.createConnection({});
}
`
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, moduleInitMethodName), map[int]string{
		3: "acme-sm.sm2.doEncrypt",
		4: "acme-sm.sm2.doEncrypt",
	})
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, "connect"), map[int]string{
		9:  "acme-sm.sm3.digest",
		10: "acme-sm.sm4.encrypt",
		11: "acme-conn.open",
		12: "acme-net.tls.createConnection",
	})
}

// The interop helpers compiled output defines locally pass a module binding
// through. A helper counts only when its one argument is a module binding.
func TestNodeLocalInteropHelpersKeyTheModule(t *testing.T) {
	t.Parallel()

	src := `var raw = require('acme-zk');
var a = _interopNamespaceDefault(raw);
var b = _interopNamespace(raw);
var c = _interopRequireWildcard(raw);
var d = _interopRequireDefault(raw);
var e = __importStar(raw);
var f = __importDefault(raw);
var g = _interopNamespaceDefault$1(raw);
var h = _interopNamespaceDefault$1(require('acme-zk2'));
var i = _interopNamespaceDefault(raw, 1);
var j = _interopNamespaceDefault(other);
function run(x) {
  a.plonk.verify(x);
  b.plonk.verify(x);
  c.plonk.verify(x);
  d.default.verify(x);
  e.plonk.verify(x);
  f.default.verify(x);
  g.plonk.verify(x);
  h.plonk.verify(x);
  i.plonk.verify(x);
  j.plonk.verify(x);
}
`
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, "run"), map[int]string{
		13: "acme-zk.plonk.verify",
		14: "acme-zk.plonk.verify",
		15: "acme-zk.plonk.verify",
		16: "acme-zk.verify",
		17: "acme-zk.plonk.verify",
		18: "acme-zk.verify",
		19: "acme-zk.plonk.verify",
		20: "acme-zk2.plonk.verify",
		21: "app/run.verify",
		22: "app/run.verify",
	})
}

// Rollup's _interopDefaultLegacy, `$N` copies included, passes a module
// binding through as the other helpers do, so `x['default']` or `x.default`
// on its result is the module's default export: the call and the read key as
// `require('m').default.init()` and `require('m').default.CURVE` do, at
// module level and in a function.
func TestNodeInteropDefaultLegacyKeysTheModuleDefault(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `var bls = require('acme-bls');
var bls__default = /*#__PURE__*/_interopDefaultLegacy(bls);
var dup = _interopDefaultLegacy$1(bls);
const a = bls__default['default'].init(bls__default['default'].CURVE);
const b = bls__default.default.init(bls__default.default.CURVE);
const c = dup['default'].init(dup['default'].CURVE);
const d = require('acme-bls').default.init(require('acme-bls').default.CURVE);
function run() {
  return bls__default['default'].init(bls__default['default'].CURVE);
}
`)
	got := map[string]string{}
	for _, fn := range graph.Functions {
		for _, call := range fn.Calls {
			if call.Callee.Name == "init" {
				got[fmt.Sprintf("%d call", call.Line)] = call.Callee.String()
			}
		}
	}
	for _, reads := range graph.NodePropertyReads {
		for _, read := range reads {
			got[fmt.Sprintf("%d read", read.Line)] = read.TargetKey
		}
	}
	want := map[string]string{}
	for _, line := range []int{4, 5, 6, 7, 9} {
		want[fmt.Sprintf("%d call", line)] = "acme-bls.init"
		want[fmt.Sprintf("%d read", line)] = "acme-bls.CURVE"
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("keys:\n got %v\nwant %v", got, want)
	}
}

// A member chain on an inline require names the module's export at any depth,
// awaited or not.
func TestNodeInlineRequireMemberChainKeysTheModule(t *testing.T) {
	t.Parallel()

	src := `async function run() {
  const a = await require('acme-gen').Gen.create({ a: 1, b: [2, 3] });
  const b = require('acme-gen').Gen.create();
  const c = require('acme-gen').create();
  return [a, b, c];
}
`
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, "run"), map[int]string{
		2: "acme-gen.Gen.create",
		3: "acme-gen.Gen.create",
		4: "acme-gen.create",
	})
}

// A renamed destructuring of a module binding, `{ sm2: signer }`, keys the
// renamed name's calls as the member's, as the unrenamed form does: const,
// let or var, at module level or in a function body, from a default import, a
// namespace import or a require. A shadowing parameter, a reassigned name and
// a var read before its declaration ran stay caller-local.
func TestNodeRenamedDestructuredModuleMemberKeysTheModule(t *testing.T) {
	t.Parallel()

	src := `import smCrypto from 'acme-sm';
import * as ns from 'acme-ns';
const req = require('acme-req');
var { sm2: signer } = smCrypto;
var { sm2 } = smCrypto;
let { box: opener } = ns;
const { hmac: mac } = req;
signer.doSignature(1);
sm2.doSignature(2);
opener.open(3);
mac.digest(4);
function inBody(x) {
  early.doSignature(x);
  var { sm2: early } = smCrypto;
  early.doSignature(x);
  const { box: b } = ns;
  b.open(x);
  let { hmac: h } = req;
  h.digest(x);
  signer.doSignature(x);
}
function shadowed(signer) {
  signer.doSignature(1);
}
function moved() {
  var { sm2: again } = smCrypto;
  again = other;
  again.doSignature(1);
}
`
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, moduleInitMethodName), map[int]string{
		8:  "acme-sm.sm2.doSignature",
		9:  "acme-sm.sm2.doSignature",
		10: "acme-ns.box.open",
		11: "acme-req.hmac.digest",
	})
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, "inBody"), map[int]string{
		13: "app/run.doSignature",
		15: "acme-sm.sm2.doSignature",
		17: "acme-ns.box.open",
		19: "acme-req.hmac.digest",
		20: "acme-sm.sm2.doSignature",
	})
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, "shadowed"), map[int]string{
		23: "app/run.doSignature",
	})
	assertNodeCallees(t, nodeCalleesOf(t, "run.js", src, "moved"), map[int]string{
		28: "app/run.doSignature",
	})
}
