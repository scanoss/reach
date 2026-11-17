// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

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
