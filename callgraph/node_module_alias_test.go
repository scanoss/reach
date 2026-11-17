// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

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
