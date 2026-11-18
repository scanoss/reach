// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"sort"
	"strings"
	"testing"
)

// Every spelling of the WebCrypto API lands on its WebIDL interface: the
// global crypto object in a browser or in Node, Node's crypto.webcrypto, and
// the subtle object held in a variable or destructured. The Node module's own
// functions keep their module name, and a project object named crypto, or a
// method of the same name on another receiver, is never WebCrypto.
func TestNodeParser_WebCryptoCallsResolveToTheirInterface(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, `import nodeCrypto from 'node:crypto';
import { webcrypto, subtle as nodeSubtle } from 'crypto';
const { subtle: destructuredSubtle } = require('node:crypto').webcrypto;

const moduleSubtle = crypto.subtle;
const { subtle: cryptoSubtle } = globalThis.crypto;

export async function browser(data) {
  await crypto.subtle.digest('SHA-256', data);
  await window.crypto.subtle.encrypt({ name: 'AES-GCM' }, data);
  await globalThis.crypto.subtle.sign('HMAC', data);
  await self.crypto.subtle.verify('HMAC', data);
  crypto.getRandomValues(new Uint8Array(12));
  crypto.randomUUID();
  await moduleSubtle.deriveBits({ name: 'PBKDF2' }, data, 256);
  await cryptoSubtle.exportKey('raw', data);
}

export async function node(data) {
  await nodeCrypto.webcrypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt']);
  await webcrypto.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits']);
  await nodeSubtle.deriveKey({ name: 'HKDF' }, data, { name: 'AES-GCM' }, false, ['encrypt']);
  await destructuredSubtle.wrapKey('raw', data, data, 'AES-KW');
  await require('crypto').webcrypto.subtle.unwrapKey('raw', data, data, 'AES-KW', 'AES-GCM', false, ['encrypt']);
  await require('node:crypto').subtle.decrypt({ name: 'AES-GCM' }, data, data);
  nodeCrypto.getRandomValues(new Uint8Array(12));
  webcrypto.getRandomValues(new Uint8Array(12));
  const { subtle } = nodeCrypto.webcrypto;
  await subtle.digest('SHA-1', data);
  nodeCrypto.randomUUID();
  nodeCrypto.createHash('sha256');
}

export async function lookalikes(crypto, store) {
  await crypto.subtle.digest('SHA-256', store);
  const subtle = store.subtle;
  await subtle.digest('SHA-256', store);
  await store.crypto.subtle.digest('SHA-256', store);
  globalThis.crypto = store;
  return store.getRandomValues(store);
}
`)
	calls := func(name string) []string {
		t.Helper()
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			if fn.ID.Name != name {
				continue
			}
			var out []string
			for _, call := range fn.Calls {
				if call.Callee.Name == "Uint8Array" {
					continue
				}
				out = append(out, call.Callee.String())
			}
			sort.Strings(out)
			return out
		}
		t.Fatalf("function %s not parsed", name)
		return nil
	}

	want := map[string][]string{
		"browser": {
			"(Crypto).getRandomValues",
			"(Crypto).randomUUID",
			"(SubtleCrypto).deriveBits",
			"(SubtleCrypto).digest",
			"(SubtleCrypto).encrypt",
			"(SubtleCrypto).exportKey",
			"(SubtleCrypto).sign",
			"(SubtleCrypto).verify",
		},
		"node": {
			"(Crypto).getRandomValues",
			"(Crypto).getRandomValues",
			"(SubtleCrypto).decrypt",
			"(SubtleCrypto).deriveKey",
			"(SubtleCrypto).digest",
			"(SubtleCrypto).generateKey",
			"(SubtleCrypto).importKey",
			"(SubtleCrypto).unwrapKey",
			"(SubtleCrypto).wrapKey",
			"node:crypto.createHash",
			"node:crypto.randomUUID",
		},
	}
	for name, expected := range want {
		if got := calls(name); strings.Join(got, "\n") != strings.Join(expected, "\n") {
			t.Errorf("%s calls:\n got %q\nwant %q", name, got, expected)
		}
	}
	for _, call := range calls("lookalikes") {
		if strings.Contains(call, "Crypto") {
			t.Errorf("lookalikes: %s resolved to WebCrypto", call)
		}
	}
}

// A name the file binds to the global crypto object, or to Node's webcrypto,
// is that object: destructured from a global object, read off one, a guarded
// read with an empty fallback, a global-object shim, a member of the crypto
// module. A name that may hold anything else stays the name.
func TestNodeParser_WebCryptoLocalAliasesResolveToTheirInterface(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, `const nodeCrypto = require('crypto');
const wc = nodeCrypto.webcrypto;
const { webcrypto: wc2 } = nodeCrypto;
const host = typeof window !== 'undefined' ? window : typeof self !== 'undefined' ? self : {};
const guarded = typeof host === 'object' && 'crypto' in host ? host.crypto : undefined;
function getGlobal() {
  if (typeof self !== 'undefined') { return self; }
  if (typeof window !== 'undefined') { return window; }
  throw new Error('no global');
}
const anyGlobal = getGlobal();
const legacy = anyGlobal.crypto || anyGlobal.msCrypto;
let rebound = globalThis.crypto;
rebound = makeFake();

export async function aliases(data) {
  const { crypto } = globalThis;
  crypto.randomUUID();
  const c = self.crypto;
  await c.subtle.digest('SHA-256', data);
  wc.getRandomValues(data);
  await wc.subtle.importKey('raw', data, 'PBKDF2', false, ['deriveBits']);
  await wc2.subtle.digest('SHA-1', data);
  guarded.getRandomValues(data);
  legacy.getRandomValues(data);
}

// A closure reads an enclosing function's crypto as the global spelling
// does, whatever the enclosing declaration holds, as before aliases were
// followed.
export function create(provider) {
  const crypto = provider.get();
  return async function enclosed(data) { return crypto.subtle.digest('SHA-256', data); };
}

export function notAliases(store, data) {
  const crypto = store.crypto;
  crypto.getRandomValues(data);
  rebound.getRandomValues(data);
  const { crypto: other } = store;
  other.randomUUID();
}
`)
	var got []string
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		for _, call := range fn.Calls {
			if strings.Contains(call.Callee.String(), "Crypto") {
				got = append(got, fn.ID.Name+" "+call.Callee.String())
			}
		}
	}
	sort.Strings(got)
	want := []string{
		"aliases (Crypto).getRandomValues",
		"aliases (Crypto).getRandomValues",
		"aliases (Crypto).getRandomValues",
		"aliases (Crypto).randomUUID",
		"aliases (SubtleCrypto).digest",
		"aliases (SubtleCrypto).digest",
		"aliases (SubtleCrypto).importKey",
		"enclosed (SubtleCrypto).digest",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("WebCrypto calls:\n got %q\nwant %q", got, want)
	}
}
