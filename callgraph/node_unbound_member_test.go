// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

const unboundMemberUtils = `export function digest(v) { return v }
`

const unboundMemberModule = `import crypto from 'crypto'
import * as utils from './utils'

function digest(v) { return v }
function getThing() { return { digest() {} } }

export class Box {
  digest() { return 1 }
  viaThis() { return this.digest() }
}

export function chained(data) {
  return crypto.createHash('md5').update(data).digest('hex')
}
export function callResultReceiver() { return getThing().digest() }
export function paramReceiver(someParam) { return someParam.digest() }
export function plainCall(v) { return digest(v) }
export function namespaceCall(v) { return utils.digest(v) }
export function typedReceiver() { const b = new Box(); return b.digest() }
`

func TestNodeMemberCallOnUnresolvedReceiverBindsNoModuleFunction(t *testing.T) {
	t.Parallel()
	for _, ext := range []string{"js", "ts"} {
		graph := buildNodeFiles(t, map[string]string{
			"m." + ext:     unboundMemberModule,
			"utils." + ext: unboundMemberUtils,
		})
		digest, _ := graphFunction(t, graph, "app/m", "", "digest")
		utilsDigest, _ := graphFunction(t, graph, "app/utils", "", "digest")
		boxDigest, _ := graphFunction(t, graph, "app/m", "Box", "digest")

		for _, name := range []string{"chained", "callResultReceiver", "paramReceiver"} {
			caller, _ := graphFunction(t, graph, "app/m", "", name)
			for _, target := range []string{digest, utilsDigest} {
				if hasCaller(graph, target, caller) {
					t.Errorf("%s: %s must not call %s", ext, name, target)
				}
			}
		}

		controls := []struct{ caller, target string }{
			{"plainCall", digest},
			{"namespaceCall", utilsDigest},
		}
		for _, c := range controls {
			caller, _ := graphFunction(t, graph, "app/m", "", c.caller)
			if !hasCaller(graph, c.target, caller) {
				t.Errorf("%s: Callers[%s] = %v, want %s", ext, c.target, graph.Callers[c.target], caller)
			}
		}
		typed, _ := graphFunction(t, graph, "app/m", "", "typedReceiver")
		if !hasCaller(graph, boxDigest, typed) {
			t.Errorf("%s: typed receiver: Callers[%s] = %v, want %s", ext, boxDigest, graph.Callers[boxDigest], typed)
		}
		viaThis, _ := graphFunction(t, graph, "app/m", "Box", "viaThis")
		if !hasCaller(graph, boxDigest, viaThis) {
			t.Errorf("%s: this call: Callers[%s] = %v, want %s", ext, boxDigest, graph.Callers[boxDigest], viaThis)
		}
	}
}

const requireReceiverModule = `const crypto = require('crypto')

function digest(v) { return v }

function viaRequire(v) { return require('./utils').digest(v) }
function viaRequireMissing() { return require('./utils').missing() }
function viaInterop(v) { return __importStar(require('./utils')).digest(v) }
function stillUnbound(data) { return crypto.createHash('md5').update(data).digest('hex') }
function stillUnboundCall() { return getThing().digest() }

module.exports = { viaRequire, viaRequireMissing, viaInterop, stillUnbound, stillUnboundCall }
`

func TestNodeMemberCallOnInlineRequireBindsTheRequiredModule(t *testing.T) {
	t.Parallel()
	for _, ext := range []string{"js", "ts"} {
		graph := buildNodeFiles(t, map[string]string{
			"m." + ext:     requireReceiverModule,
			"utils." + ext: unboundMemberUtils,
		})
		local, _ := graphFunction(t, graph, "app/m", "", "digest")
		utilsDigest, _ := graphFunction(t, graph, "app/utils", "", "digest")

		for _, name := range []string{"viaRequire", "viaInterop"} {
			caller, _ := graphFunction(t, graph, "app/m", "", name)
			if !hasCaller(graph, utilsDigest, caller) {
				t.Errorf("%s: Callers[%s] = %v, want %s", ext, utilsDigest, graph.Callers[utilsDigest], caller)
			}
			if hasCaller(graph, local, caller) {
				t.Errorf("%s: %s must not call the same-file digest", ext, name)
			}
		}
		for _, name := range []string{"viaRequireMissing", "stillUnbound", "stillUnboundCall"} {
			caller, _ := graphFunction(t, graph, "app/m", "", name)
			for _, target := range []string{local, utilsDigest} {
				if hasCaller(graph, target, caller) {
					t.Errorf("%s: %s must not call %s", ext, name, target)
				}
			}
		}
	}
}

// A member call nothing binds, whose method a function of the module also
// names, is a call of the method of a value nothing typed: keyed by the bare
// name, which no function declares, it stays in the graph (the call was
// lost with the module function's key) and never reaches the function.
// Inside the function of that name too: `function sign() { s.sign() }`.
func TestNodeUnboundMemberSharingAFunctionKeyStaysACall(t *testing.T) {
	t.Parallel()
	for _, ext := range []string{"js", "ts"} {
		graph := buildNodeFiles(t, map[string]string{
			"m." + ext: unboundMemberModule,
			"s." + ext: `const acme = require('acme-sig')
function make(bits) {
  return function sign(data, key) {
    const signer = acme.createSigner('x' + bits)
    return signer.sign({ key, mode: 'pss' }, data)
  }
}
module.exports = { make }
`,
			"utils." + ext: unboundMemberUtils,
		})
		digest, _ := graphFunction(t, graph, "app/m", "", "digest")
		for _, name := range []string{"chained", "callResultReceiver", "paramReceiver"} {
			caller, _ := graphFunction(t, graph, "app/m", "", name)
			if !hasCaller(graph, "digest", caller) {
				t.Errorf("%s: Callers[digest] = %v, want %s", ext, graph.Callers["digest"], caller)
			}
			if hasCaller(graph, digest, caller) {
				t.Errorf("%s: %s must not call %s", ext, name, digest)
			}
		}
		signKey, sign := graphFunction(t, graph, "app/s", "", "sign")
		if !hasCaller(graph, "sign", signKey) || hasCaller(graph, signKey, signKey) {
			t.Errorf("%s: Callers[sign] = %v, Callers[%s] = %v, want only the bare key called", ext, graph.Callers["sign"], signKey, graph.Callers[signKey])
		}
		for _, call := range sign.Calls {
			if call.Raw == "signer.sign" && (call.Callee.String() != "sign" || call.ReceiverVar != "signer" || len(call.Arguments) != 2) {
				t.Errorf("%s: signer.sign = %s receiver %q args %q, want sign on signer with 2 arguments", ext, call.Callee, call.ReceiverVar, call.Arguments)
			}
		}
		if _, declared := graph.Functions["sign"]; declared {
			t.Errorf("%s: the bare key must name no function", ext)
		}
	}
}
