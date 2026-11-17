// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"sort"
	"testing"

	"github.com/scanoss/reach/callgraph/contracts"
)

// nodeExportedSites lists a caller's call sites as an export reads them: one
// per edge resolution, joined to the call the caller makes at that site under
// that key, as `key line:start-end raw`. A resolution no call answers is
// listed as stale.
func nodeExportedSites(graph *CallGraph, callerKey string) []string {
	fn := graph.Functions[callerKey]
	var out []string
	for key, res := range graph.EdgeResolutions {
		caller, callee, ok := EdgeResolutionEndpoints(key, res)
		if !ok || caller != callerKey {
			continue
		}
		site := fmt.Sprintf("%s %d:%d-%d stale", callee, res.CallSite, res.StartCol, res.EndCol)
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if call.Callee.String() == callee && call.Line == res.CallSite && call.StartCol == res.StartCol && call.EndCol == res.EndCol {
				site = fmt.Sprintf("%s %d:%d-%d %s", callee, call.Line, call.StartCol, call.EndCol, call.Raw)
			}
		}
		out = append(out, site)
	}
	sort.Strings(out)
	return out
}

// A call the KB pass re-keys from the caller-local key it shares with other
// calls of the method name leaves no site behind under that key: each call is
// exported once, with its own data, under its final key, and the caller-local
// key keeps only the call still targeting it.
func TestNodeRekeyedCallLeavesNoCallerLocalCopy(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: node
library:
  name: acme-test
contracts:
  - method: acme-pki.Crl.<init>
    arity: 0
    return: {type: acme-pki.Crl, confidence: high}
  - method: acme-pki.Crl.verify
    arity: 1
    return: {type: boolean, confidence: high}
  - method: acme-pki.Csr.<init>
    arity: 0
    return: {type: acme-pki.Csr, confidence: high}
  - method: acme-pki.Csr.verify
    arity: 0
    return: {type: boolean, confidence: high}
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	graph := buildNodeGraph(t, `const acme = require('acme-pki');
const parsed = acme.Certificate.fromBER(ber);
const ok = await parsed.verify(issuer);
const crl = new acme.Crl();
await crl.verify({ issuerCertificate: issuer });
const csr = new acme.Csr();
await csr.verify();
`)
	resolveNodeAssignedVarCallees(graph, kb)

	got := nodeExportedSites(graph, "app.<module>")
	want := []string{
		"acme-pki.(Crl).<init> 4:13-27 new acme.Crl",
		"acme-pki.(Crl).verify 5:7-48 crl.verify",
		"acme-pki.(Csr).<init> 6:13-27 new acme.Csr",
		"acme-pki.(Csr).verify 7:7-19 csr.verify",
		"acme-pki.Certificate.fromBER 2:16-45 acme.Certificate.fromBER",
		"app.verify 3:18-39 parsed.verify",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("exported sites:\n got %q\nwant %q", got, want)
	}
	if callers := graph.Callers["app.verify"]; len(callers) != 1 || callers[0] != "app.<module>" {
		t.Errorf("callers of app.verify = %v, want the module, which still calls it on line 3", callers)
	}
}

// A fluent chain link the KB re-keys drops its own site under the old key,
// and keeps the caller of that key while another call still targets it.
func TestNodeRekeyedChainLinkLeavesNoCallerLocalCopy(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: node
library:
  name: acme-test
contracts:
  - method: acme-h.create
    arity: 0
    return: {type: acme-h.Hasher, confidence: high}
  - method: acme-h.Hasher.digest
    arity: 0
    return: {type: string, confidence: high}
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	graph := buildNodeGraph(t, `const h = require('acme-h');
const a = other.digest();
const b = h.create().digest();
`)
	resolveFluentChainCalleesByContract(graph, kb)

	got := nodeExportedSites(graph, "app.<module>")
	want := []string{
		"acme-h.(Hasher).digest 3:11-30 h.create().digest",
		"acme-h.create 3:11-21 h.create",
		"app.digest 2:11-25 other.digest",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("exported sites:\n got %q\nwant %q", got, want)
	}
	if callers := graph.Callers["app.digest"]; len(callers) != 1 {
		t.Errorf("callers of app.digest = %v, want the module, which still calls it on line 2", callers)
	}
}
