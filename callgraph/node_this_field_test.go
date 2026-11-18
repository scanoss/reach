// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"testing"

	"github.com/scanoss/reach/callgraph/contracts"
)

// A field of this that a function assigns a call's result to is the receiver
// of the calls the function then makes on it: the producer's AssignedVar and
// the call's ReceiverVar are `this.<field>`, and the KB types the call as on
// a variable. A call on a field the function never assigns is keyed by the
// field too, and stays untyped.
func TestNodeThisFieldReceiverTypedByItsProducer(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: node
library:
  name: acme-test
contracts:
  - method: acme-kx.createAgreement
    arity: 1
    return: {type: acme-kx.Agreement, confidence: high}
  - method: acme-kx.Agreement.generateKeys
    arity: 0
    return: {type: Buffer, confidence: high}
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	graph := buildNodeFilesWithKB(t, map[string]string{
		"kex.js": `const { createAgreement } = require('acme-kx');
class Kex {
  generateKeys() {
    if (!this._dh) {
      this._dh = createAgreement(this.curve);
      this._public = this._dh.generateKeys();
    }
  }
  again() { return this._dh.generateKeys(); }
}
`,
	}, kb)
	calls := func(method string) []FunctionCall {
		for _, fn := range graph.Functions {
			if fn.ID.Type == "Kex" && fn.ID.Name == method {
				return fn.Calls
			}
		}
		t.Fatalf("Kex.%s not declared", method)
		return nil
	}
	var producer, typed *FunctionCall
	for i, call := range calls("generateKeys") {
		switch call.Callee.Name {
		case "createAgreement":
			producer = &calls("generateKeys")[i]
		case "generateKeys":
			typed = &calls("generateKeys")[i]
		}
	}
	if producer == nil || producer.AssignedVar != "this._dh" {
		t.Fatalf("producer %+v: want AssignedVar this._dh", producer)
	}
	if typed == nil || typed.ReceiverVar != "this._dh" || typed.AssignedVar != "this._public" || typed.Callee.String() != "acme-kx.(Agreement).generateKeys" {
		t.Fatalf("this._dh.generateKeys(): %+v, want receiver this._dh typed acme-kx.(Agreement).generateKeys", typed)
	}
	for _, call := range calls("again") {
		if call.ReceiverVar != "this._dh" || call.Callee.Type != "" {
			t.Errorf("again: %s receiver %q, want this._dh and untyped", call.Callee, call.ReceiverVar)
		}
	}
}
