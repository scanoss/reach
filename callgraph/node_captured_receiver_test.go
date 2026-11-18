// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

// A name a function around this one declares is the receiver of the calls
// this one makes on it, as the function's own locals are: a closure's
// captured `kx`, at any depth of nesting. A name no function and not the
// module declares (a global) still leaves the receiver empty.
func TestNodeCapturedNameIsTheReceiver(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, `const acme = require('acme-kx');
function pair(curve) {
  const kx = acme.createAgreement(curve);
  kx.generateKeys();
  return {
    key: kx.getPublicKey(),
    derive(peer, own) {
      if (own) kx.setPrivateKey(own);
      return kx.computeSecret(peer);
    },
    later: () => () => kx.computeSecret(1),
    shadow(kx) { return kx.computeSecret(2); },
    global() { return session.computeSecret(3); },
  };
}
`)
	want := map[string]string{
		"setPrivateKey": "kx",
		"computeSecret": "kx",
	}
	seen := map[string]int{}
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		for j := range fn.Calls {
			call := &fn.Calls[j]
			name := call.Callee.Name
			if call.Raw == "session.computeSecret" {
				if call.ReceiverVar != "" {
					t.Errorf("%s: global receiver ReceiverVar = %q, want none", fn.ID, call.ReceiverVar)
				}
				continue
			}
			if r, ok := want[name]; ok {
				seen[name]++
				if call.ReceiverVar != r {
					t.Errorf("%s: %s ReceiverVar = %q, want %q", fn.ID, call.Raw, call.ReceiverVar, r)
				}
			}
		}
	}
	// setPrivateKey once; computeSecret in derive, the inner arrow and shadow.
	if seen["setPrivateKey"] != 1 || seen["computeSecret"] != 3 {
		t.Errorf("calls seen = %v, want setPrivateKey 1, computeSecret 3", seen)
	}
}
