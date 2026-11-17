// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

// nodeCallSitesByLine indexes a function's calls by line, as
// `callee recv=<receiver> asg=<assigned> chain=<chained>`; the raw text is
// checked apart, since the two spellings differ there.
func nodeCallSitesByLine(t *testing.T, graph *CallGraph, fnName string) (map[int][]string, map[int][]string) {
	t.Helper()
	for _, fn := range graph.Functions {
		if fn.ID.Name != fnName {
			continue
		}
		sites, raws := map[int][]string{}, map[int][]string{}
		for i := range fn.Calls {
			call := &fn.Calls[i]
			site := call.Callee.String() + " recv=" + call.ReceiverVar + " asg=" + call.AssignedVar
			if call.ChainID != "" {
				site += " chained"
			}
			sites[call.Line] = append(sites[call.Line], site)
			raws[call.Line] = append(raws[call.Line], call.Raw)
		}
		return sites, raws
	}
	t.Fatalf("function %s not found", fnName)
	return nil, nil
}

// A call through a string-literal index is the call of the member the index
// names: same key, receiver, assigned variable and chain as the dotted
// spelling, with raw as written. A template literal or a computed index names
// no member and makes no call site.
func TestNodeStringIndexCallKeysAsDottedForm(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `const hash = require('acme-hash');
import * as acme from 'acme-crypto';
import smCrypto from 'acme-sm';
a = hash["sha256"](1);
a = hash.sha256(1);
acme['mode'].CTR.create();
acme.mode.CTR.create();
hash[name]();
hash[`+"`sha256`"+`]();
function run(local) {
  let x = local['digest']();
  x = local.digest();
  const s = smCrypto;
  s['sm2'].doSign(1);
  s.sm2.doSign(1);
  hash.create()['update'](1);
  hash.create().update(1);
}
`)
	pairs := map[string][][2]int{
		moduleInitMethodName: {{4, 5}, {6, 7}},
		"run":                {{11, 12}, {14, 15}, {16, 17}},
	}
	for fnName, lines := range pairs {
		sites, raws := nodeCallSitesByLine(t, graph, fnName)
		for _, pair := range lines {
			indexed, dotted := sites[pair[0]], sites[pair[1]]
			if len(indexed) == 0 || fmtSites(indexed) != fmtSites(dotted) {
				t.Errorf("%s: line %d calls %q, want the dotted line %d's %q", fnName, pair[0], indexed, pair[1], dotted)
			}
		}
		if fnName == moduleInitMethodName {
			for _, line := range []int{8, 9} {
				if len(sites[line]) != 0 {
					t.Errorf("line %d: calls %q, want none for a computed or template index", line, sites[line])
				}
			}
			if got := raws[4]; len(got) != 1 || got[0] != `hash["sha256"]` {
				t.Errorf(`line 4 raw = %q, want hash["sha256"] as written`, got)
			}
			if got := raws[6]; len(got) != 1 || got[0] != `acme['mode'].CTR.create` {
				t.Errorf(`line 6 raw = %q, want acme['mode'].CTR.create as written`, got)
			}
		}
	}
	want := map[int]string{4: "acme-hash.sha256 recv= asg=a", 6: "acme-crypto.mode.CTR.create recv= asg="}
	sites, _ := nodeCallSitesByLine(t, graph, moduleInitMethodName)
	for line, site := range want {
		if got := sites[line]; len(got) != 1 || got[0] != site {
			t.Errorf("line %d: calls %q, want %q", line, got, site)
		}
	}
}

func fmtSites(sites []string) string {
	out := ""
	for _, site := range sites {
		out += site + ";"
	}
	return out
}

// A property read through a string-literal index anywhere in its chain is
// keyed as the dotted read is, as a call through it is.
func TestNodeStringIndexReadKeysAsDottedForm(t *testing.T) {
	t.Parallel()

	graph := buildNodeGraph(t, `import * as acme from 'acme-crypto';
const m = acme['mode'].CTR;
const n = acme.mode.CTR;
`)
	targets := map[int]string{}
	for _, reads := range graph.NodePropertyReads {
		for _, read := range reads {
			targets[read.Line] = read.TargetKey
		}
	}
	if targets[2] == "" || targets[2] != targets[3] || targets[2] != "acme-crypto.mode.CTR" {
		t.Errorf("read targets = %v, want acme-crypto.mode.CTR on lines 2 and 3", targets)
	}
}
