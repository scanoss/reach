// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/callgraph/contracts"
)

// buildNodeFilesWithKB builds the Node files with kb in place of the
// installed source's KB (none when kb is nil).
func buildNodeFilesWithKB(t *testing.T, files map[string]string, kb *contracts.KnowledgeBase) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	b := NewBuilderForEcosystem("node", NewNodeParser())
	b.kb = kb
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// A call or read made directly on `new X(...)` is keyed as the same call or
// read on a variable the instance is assigned to: through the KB contract of
// an imported class's constructor when a KB is installed (contracted method
// or not), caller-local without one, and as the declared class for a project
// class either way.
func TestNodeMemberOnNewKeyedAsOnVariable(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: node
library:
  name: acme-test
contracts:
  - method: acme-pki.Cert.<init>
    arity: 1
    return: {type: acme-pki.Cert, confidence: high}
  - method: acme-pki.Cert.verify
    arity: 0
    return: {type: boolean, confidence: high}
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	files := map[string]string{
		"cert.js": "export class Pcert { verify() {} }\n",
		"app.js": `import * as acme from 'acme-pki';
import { Cert } from 'acme-pki';
import * as certs from './cert';
import { Pcert } from './cert';
class Local { verify() { return 1; } }
function run(p) {
  const a = new acme.Cert(p);
  a.verify(); a.renew(); const a1 = a.fingerprint;
  new acme.Cert(p).verify(); new acme.Cert(p).renew(); const a2 = new acme.Cert(p).fingerprint;
  const b = new Cert(p);
  b.verify(); b.renew(); const b1 = b.fingerprint;
  new Cert(p).verify(); new Cert(p).renew(); const b2 = new Cert(p).fingerprint;
  const l = new Local();
  l.verify(); l.renew(); const l1 = l.fingerprint;
  new Local().verify(); new Local().renew(); const l2 = new Local().fingerprint;
  const q = new Pcert();
  q.verify(); q.renew(); const q1 = q.fingerprint;
  new Pcert().verify(); new Pcert().renew(); const q2 = new Pcert().fingerprint;
  const n = new certs.Pcert();
  n.verify(); n.renew(); const n1 = n.fingerprint;
  new certs.Pcert().verify(); new certs.Pcert().renew(); const n2 = new certs.Pcert().fingerprint;
}
`,
	}
	// Each variable-form line and the direct-form line after it.
	pairs := map[string][2]int{"acme.Cert": {8, 9}, "Cert": {11, 12}, "Local": {14, 15}, "Pcert": {17, 18}, "certs.Pcert": {20, 21}}
	for _, tc := range []struct {
		name string
		kb   *contracts.KnowledgeBase
		want map[string]string
	}{
		{name: "no KB", want: map[string]string{
			"acme.Cert": "app.verify app.renew app.fingerprint", "Cert": "app.verify app.renew app.fingerprint",
			"Local":       "app.(Local).verify app.(Local).renew app.(Local).fingerprint",
			"Pcert":       "cert.(Pcert).verify cert.(Pcert).renew cert.(Pcert).fingerprint",
			"certs.Pcert": "cert.(Pcert).verify cert.(Pcert).renew cert.(Pcert).fingerprint",
		}},
		{name: "test KB", kb: kb, want: map[string]string{
			"acme.Cert":   "acme-pki.(Cert).verify acme-pki.(Cert).renew acme-pki.(Cert).fingerprint",
			"Cert":        "acme-pki.(Cert).verify acme-pki.(Cert).renew acme-pki.(Cert).fingerprint",
			"Local":       "app.(Local).verify app.(Local).renew app.(Local).fingerprint",
			"Pcert":       "cert.(Pcert).verify cert.(Pcert).renew cert.(Pcert).fingerprint",
			"certs.Pcert": "cert.(Pcert).verify cert.(Pcert).renew cert.(Pcert).fingerprint",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildNodeFilesWithKB(t, files, tc.kb)
			keys := nodeLineMemberKeys(graph, "run")
			for class, lines := range pairs {
				variable, direct := keys[lines[0]], keys[lines[1]]
				if variable != direct {
					t.Errorf("%s: direct form %q, variable form %q", class, direct, variable)
				}
				if variable != tc.want[class] {
					t.Errorf("%s: keys %q, want %q", class, variable, tc.want[class])
				}
			}
		})
	}
}

// nodeLineMemberKeys lists, per line of fnName, the keys of its verify and
// renew calls and its fingerprint read, in that order.
func nodeLineMemberKeys(graph *CallGraph, fnName string) map[int]string {
	out := map[int]string{}
	for _, fn := range graph.Functions {
		if fn.ID.Name != fnName {
			continue
		}
		byName := map[int]map[string]string{}
		add := func(line int, name, key string) {
			if byName[line] == nil {
				byName[line] = map[string]string{}
			}
			byName[line][name] = key
		}
		for _, call := range fn.Calls {
			add(call.Line, call.Callee.Name, call.Callee.String())
		}
		for _, reads := range graph.NodePropertyReads {
			for _, read := range reads {
				if read.CallerKey == fn.ID.String() {
					add(read.Line, read.MethodName, read.TargetKey)
				}
			}
		}
		for line, keys := range byName {
			out[line] = fmt.Sprintf("%s %s %s", keys["verify"], keys["renew"], keys["fingerprint"])
		}
	}
	return out
}
