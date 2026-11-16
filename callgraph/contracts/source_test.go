// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package contracts

import (
	"sync"
	"testing"
	"testing/fstest"
)

const sourceTestKB = `schema_version: "2"
ecosystem: java
library:
  name: source-test
contracts:
  - method: javax.crypto.Cipher.getInstance
    arity: 1
    return:
      type: javax.crypto.Cipher
      confidence: high
`

// Every call graph build loads its ecosystem's KB. Re-parsing the YAML on
// each build dominated scan and test time, so ForEcosystem parses each
// ecosystem of the installed source once and hands every caller the same KB.
func TestForEcosystemParsesEachEcosystemOnce(t *testing.T) {
	SetSource(fstest.MapFS{"java/source-test.yaml": {Data: []byte(sourceTestKB)}})
	t.Cleanup(func() { SetSource(nil) })
	for _, eco := range []string{"java", "python", "unknown-ecosystem"} {
		t.Run(eco, func(t *testing.T) {
			const callers = 16
			got := make([]*KnowledgeBase, callers)
			var wg sync.WaitGroup
			for i := range callers {
				wg.Go(func() {
					kb, err := ForEcosystem(eco)
					if err != nil {
						t.Errorf("ForEcosystem(%q): %v", eco, err)
					}
					got[i] = kb
				})
			}
			wg.Wait()
			for i, kb := range got {
				if kb == nil {
					t.Fatalf("caller %d got a nil KB", i)
				}
				if kb != got[0] {
					t.Fatalf("caller %d got a separately parsed KB; want one shared KB per ecosystem", i)
				}
			}
		})
	}
	if kb, _ := ForEcosystem("java"); len(kb.ContractsFor("javax.crypto.Cipher.getInstance", 1)) != 1 {
		t.Fatal("java KB from the installed source lacks its contract")
	}
}

// The engine ships no knowledge: with no source installed every ecosystem
// loads as an empty KB, and installing a source replaces the parsed KBs.
func TestSetSourceReplacesParsedKBs(t *testing.T) {
	SetSource(nil)
	t.Cleanup(func() { SetSource(nil) })
	empty, err := ForEcosystem("java")
	if err != nil || len(empty.Contracts) != 0 {
		t.Fatalf("no source: got %d contracts, err %v; want an empty KB", len(empty.Contracts), err)
	}
	SetSource(fstest.MapFS{"java/source-test.yaml": {Data: []byte(sourceTestKB)}})
	kb, err := ForEcosystem("java")
	if err != nil || len(kb.Contracts) != 1 {
		t.Fatalf("installed source: got %d contracts, err %v; want 1", len(kb.Contracts), err)
	}
}
