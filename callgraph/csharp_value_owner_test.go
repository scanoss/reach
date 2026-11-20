// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// A receiver spelled with a field's name is a value: no using can make it
// name a type, and owner alternatives would let the stitch claim an edge into
// whatever dependency declares that name.
func TestCSharpFieldReceiverGetsNoOwnerAlternatives(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "H.cs")
	src := `using Acme.Crypto.Engines;
namespace App;
class H {
    private Box Registry;
    void Run() {
        Registry.Init(true, null);
        Sm4Engine.Create();
    }
}`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	analysis, err := NewCSharpParser().parseFile(path, "App")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	alts := map[string][]string{}
	for _, fn := range analysis.Functions {
		for _, call := range fn.Calls {
			alts[call.Callee.String()] = call.OwnerAlternatives
		}
	}
	if got := alts["App.(Registry).Init#2"]; len(got) != 0 {
		t.Errorf("field receiver: alternatives %v, want none", got)
	}
	if got := alts["App.(Sm4Engine).Create#0"]; len(got) == 0 {
		t.Errorf("type receiver: no alternatives, want the usings")
	}
}
