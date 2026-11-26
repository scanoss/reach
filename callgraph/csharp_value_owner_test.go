// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
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
    public Box Store { get; set; }
    void Run() {
        Registry.Init(true, null);
        Store.Init(true, null);
        Sm4Engine.Create();
    }
}`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	analysis, err := NewCSharpParser().parseFile(path, "App", nil)
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
	// C# spells a property the way it spells a type, so this is the shape
	// most likely to collide with a dependency's type name.
	if got := alts["App.(Store).Init#2"]; len(got) != 0 {
		t.Errorf("property receiver: alternatives %v, want none", got)
	}
	if got := alts["App.(Sm4Engine).Create#0"]; len(got) == 0 {
		t.Errorf("type receiver: no alternatives, want the usings")
	}
}

// A value member spelled like a type hides the type only where the name reads
// as a value. `new Sm4Engine()` always names a type, and so does a local that
// one constructs: both keep the owners the usings allow.
func TestCSharpTypeNamedLikeAValueKeepsOwnerAlternatives(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "P.cs")
	src := `using Acme.Crypto.Engines;
namespace App;
public static class Service {
    public static Box Sm4Engine { get; set; }
    public static void Run(byte[] m) {
        var engine = new Sm4Engine();
        engine.Init(true, m);
        Sm4Engine.Init(false, m);
    }
}`
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	analysis, err := NewCSharpParser().parseFile(path, "App", nil)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	byLine := map[int][]string{}
	for _, fn := range analysis.Functions {
		for _, call := range fn.Calls {
			byLine[call.Line] = call.OwnerAlternatives
		}
	}
	want := []string{"App.Sm4Engine", "Acme.Crypto.Engines.Sm4Engine"}
	if got := byLine[6]; !slices.Equal(got, want) {
		t.Errorf("constructor: alternatives %q, want %q", got, want)
	}
	if got := byLine[7]; !slices.Equal(got, want) {
		t.Errorf("constructed local: alternatives %q, want %q", got, want)
	}
	// The property reads as a value of its declared type, never as the type
	// its name spells.
	for _, owner := range byLine[8] {
		if strings.HasSuffix(owner, ".Sm4Engine") {
			t.Errorf("property receiver: alternative %q names the type its name spells", owner)
		}
	}
}
