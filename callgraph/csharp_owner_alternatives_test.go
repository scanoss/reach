// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// buildCSharpGraph builds a graph over a directory of named C# sources.
func buildCSharpGraph(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilderForEcosystem(ecosystemCSharp, NewCSharpParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "Acme"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

// A type reached through an on-demand using is keyed by the namespace that
// declares it, not by the caller's own.
func TestCSharpGuessedOwnerSettlesOnTheDeclaringNamespace(t *testing.T) {
	graph := buildCSharpGraph(t, map[string]string{
		"lib.cs": "namespace Acme.Crypto;\nclass Hasher { public static void Go() { } }\n",
		"app.cs": "using Acme.Crypto;\nnamespace Acme.App;\nclass App { void Run() { Hasher.Go(); } }\n",
	})
	if !hasCall(t, graph, "Acme.App.(App).Run#0", "Acme.Crypto.(Hasher).Go#0") {
		t.Errorf("calls = %q, want the call keyed by the declaring namespace", callsOf(t, graph, "Acme.App.(App).Run#0"))
	}
}

// A type the caller's own namespace declares shadows an on-demand using.
func TestCSharpOwnNamespaceWinsOverAUsing(t *testing.T) {
	graph := buildCSharpGraph(t, map[string]string{
		"lib.cs": "namespace Acme.Crypto;\nclass Hasher { public static void Go() { } }\n",
		"app.cs": "using Acme.Crypto;\nnamespace Acme.App;\nclass Hasher { public static void Go() { } }\nclass App { void Run() { Hasher.Go(); } }\n",
	})
	if !hasCall(t, graph, "Acme.App.(App).Run#0", "Acme.App.(Hasher).Go#0") {
		t.Errorf("calls = %q, want the caller's own namespace to win", callsOf(t, graph, "Acme.App.(App).Run#0"))
	}
}

// Two usings that both declare the name settle nothing: the guess stands.
func TestCSharpAmbiguousOwnerIsLeftAlone(t *testing.T) {
	graph := buildCSharpGraph(t, map[string]string{
		"one.cs": "namespace One;\nclass Hasher { public static void Go() { } }\n",
		"two.cs": "namespace Two;\nclass Hasher { public static void Go() { } }\n",
		"app.cs": "using One;\nusing Two;\nnamespace Acme.App;\nclass App { void Run() { Hasher.Go(); } }\n",
	})
	if !hasCall(t, graph, "Acme.App.(App).Run#0", "Acme.App.(Hasher).Go#0") {
		t.Errorf("calls = %q, want the guess left alone", callsOf(t, graph, "Acme.App.(App).Run#0"))
	}
}
