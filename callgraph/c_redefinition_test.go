// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func buildCFiles(t *testing.T, ecosystem string, files map[string]string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilderForEcosystem(ecosystem, NewParserForEcosystem(ecosystem)).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// callsByFile lists, per declaration file, the callee names of every
// declaration named name.
func callsByFile(graph *CallGraph, name string) map[string][]string {
	out := map[string][]string{}
	for _, fn := range graph.Functions {
		if fn.ID.Name != name {
			continue
		}
		file := filepath.Base(fn.FilePath)
		for _, c := range fn.Calls {
			out[file] = append(out[file], c.Callee.Name)
		}
		sort.Strings(out[file])
	}
	return out
}

// Two files of one package defining one external name (alternative backends)
// both keep their body, each under a key of its own file's; the first file
// read keeps the package key.
func TestCRedefinitionAcrossFilesKeepsBothBodies(t *testing.T) {
	t.Parallel()

	for _, ecosystem := range []string{ecosystemC, ecosystemCPP} {
		ext := ".c"
		if ecosystem == ecosystemCPP {
			ext = ".cpp"
		}
		graph := buildCFiles(t, ecosystem, map[string]string{
			"backend-zork" + ext:  "int sign_token(int k) { return zork_hmac(k); }\n",
			"backend-plugh" + ext: "int sign_token(int k) { plugh_init(); return plugh_hmac(k); }\n",
		})
		got := callsByFile(graph, "sign_token")
		if len(got["backend-zork"+ext]) != 1 || len(got["backend-plugh"+ext]) != 2 {
			t.Fatalf("%s: calls by file %v, want both bodies", ecosystem, got)
		}
		keys := map[string]bool{}
		for key, fn := range graph.Functions {
			if fn.ID.Name == "sign_token" {
				keys[key] = true
			}
		}
		if !keys["app.sign_token"] || !keys["app/backend-zork"+ext+".sign_token"] {
			t.Errorf("%s: keys %v, want app.sign_token and app/backend-zork%s.sign_token", ecosystem, keys, ext)
		}
	}
}

// #if/#else bodies of one name in one file both keep their calls.
func TestCRedefinitionInOneFileKeepsBothBodies(t *testing.T) {
	t.Parallel()

	src := "#ifdef USE_ZORK\n" +
		"static int pick(void) { return zork_rand(); }\n" +
		"#else\n" +
		"static int pick(void) { return plugh_rand(); }\n" +
		"#endif\n" +
		"#ifdef USE_ZORK\n" +
		"int seed(void) { return zork_seed(); }\n" +
		"#else\n" +
		"int seed(void) { return plugh_seed(); }\n" +
		"#endif\n"
	graph := buildCFiles(t, ecosystemC, map[string]string{"rng.c": src})
	for name, want := range map[string]int{"pick": 2, "seed": 2} {
		n := 0
		for _, fn := range graph.Functions {
			if fn.ID.Name == name {
				n += len(fn.Calls)
			}
		}
		if n != want {
			t.Errorf("%s: %d calls across its declarations, want %d", name, n, want)
		}
	}
}
