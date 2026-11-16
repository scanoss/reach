// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func parseInlinePythonFiles(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	for rel, src := range files {
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilder(NewPythonParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

func stripSourceLocations(nodes []SourceNode) []SourceNode {
	for i := range nodes {
		nodes[i].Location = nil
		nodes[i].SourceNodes = stripSourceLocations(nodes[i].SourceNodes)
	}
	return nodes
}

const pythonAlgorithmSourcesModule = `import hashlib

ALG = "sha256"
TWICE = "sha256"
TWICE = "md5"

def by_param(data, alg):
    return hashlib.new(alg, data)

def by_local(data):
    a = "sha1"
    return hashlib.new(a, data)

def by_module_constant(data):
    return hashlib.new(ALG, data)

def by_rebound_param(alg, data):
    alg = alg.lower()
    return hashlib.new(alg, data)

def by_augmented_param(alg, data):
    alg += "-x"
    return hashlib.new(alg, data)

def by_poisoned_local(data, flag):
    a = "sha1"
    if flag:
        a = "md5"
    return hashlib.new(a, data)

def by_rebound_module_constant(data):
    return hashlib.new(TWICE, data)

def by_fstring_local(data, n):
    a = f"sha{n}"
    return hashlib.new(a, data)

def by_bytes_local(data):
    a = b"sha1"
    return hashlib.new(a, data)

def by_keyword_only(*parts, alg):
    return hashlib.new(alg)

def by_keyword_only_after_typed_splat(*parts: str, alg: str = "sha256"):
    return hashlib.new(alg)

def by_keyword_only_after_typed_kwargs(data, **kw: str):
    return hashlib.new(data)

class Hasher:
    def by_method_param(self, alg):
        return hashlib.new(alg)

    @classmethod
    def by_classmethod_param(cls, data, alg):
        return hashlib.new(alg)

    @staticmethod
    def by_staticmethod_param(data, alg):
        return hashlib.new(alg)

    def by_receiver(self):
        return hashlib.new(self)

    def by_method_keyword_only(self, *, alg="sha1"):
        return hashlib.new(alg)

def by_keyword_only_after_star(data, *, alg: str, **rest):
    return hashlib.new(alg)

def by_kwargs(data, **alg):
    return hashlib.new(alg)

def by_splat(*alg):
    return hashlib.new(alg)

def by_rebound_keyword_only(*, alg):
    alg = alg.lower()
    return hashlib.new(alg)

def by_param_or_literal(alg, data):
    if not alg:
        alg = "sha1"
    return hashlib.new(alg, data)

def by_int_or_literal(data, flag):
    a = 1
    if flag:
        a = "sha1"
    return hashlib.new(a, data)

def by_literal_or_call(data, flag):
    a = "sha1"
    if flag:
        a = pick()
    a = "sha1"
    return hashlib.new(a, data)
`

func TestPythonParser_AlgorithmArgumentSources(t *testing.T) {
	graph := parseInlinePythonFiles(t, map[string]string{"app/hasher.py": pythonAlgorithmSourcesModule})

	value := func(text string) []SourceNode {
		return []SourceNode{{Type: "VALUE", Value: text}}
	}
	tests := []struct {
		function string
		want     []SourceNode
	}{
		{"by_param", []SourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: 1}}},
		{"by_local", []SourceNode{{Type: "VARIABLE", Name: "a", SourceNodes: value(`"sha1"`)}}},
		{"by_module_constant", []SourceNode{{Type: "VARIABLE", Name: "ALG", SourceNodes: value(`"sha256"`)}}},
		{"by_rebound_param", nil},
		{"by_augmented_param", nil},
		// Written more than once: the string literals it may hold (E1.3a),
		// exhaustive when every binding is one.
		{"by_poisoned_local", []SourceNode{{Type: "VARIABLE", Name: "a", MayValues: []string{`"sha1"`, `"md5"`}, MayValuesExhaustive: true}}},
		{"by_rebound_module_constant", []SourceNode{{Type: "VARIABLE", Name: "TWICE", MayValues: []string{`"sha256"`, `"md5"`}, MayValuesExhaustive: true}}},
		{"by_param_or_literal", []SourceNode{{Type: "VARIABLE", Name: "alg", MayValues: []string{`"sha1"`}}}},
		{"by_int_or_literal", []SourceNode{{Type: "VARIABLE", Name: "a", MayValues: []string{`"sha1"`}}}},
		{"by_literal_or_call", []SourceNode{{Type: "VARIABLE", Name: "a", MayValues: []string{`"sha1"`}}}},
		{"by_fstring_local", nil},
		{"by_bytes_local", nil},
		// A keyword-only parameter is the caller's argument of that name: no
		// position (-1).
		{"by_keyword_only", []SourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: -1}}},
		{"by_keyword_only_after_typed_splat", []SourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: -1}}},
		{"by_keyword_only_after_star", []SourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: -1}}},
		{"by_rebound_keyword_only", nil},
		{"by_keyword_only_after_typed_kwargs", []SourceNode{{Type: "PARAMETER", Name: "data", ParameterIndex: 0}}},
		{"by_kwargs", nil},
		{"by_splat", nil},
		// A method's parameters count from the one after self or cls, as the
		// caller writes its arguments; a static method's from the first.
		{"by_method_param", []SourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: 0}}},
		{"by_classmethod_param", []SourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: 1}}},
		{"by_staticmethod_param", []SourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: 1}}},
		{"by_receiver", nil},
		{"by_method_keyword_only", []SourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: -1}}},
	}
	for _, tt := range tests {
		t.Run(tt.function, func(t *testing.T) {
			var call *FunctionCall
			for _, fn := range graph.Functions {
				if fn.ID.Name == tt.function {
					call = findPythonCallByMethod(fn, "new")
				}
			}
			if call == nil {
				t.Fatalf("hashlib.new call in %s not found", tt.function)
			}
			if len(call.ArgumentSources) == 0 {
				t.Fatalf("ArgumentSources = nil, want one entry per argument")
			}
			if got := stripSourceLocations(call.ArgumentSources[0]); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ArgumentSources[0] = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestPythonParser_ParameterSourceLocation(t *testing.T) {
	graph := parseInlinePythonFiles(t, map[string]string{"app/hasher.py": pythonAlgorithmSourcesModule})
	for _, fn := range graph.Functions {
		if fn.ID.Name != "by_param" {
			continue
		}
		node := findPythonCallByMethod(fn, "new").ArgumentSources[0][0]
		if node.Location == nil || filepath.Base(node.Location.FilePath) != "hasher.py" || node.Location.Line != 8 {
			t.Fatalf("PARAMETER location = %+v, want hasher.py:8", node.Location)
		}
		return
	}
	t.Fatal("by_param not found")
}

// A module that binds names dynamically (exec) gives none of its names a
// value, not even the literals it may hold.
func TestPythonParser_MayValuesWithheldUnderDynamicBinding(t *testing.T) {
	graph := parseInlinePythonFiles(t, map[string]string{"app/dyn.py": `import hashlib

ALG = "sha256"
ALG = "md5"
exec("ALG = 'sha1'")

def use(data):
    return hashlib.new(ALG, data)
`})
	for _, fn := range graph.Functions {
		if fn.ID.Name != "use" {
			continue
		}
		call := findPythonCallByMethod(fn, "new")
		if call == nil || len(call.ArgumentSources) == 0 {
			t.Fatal("hashlib.new call not found")
		}
		if got := call.ArgumentSources[0]; got != nil {
			t.Errorf("ArgumentSources[0] = %+v, want none", got)
		}
		return
	}
	t.Fatal("use not found")
}
