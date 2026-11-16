// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"sort"
	"testing"
)

// Defs and classes inside module-level if / try / with blocks are module
// members, and a class nested in a class body is a class of its own keyed by
// its qualified name. pyjwt guards every asymmetric algorithm with
// `if has_crypto:`; before, none of those methods was in the graph.
func TestPythonParser_MemberDefinitionsInBlocksAndNestedClasses(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import hashlib

try:
    import cryptography
    has_crypto = True
except ImportError:
    has_crypto = False

if has_crypto:
    class RSAAlgorithm:
        def sign(self, msg):
            return hashlib.sha256(msg).digest()
elif False:
    def elif_fn():
        return hashlib.md5()
else:
    def no_crypto():
        return hashlib.sha1()

try:
    def fast():
        return hashlib.blake2b()
except ImportError:
    pass
finally:
    def cleanup():
        return hashlib.sha512()

with open("x") as fh:
    def in_with():
        return hashlib.sha224()

class Outer:
    def run(self):
        return hashlib.sha384()

    if True:
        def guarded(self):
            return hashlib.sha3_256()

    class Inner:
        def go(self):
            return hashlib.sha3_512()

        class Deep:
            def down(self):
                return hashlib.shake_128()

    @decorator
    class Wrapped:
        def wrapped(self):
            return hashlib.shake_256()

def enclosing():
    def closure():
        return hashlib.new("md5")
    class Local:
        def local(self):
            return hashlib.new("sha1")
    return closure
`)
	got := map[string]int{}
	for _, fn := range analysis.Functions {
		got[fn.ID.String()] = len(fn.Calls)
	}
	want := []string{
		"consumer.app.(RSAAlgorithm).sign",
		"consumer.app.elif_fn",
		"consumer.app.no_crypto",
		"consumer.app.fast",
		"consumer.app.cleanup",
		"consumer.app.in_with",
		"consumer.app.(Outer).run",
		"consumer.app.(Outer).guarded",
		"consumer.app.(Outer.Inner).go",
		"consumer.app.(Outer.Inner.Deep).down",
		"consumer.app.(Outer.Wrapped).wrapped",
		"consumer.app.enclosing",
	}
	for _, key := range want {
		calls, ok := got[key]
		if !ok {
			t.Errorf("missing function %s; have %v", key, sortedKeys(got))
			continue
		}
		if calls == 0 {
			t.Errorf("%s has no calls", key)
		}
	}
	for _, key := range []string{"consumer.app.closure", "consumer.app.(Local).local", "consumer.app.(enclosing.Local).local"} {
		if _, ok := got[key]; ok {
			t.Errorf("%s is a function's local, not a member: it must stay in its enclosing function", key)
		}
	}
	if got["consumer.app.enclosing"] < 2 {
		t.Errorf("enclosing keeps its closure's and local class's calls, got %d calls", got["consumer.app.enclosing"])
	}
}

// The methods of a class defined in a module-level block take part in the
// graph: a call into one links to its declaration.
func TestBuilder_PythonClassInBlockIsLinked(t *testing.T) {
	t.Parallel()
	graph := buildPythonProject(t, map[string]string{
		"algos.py": `import hashlib

has_crypto = True
if has_crypto:
    class RSAAlgorithm:
        @staticmethod
        def digest(msg):
            return hashlib.sha256(msg).digest()


def sign(msg):
    return RSAAlgorithm.digest(msg)
`,
	})
	const callee = "probe.algos.(RSAAlgorithm).digest"
	if graph.Functions[callee] == nil {
		t.Fatalf("missing %s; have %v", callee, keysOf(graph.Functions))
	}
	if callers := graph.Callers[callee]; len(callers) != 1 || callers[0] != "probe.algos.sign" {
		t.Errorf("callers of %s = %v, want [probe.algos.sign]", callee, callers)
	}
}

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// A name defined in both branches of a block keeps both bodies' calls: which
// one runs depends on the environment.
func TestBuilder_PythonRedefinitionKeepsBothBodies(t *testing.T) {
	t.Parallel()
	graph := buildPythonProject(t, map[string]string{
		"fast.py": `import hashlib

try:
    import _speedups

    def digest(data):
        return _speedups.digest(data)
except ImportError:
    def digest(data):
        return hashlib.sha256(data).digest()
`,
	})
	fn := graph.Functions["probe.fast.digest"]
	if fn == nil {
		t.Fatalf("missing probe.fast.digest; have %v", keysOf(graph.Functions))
	}
	var callees []string
	for _, call := range fn.Calls {
		callees = append(callees, call.Callee.String())
	}
	sort.Strings(callees)
	want := map[string]bool{"_speedups.digest": false, "hashlib.sha256": false}
	for _, c := range callees {
		if _, ok := want[c]; ok {
			want[c] = true
		}
	}
	for c, seen := range want {
		if !seen {
			t.Errorf("digest lost the call to %s; calls %v", c, callees)
		}
	}
	if fn.StartLine != 9 {
		t.Errorf("digest keeps the last definition's position, got line %d", fn.StartLine)
	}
}
