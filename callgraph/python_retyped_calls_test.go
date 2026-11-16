// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"strings"
	"testing"
)

const pythonRetypedCallsSrc = `from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class Base:
    def run(self, data):
        return data


class Fast(Base):
    def step(self):
        return 1


class Cipher:
    def update(self, data):
        return data


def sign(data):
    key = ec.generate_private_key(ec.SECP256R1())
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def seal(key, nonce, data):
    aesgcm = AESGCM(key)
    first = aesgcm.encrypt(nonce, data, associated_data=b"aad")
    return aesgcm.encrypt(nonce, first, None)


def own(data):
    c = Cipher()
    return c.update(data)


def inherited(data):
    fast = Fast()
    return fast.run(data)
`

// buildTypedPythonProject is buildPythonProject with the Python type
// resolver chain (contracts, assignment propagation) the scanner runs.
func buildTypedPythonProject(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	builder := NewBuilderForEcosystem("python", NewPythonParser())
	builder.SetTypeResolver(NewPythonTypeResolverChain())
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: writePythonTree(t, files), ImportPath: "probe"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// pythonResolutionsAt lists the callees of the edge resolutions recorded from
// caller at line.
func pythonResolutionsAt(graph *CallGraph, caller string, line int) []string {
	var out []string
	for key, res := range graph.EdgeResolutions {
		from, to, ok := EdgeResolutionEndpoints(key, res)
		if ok && from == caller && res.CallSite == line {
			out = append(out, to)
		}
	}
	slices.Sort(out)
	return out
}

// A method called on a local whose type a pass learns after the caller index
// (a contract factory's return type, a dependency or own constructor) moves
// its edge to the typed key: the parse-time key keyed by the local's name has
// no caller and no recorded resolution left, the typed key has the call's
// edge, and the call itself keeps its text, receiver and arguments, so the
// fragment export finds it. A local that a class inherits its method for
// links to the base's declaration. (A class that declares no method of its
// own is not yet known to the assignment pass, so its locals stay untyped.)
func TestBuilder_PythonRetypedLocalCallMovesItsEdge(t *testing.T) {
	requireContracts(t)
	t.Parallel()
	graph := buildTypedPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/m.py":        pythonRetypedCallsSrc,
	})
	cases := []struct {
		caller, stale, typed string
		line                 int
		raw, receiver        string
		args                 []string
	}{
		{"probe.app.m.sign", "probe.app.m.(key).sign", "cryptography.hazmat.primitives.asymmetric.ec.(EllipticCurvePrivateKey).sign", 23, "key.sign", "key", []string{"data", "ec.ECDSA(hashes.SHA256())"}},
		{"probe.app.m.seal", "probe.app.m.(aesgcm).encrypt", "cryptography.hazmat.primitives.ciphers.aead.(AESGCM).encrypt", 28, "aesgcm.encrypt", "aesgcm", []string{"nonce", "data", `associated_data=b"aad"`}},
		{"probe.app.m.own", "probe.app.m.(c).update", "probe.app.m.(Cipher).update", 34, "c.update", "c", []string{"data"}},
		{"probe.app.m.inherited", "probe.app.m.(fast).run", "probe.app.m.(Fast).run", 39, "fast.run", "fast", []string{"data"}},
	}
	for _, c := range cases {
		if callers := graph.Callers[c.stale]; slices.Contains(callers, c.caller) {
			t.Errorf("%s keeps the parse-time edge to %s", c.caller, c.stale)
		}
		if !slices.Contains(graph.Callers[c.typed], c.caller) {
			t.Errorf("no edge %s -> %s; callers %v", c.caller, c.typed, graph.Callers[c.typed])
		}
		at := pythonResolutionsAt(graph, c.caller, c.line)
		if slices.Contains(at, c.stale) || !slices.Contains(at, c.typed) {
			t.Errorf("%s line %d: resolutions %v, want %s and not %s", c.caller, c.line, at, c.typed, c.stale)
		}
		var call *FunctionCall
		for i := range graph.Functions[c.caller].Calls {
			if candidate := &graph.Functions[c.caller].Calls[i]; candidate.Line == c.line && candidate.Callee.String() == c.typed {
				call = candidate
			}
		}
		if call == nil {
			t.Errorf("%s: no call at line %d keyed %s", c.caller, c.line, c.typed)
			continue
		}
		if call.Raw != c.raw || call.ReceiverVar != c.receiver || !slices.Equal(call.Arguments, c.args) {
			t.Errorf("%s: call %q receiver %q args %q, want %q %q %q", c.caller, call.Raw, call.ReceiverVar, call.Arguments, c.raw, c.receiver, c.args)
		}
	}
	if !slices.Contains(graph.Callers["probe.app.m.(Base).run"], "probe.app.m.inherited") {
		t.Errorf("fast.run() on a Fast does not reach Base.run; callers %v", graph.Callers["probe.app.m.(Base).run"])
	}
}

// Two calls on one retyped local each keep their own site: dropping the first
// call's parse-time edges does not remove the edge the second call draws, and
// each site has exactly one resolution to the typed key.
func TestBuilder_PythonRetypedLocalCallsKeepOneSiteEach(t *testing.T) {
	requireContracts(t)
	t.Parallel()
	graph := buildTypedPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/m.py":        pythonRetypedCallsSrc,
	})
	const caller, typed = "probe.app.m.seal", "cryptography.hazmat.primitives.ciphers.aead.(AESGCM).encrypt"
	for _, line := range []int{28, 29} {
		at := pythonResolutionsAt(graph, caller, line)
		if n := strings.Count(strings.Join(at, "\n"), typed); n != 1 || len(at) != 1 {
			t.Errorf("line %d: resolutions %v, want exactly one to %s", line, at, typed)
		}
	}
	if !slices.Contains(graph.Callers[typed], caller) {
		t.Errorf("no edge %s -> %s", caller, typed)
	}
}

// A receiver no pass types keeps its parse-time key and its edge.
func TestBuilder_PythonUntypedLocalCallKeepsItsKey(t *testing.T) {
	t.Parallel()
	graph := buildTypedPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/m.py": `def duck(sink, data):
    return sink.write(data)
`,
	})
	if !slices.Contains(graph.Callers["probe.app.m.(sink).write"], "probe.app.m.duck") {
		t.Errorf("sink.write() lost its edge; callers %v", graph.Callers["probe.app.m.(sink).write"])
	}
}

// A call on a local before the local is rebound to a typed value keeps the
// parse-time key it shares with the retyped call after it: moving the second
// call's edge leaves the first call's edge in place.
func TestBuilder_PythonRetypedCallLeavesAnEarlierSameKeyCall(t *testing.T) {
	t.Parallel()
	graph := buildTypedPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/m.py": `class Cipher:
    def update(self, data):
        return data


def f(x):
    x.update(1)
    x = Cipher()
    return x.update(2)
`,
	})
	const caller = "probe.app.m.f"
	if !slices.Contains(graph.Callers["probe.app.m.(x).update"], caller) {
		t.Errorf("x.update(1) before the rebind lost its edge; callers %v", graph.Callers["probe.app.m.(x).update"])
	}
	if got := pythonResolutionsAt(graph, caller, 7); !slices.Equal(got, []string{"probe.app.m.(x).update"}) {
		t.Errorf("line 7 resolutions %v", got)
	}
	if got := pythonResolutionsAt(graph, caller, 9); !slices.Equal(got, []string{"probe.app.m.(Cipher).update"}) {
		t.Errorf("line 9 resolutions %v", got)
	}
}
