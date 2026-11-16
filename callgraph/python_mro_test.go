// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"
)

// The parser types a call on self or cls with the caller's own class (its
// qualified name for a nested class) and marks it for the method resolution
// order; cls(...) in a classmethod constructs that class. A staticmethod's
// parameter 0 is not a self-reference, and a module function has no class to
// type the call with.
func TestPythonParser_OwnClassCallsTyped(t *testing.T) {
	t.Parallel()
	fns := parsePythonInline(t, `import hashlib


class Signer:
    def __init__(self):
        self.__init__()

    def sign(self, data):
        return self._check(data)

    @classmethod
    def default(cls):
        cls.prepare()
        return cls("HS256")

    @classmethod
    def renamed(klass):
        return klass()

    @staticmethod
    def tool(self):
        return self.run()

    class Nested:
        def go(self):
            return self.step()


def free(self):
    return self.helper()
`)
	cases := []struct {
		caller, method string
		want           FunctionID
		owner          string
	}{
		{"<init>", "<init>", FunctionID{Package: "mypkg.src", Type: "Signer", Name: "<init>"}, "Signer"},
		{"sign", "_check", FunctionID{Package: "mypkg.src", Type: "Signer", Name: "_check"}, "Signer"},
		{"default", "prepare", FunctionID{Package: "mypkg.src", Type: "Signer", Name: "prepare"}, "Signer"},
		{"default", "<init>", FunctionID{Package: "mypkg.src", Type: "Signer", Name: "<init>"}, "Signer"},
		{"renamed", "<init>", FunctionID{Package: "mypkg.src", Type: "Signer", Name: "<init>"}, "Signer"},
		{"tool", "run", FunctionID{Package: "mypkg.src", Type: "self", Name: "run"}, ""},
		{"go", "step", FunctionID{Package: "mypkg.src", Type: "Signer.Nested", Name: "step"}, "Signer.Nested"},
		{"free", "helper", FunctionID{Package: "mypkg.src", Name: "helper"}, ""},
	}
	for _, c := range cases {
		fn := findPythonFuncByName(fns, c.caller)
		if fn == nil {
			t.Fatalf("function %s not found", c.caller)
		}
		call := findPythonCallByMethod(fn, c.method)
		if call == nil {
			t.Fatalf("%s: call %s not found", c.caller, c.method)
		}
		if call.Callee != c.want || call.pythonOwner != c.owner {
			t.Errorf("%s: %s callee %s owner %q, want %s owner %q", c.caller, c.method, call.Callee, call.pythonOwner, c.want, c.owner)
		}
	}
}

// A self / cls / super() call is an internal edge to the declaration the
// method resolution order gives: the caller's class, else its bases in C3
// order (a diamond reaches the right branch's override before the shared
// base), across modules of the project; super() skips the caller's class.
func TestBuilder_PythonOwnClassCallsFollowTheMRO(t *testing.T) {
	t.Parallel()
	graph := buildPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/base.py": `class A:
    def m(self):
        return 1

    def own(self):
        return 2

    def __init__(self, k):
        self.k = k
`,
		"app/diamond.py": `from app.base import A


class B(A):
    pass


class C(A):
    def m(self):
        return super().m()


class D(B, C):
    def own(self):
        return 3

    def run(self):
        self.own()
        self.m()
        return super().own()

    @classmethod
    def make(cls):
        return cls(1)


class Failure(ValueError):
    def __init__(self, msg):
        super().__init__(msg)

    def missing(self):
        return self.not_declared()
`,
	})
	edges := []struct{ caller, callee string }{
		{"probe.app.diamond.(D).run", "probe.app.diamond.(D).own"},
		{"probe.app.diamond.(D).run", "probe.app.diamond.(C).m"},
		{"probe.app.diamond.(D).run", "probe.app.base.(A).own"},
		{"probe.app.diamond.(C).m", "probe.app.base.(A).m"},
		{"probe.app.diamond.(D).make", "probe.app.base.(A).<init>"},
	}
	for _, e := range edges {
		if !slices.Contains(graph.Callers[e.callee], e.caller) {
			t.Errorf("no edge %s -> %s; callers %v", e.caller, e.callee, graph.Callers[e.callee])
		}
	}
	if slices.Contains(graph.Callers["probe.app.base.(A).m"], "probe.app.diamond.(D).run") {
		t.Errorf("D.run's self.m() reaches C.m first in D's MRO (D, B, C, A), not A.m")
	}
	// Outside the graph: super() names the first base, self the own class.
	failure := graph.Functions["probe.app.diamond.(Failure).<init>"]
	if failure == nil || len(failure.Calls) != 1 || failure.Calls[0].Callee.String() != "builtins.(ValueError).<init>" {
		t.Errorf("Failure.__init__'s super().__init__ callee, want builtins.(ValueError).<init>; decl %+v", failure)
	}
	missing := graph.Functions["probe.app.diamond.(Failure).missing"]
	if missing == nil || len(missing.Calls) != 1 || missing.Calls[0].Callee.String() != "probe.app.diamond.(Failure).not_declared" {
		t.Errorf("an undeclared self method keeps the caller's class; decl %+v", missing)
	}
}

// Instantiating a class links to the nearest __init__ of its method
// resolution order, whether the class is named in its module, through an
// imported module, nested in another class or typed by a from-import; the
// call keeps its own spelling, the one contracts key on.
func TestBuilder_PythonInstantiationLinksTheConstructor(t *testing.T) {
	t.Parallel()
	graph := buildPythonProject(t, map[string]string{
		"app/__init__.py": "from app.keys import Leaf\n",
		"app/keys.py": `class Base:
    def __init__(self, k):
        self.k = k


class Leaf(Base):
    pass


class Outer:
    class Inner(Base):
        pass


def local():
    return Leaf(1)


def nested():
    return Outer.Inner(2)
`,
		"app/use.py": `import app
from app import keys
from app.keys import Leaf


def via_module():
    return keys.Leaf(3)


def via_from_import():
    return Leaf(4)


def via_reexport():
    return app.Leaf(5)
`,
		"app/reexported.py": `from app import Leaf


def via_reexported_type():
    return Leaf(6)
`,
	})
	const ctor = "probe.app.keys.(Base).<init>"
	for _, caller := range []string{"probe.app.keys.local", "probe.app.keys.nested", "probe.app.use.via_module", "probe.app.use.via_from_import", "probe.app.use.via_reexport", "probe.app.reexported.via_reexported_type"} {
		if !slices.Contains(graph.Callers[ctor], caller) {
			t.Errorf("no edge %s -> %s; callers %v", caller, ctor, graph.Callers[ctor])
		}
	}
	if !slices.Contains(graph.Callers["probe.app.keys.Leaf"], "probe.app.keys.local") {
		t.Errorf("Leaf(1) keeps its module spelling probe.app.keys.Leaf; callers %v", graph.Callers["probe.app.keys.Leaf"])
	}
}

// A method called on a class object imported from another module (a
// classmethod or staticmethod, `Signer.default()`) links to the declaration
// of the class's method resolution order, also through a re-export; the call
// keeps its spelling.
func TestBuilder_PythonImportedClassMemberCallLinks(t *testing.T) {
	t.Parallel()
	graph := buildPythonProject(t, map[string]string{
		"app/__init__.py": "from app.signer import Signer\n",
		"app/base.py": `class Base:
    @classmethod
    def default(cls):
        return cls()
`,
		"app/signer.py": `from app.base import Base


class Signer(Base):
    @staticmethod
    def tool():
        return 1
`,
		"app/client.py": `import app
from app import signer
from app.signer import Signer


def from_import():
    return Signer.default()


def via_module():
    return signer.Signer.tool()


def via_reexport():
    return app.Signer.default()
`,
	})
	edges := []struct{ caller, callee string }{
		{"probe.app.client.from_import", "probe.app.base.(Base).default"},
		{"probe.app.client.via_module", "probe.app.signer.(Signer).tool"},
		{"probe.app.client.via_reexport", "probe.app.base.(Base).default"},
	}
	for _, e := range edges {
		if !slices.Contains(graph.Callers[e.callee], e.caller) {
			t.Errorf("no edge %s -> %s; callers %v", e.caller, e.callee, graph.Callers[e.callee])
		}
	}
	if !slices.Contains(graph.Callers["probe.app.signer.Signer.default"], "probe.app.client.from_import") {
		t.Errorf("Signer.default() keeps its spelling; callers %v", graph.Callers["probe.app.signer.Signer.default"])
	}
}
