// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"
)

const pythonAnnotationTypesSrc = `from dataclasses import dataclass
from typing import Any, Optional

import app.remote
from app import remote as rmod
from app.other import Leaf, Remote, helper, make_other, make_remote


class Store:
    def put(self, k):
        return k


class Outer:
    class Inner:
        def put(self, k):
            return k

    def nested(self, inner: Inner):
        return inner.put(1)


def same_module(store: Store):
    return store.put(1)


def optional(store: Optional[Store]):
    return store.put(2)


def union_none(store: Store | None):
    return store.put(3)


def forward(store: "Store"):
    return store.put(4)


def dotted(remote: rmod.Remote):
    return remote.fetch()


def module_path(remote: app.remote.Remote):
    return remote.fetch()


def builtin(data: bytes):
    return data.decode()


def anything(value: Any):
    return value.get(1)


def through_other_module(remote: Remote):
    return remote.fetch()


def inherited(leaf: Leaf):
    return leaf.base()


def returned():
    remote = make_remote()
    return remote.fetch()


async def amake() -> Store:
    return Store()


def coroutine():
    pending = amake()
    return pending.put(5)


def imported_function():
    return helper()


@dataclass
class Point:
    def norm(self):
        return 1


def decorated(point: Point):
    return point.norm()


def subscripted_string(remote: "rmod.Remote[int]"):
    return remote.fetch()


def make_inner() -> Outer.Inner:
    return Outer.Inner()


def nested_return():
    inner = make_inner()
    return inner.put(9)


def returned_import():
    remote = make_other()
    return remote.fetch()
`

func buildPythonAnnotationTypesProject(t *testing.T) *CallGraph {
	t.Helper()
	return buildTypedPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/m.py":        pythonAnnotationTypesSrc,
		"app/remote.py": `class Remote:
    def fetch(self):
        return 1


class Base:
    def base(self):
        return 1


class Leaf(Base):
    pass


def helper():
    return 1


def make_remote() -> Remote:
    return Remote()
`,
		"app/other.py": "from app.remote import Leaf, Remote, helper, make_remote\n\n\ndef make_other() -> Remote:\n    return Remote()\n",
	})
}

func TestBuilder_PythonAnnotatedReceivers(t *testing.T) {
	t.Parallel()
	graph := buildPythonAnnotationTypesProject(t)
	const put = "probe.app.m.(Store).put"
	for _, c := range []struct {
		name, caller, raw, arg string
		want                   string // "" when the call must stay untyped
	}{
		{"class of the module", "same_module", "store.put", "1", put},
		{"Optional", "optional", "store.put", "2", put},
		{"union with None", "union_none", "store.put", "3", put},
		{"string forward reference", "forward", "store.put", "4", put},
		{"nested class from its enclosing class body", "(Outer).nested", "inner.put", "1", "probe.app.m.(Outer.Inner).put"},
		{"attribute of an imported module alias", "dotted", "remote.fetch", "", "probe.app.remote.(Remote).fetch"},
		{"dotted module path", "module_path", "remote.fetch", "", "probe.app.remote.(Remote).fetch"},
		{"builtin class", "builtin", "data.decode", "", "builtins.(bytes).decode"},
		{"typing construct", "anything", "value.get", "1", ""},
		{"class imported through another module", "through_other_module", "remote.fetch", "", "probe.app.other.(Remote).fetch"},
		{"return annotation of a function in another module", "returned", "remote.fetch", "", "probe.app.remote.(Remote).fetch"},
		{"async def not awaited", "coroutine", "pending.put", "5", ""},
		{"decorated class", "decorated", "point.norm", "", "probe.app.m.(Point).norm"},
		{"subscripted string annotation", "subscripted_string", "remote.fetch", "", ""},
		{"nested class as return annotation", "nested_return", "inner.put", "9", ""},
		{"return annotation naming an imported class", "returned_import", "remote.fetch", "", "probe.app.remote.(Remote).fetch"},
	} {
		got, untyped := pythonCallee(t, graph, "probe.app.m."+c.caller, c.raw, c.arg)
		switch {
		case c.want == "" && !untyped:
			t.Errorf("%s: %s typed as %s, want untyped", c.name, c.raw, got)
		case c.want != "" && (untyped || got != c.want):
			t.Errorf("%s: %s = %s (untyped %v), want %s", c.name, c.raw, got, untyped, c.want)
		}
	}
	// A class, method or function named through another module's import
	// links to its declaration, an inherited method through the class's
	// method resolution order.
	for caller, callee := range map[string]string{
		"probe.app.m.through_other_module": "probe.app.remote.(Remote).fetch",
		"probe.app.m.inherited":            "probe.app.remote.(Base).base",
		"probe.app.m.imported_function":    "probe.app.remote.helper",
		"probe.app.m.same_module":          put,
	} {
		if !slices.Contains(graph.Callers[callee], caller) {
			t.Errorf("no edge %s -> %s", caller, callee)
		}
	}
}
