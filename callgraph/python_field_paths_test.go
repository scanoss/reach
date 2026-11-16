// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

const pythonFieldPathsSrc = `import threading
import typing
from typing import cast


class Store:
    def put(self, k):
        return k


class Other:
    def put(self, k):
        return k


class Databases:
    main: Store


class Config:
    def __init__(self):
        self.store = Store()


class HomeServer:
    def __init__(self):
        self.config = Config()

    def get_datastores(self) -> Databases:
        return Databases()


class Handler:
    def __init__(self, hs: HomeServer, thing):
        self.store = hs.get_datastores().main
        self.config = hs.config
        self.config_store = self.config.store
        self.casted = cast(Store, thing)
        self.typing_casted = typing.cast("Store", thing)

    def other(self, obj):
        return obj.store.put(13)

    def go(self):
        self.config.store.put(0)
        self.store.put(1)
        self.config_store.put(2)
        self.casted.put(3)
        return self.typing_casted.put(4)


def local_cast(thing):
    store = cast(Store, thing)
    return store.put(5)


class Sub:
    def __init__(self):
        self.meddled = Store()
        self.agreed = Store()
        self.remote_meddled = Store()

    def go(self):
        self.agreed.put(7)
        self.remote_meddled.put(10)
        return self.meddled.put(6)


class Unrelated:
    def __init__(self):
        self.meddled = Store()

    def go(self):
        return self.meddled.put(8)


def configure(sub: Sub, thread: threading.Thread):
    sub.meddled = Other()
    sub.agreed = Store()
    thread.meddled = Other()


def configure_cast(obj):
    sub = cast(Sub, obj)
    sub.agreed = Store()


class Annotated:
    store: Store

    def __init__(self, thing):
        self.store = thing

    def go(self):
        return self.store.put(11)


class Redeclared:
    store: Store

    def go(self):
        return self.store.put(12)


class RedeclaredSub(Redeclared):
    store: Other


StoreAlias = typing.Dict[str, int]


class Aliased:
    def __init__(self):
        self.aliased = Store()

    def go(self):
        return self.aliased.put(14)


class Linked:
    def __init__(self, other):
        self.next = self.next.next

    def go(self):
        return self.next.put(9)
`

func TestBuilder_PythonFieldPathsAndCasts(t *testing.T) {
	t.Parallel()
	graph := buildTypedPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/m.py":        pythonFieldPathsSrc,
		"app/conf.py": `from app.m import Other, StoreAlias, Sub


def configure(sub: Sub):
    sub.remote_meddled = Other()


def configure_alias(value: StoreAlias):
    value.aliased = Other()
`,
	})
	const put = "probe.app.m.(Store).put"
	for _, c := range []struct {
		name, caller, raw, arg string
		want                   string // "" when the call must stay untyped
	}{
		{"attribute of an annotated parameter", "(Handler).go", "self.config.store.put", "0", put},
		{"attribute of a call's result", "(Handler).go", "self.store.put", "1", put},
		{"attribute of a typed field", "(Handler).go", "self.config_store.put", "2", put},
		{"cast", "(Handler).go", "self.casted.put", "3", put},
		{"typing.cast with a string", "(Handler).go", "self.typing_casted.put", "4", put},
		{"local cast", "local_cast", "store.put", "5", put},
		{"another class written on an annotated receiver", "(Sub).go", "self.meddled.put", "6", ""},
		{"the same class written on an annotated receiver", "(Sub).go", "self.agreed.put", "7", put},
		{"a write on another class's receiver", "(Unrelated).go", "self.meddled.put", "8", put},
		{"a field read off itself", "(Linked).go", "self.next.put", "9", ""},
		{"the field's annotation over a write of unknown value", "(Annotated).go", "self.store.put", "11", put},
		{"two annotations", "(Redeclared).go", "self.store.put", "12", ""},
		{"a field of a parameter named otherwise", "(Handler).other", "obj.store.put", "13", ""},
		{"a write on a receiver annotated with an alias", "(Aliased).go", "self.aliased.put", "14", ""},
		{"another class written on a receiver annotated in another module", "(Sub).go", "self.remote_meddled.put", "10", ""},
	} {
		got, untyped := pythonCallee(t, graph, "probe.app.m."+c.caller, c.raw, c.arg)
		switch {
		case c.want == "" && !untyped:
			t.Errorf("%s: %s typed as %s, want untyped", c.name, c.raw, got)
		case c.want != "" && (untyped || got != c.want):
			t.Errorf("%s: %s = %s (untyped %v), want %s", c.name, c.raw, got, untyped, c.want)
		}
	}
}
