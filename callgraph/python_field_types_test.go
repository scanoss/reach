// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

const pythonFieldTypesSrc = `import threading
from typing import Optional

from cryptography.hazmat.primitives.asymmetric import ec

from app import remote as app_remote
from app.other import Remote, RemoteBase
from app.remote import Alias


class Store:
    def put(self, k):
        return k


class Other:
    def put(self, k):
        return k


def make_store() -> Store:
    return Store()


async def open_store() -> Store:
    return Store()


class Built:
    def __init__(self):
        self.store = Store()

    def go(self):
        return self.store.put(1)


class Param:
    def __init__(self, store: Store):
        self.store = store

    def go(self):
        return self.store.put(1)


class Factory:
    def __init__(self):
        self.store = make_store()

    def go(self):
        return self.store.put(1)


class Declared:
    store: Store
    maybe: Optional[Store] = None

    def go(self):
        self.maybe.put(2)
        return self.store.put(1)


class Prop:
    @property
    def store(self) -> Store:
        return Store()

    def go(self):
        return self.store.put(1)


class Child(Built):
    def other(self):
        return self.store.put(3)


class Twice:
    def __init__(self):
        self.store = Store()

    def go(self):
        return self.store.put(1)


class Rebound(Twice):
    def __init__(self):
        self.store = Other()


class NoneOr:
    def __init__(self, flag):
        self.store = Store() if flag else None
        self.either = Store() if flag else Other()

    def go(self):
        self.either.put(2)
        return self.store.put(1)


class Literal:
    def __init__(self):
        self.store = Store()
        self.store = 3

    def go(self):
        return self.store.put(1)


class Dynamic:
    def __init__(self, name):
        self.store = Store()
        setattr(self, name, None)

    def go(self):
        return self.store.put(1)


class Threaded(threading.Thread):
    def __init__(self):
        self.store = Store()

    def go(self):
        return self.store.put(1)


class Shadowed:
    def __init__(self):
        self.store = Store()

    def go(self):
        class Local:
            def run(self):
                return self.store.put(9)
        return self.store.put(1)


class Async:
    def __init__(self):
        self.pending = open_store()

    async def start(self):
        self.store = await open_store()

    def go(self):
        self.pending.put(2)
        return self.store.put(1)


class Contracted:
    def __init__(self):
        self.key = ec.generate_private_key(ec.SECP256R1())

    def go(self, data):
        return self.key.sign(data, None)


class Static:
    def __init__(self):
        self.store = Store()

    @staticmethod
    def go(self):
        return self.store.put(1)


class Imported:
    def __init__(self):
        self.remote = Remote()

    def go(self):
        return self.remote.fetch()


class Meddled:
    def __init__(self):
        self.meddled = Store()

    def go(self):
        return self.meddled.put(1)


def meddle(obj):
    obj.meddled = None


class Maker:
    def build(self) -> Store:
        return Store()


class Chained:
    def __init__(self):
        self.maker = Maker()

    def setup(self):
        self.built = self.maker.build()

    def go(self):
        made = self.maker.build()
        made.put(5)
        return self.built.put(6)


class Setter:
    def __init__(self):
        self._store = Store()

    @property
    def store(self) -> Store:
        return self._store

    @store.setter
    def store(self, value):
        self._store = value

    def go(self):
        return self.store.put(1)


class Closure:
    def __init__(self):
        self.store = Store()

    def go(self):
        def inner(self):
            return self.store.put(7)
        return inner


class Lit:
    def __init__(self):
        self.named = Store()

    def go(self):
        return self.named.put(1)


def name_it(obj):
    setattr(obj, "named", None)


class DictOpen:
    def __init__(self, **kw):
        self.store = Store()
        self.__dict__.update(kw)

    def go(self):
        return self.store.put(1)


class VarsOpen:
    def __init__(self, **kw):
        self.store = Store()
        vars(self).update(kw)

    def go(self):
        return self.store.put(1)


class Hooked:
    def __init__(self):
        self.store = Store()

    def __setattr__(self, name, value):
        super().__setattr__(name, value)

    def go(self):
        return self.store.put(1)


class RemoteParam:
    def __init__(self, remote: Remote):
        self.remote = remote

    def go(self):
        return self.remote.fetch()


class AwaitCtor:
    async def start(self):
        self.store = await Store()

    def go(self):
        return self.store.put(1)


class AliasField:
    def __init__(self, value: Alias):
        self.value = value

    def go(self):
        return self.value.get(1)


class ViaOther(RemoteBase):
    def __init__(self):
        self.store = Store()

    def go(self):
        return self.store.put(1)


class ShadowParam:
    def __init__(self, make_store):
        self.store = make_store()

    def go(self):
        return self.store.put(1)


class StaticWriter:
    @staticmethod
    def reset(self):
        self.victim = None


class Victim:
    def __init__(self):
        self.victim = Store()

    def go(self):
        return self.victim.put(1)


class DottedAnnotation:
    remote: app_remote.Remote

    def go(self):
        return self.remote.fetch()


class ModuleAnnotation:
    remote: app_remote

    def go(self):
        return self.remote.fetch()


class OrDefault:
    def __init__(self, store: Optional[Store] = None):
        self.store = store or Store()

    def go(self):
        return self.store.put(1)
`

func buildPythonFieldTypesProject(t *testing.T) *CallGraph {
	t.Helper()
	return buildTypedPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/m.py":        pythonFieldTypesSrc,
		"app/remote.py": `from typing import Dict

Alias = Dict[str, int]


class RemoteBase:
    def base(self):
        return 1


class Remote:
    def fetch(self):
        return 1
`,
		"app/other.py": "from app.remote import Alias, Remote, RemoteBase\n",
	})
}

// pythonCallee returns the callee key of the call caller makes as raw (the
// callee expression's text) with first argument arg, and whether nothing
// typed it.
func pythonCallee(t *testing.T, graph *CallGraph, caller, raw, arg string) (string, bool) {
	t.Helper()
	fn := graph.Functions[caller]
	if fn == nil {
		t.Fatalf("no function %s", caller)
	}
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.Raw == raw && (arg == "" && len(call.Arguments) == 0 || len(call.Arguments) > 0 && call.Arguments[0] == arg) {
			return call.Callee.String(), PythonCallUntyped(graph, call)
		}
	}
	t.Fatalf("%s makes no call %s(%s, ..)", caller, raw, arg)
	return "", false
}

func TestBuilder_PythonSelfFieldReceivers(t *testing.T) {
	requireContracts(t)
	t.Parallel()
	graph := buildPythonFieldTypesProject(t)
	const put = "probe.app.m.(Store).put"
	for _, c := range []struct {
		name, caller, raw, arg string
		want                   string // "" when the call must stay untyped
	}{
		{"constructed in __init__", "Built", "self.store.put", "1", put},
		{"annotated parameter stored as is", "Param", "self.store.put", "1", put},
		{"function annotated to return the class", "Factory", "self.store.put", "1", put},
		{"class-level annotation", "Declared", "self.store.put", "1", put},
		{"Optional class-level annotation", "Declared", "self.maybe.put", "2", put},
		{"property return annotation", "Prop", "self.store.put", "1", put},
		{"field inherited from the base", "Child.other", "self.store.put", "3", put},
		{"a subclass writes another class", "Twice", "self.store.put", "1", ""},
		{"None and a class", "NoneOr", "self.store.put", "1", put},
		{"two classes", "NoneOr", "self.either.put", "2", ""},
		{"a write of unknown value", "Literal", "self.store.put", "1", ""},
		{"attributes set by computed name", "Dynamic", "self.store.put", "1", ""},
		{"base outside the graph", "Threaded", "self.store.put", "1", ""},
		{"self rebound by a local class", "Shadowed", "self.store.put", "9", ""},
		{"self of the method", "Shadowed", "self.store.put", "1", put},
		{"awaited async factory", "Async", "self.store.put", "1", put},
		{"async factory not awaited", "Async", "self.pending.put", "2", ""},
		{"contract return type", "Contracted", "self.key.sign", "data", "cryptography.hazmat.primitives.asymmetric.ec.(EllipticCurvePrivateKey).sign"},
		{"staticmethod parameter named self", "Static", "self.store.put", "1", ""},
		{"class imported through another module", "Imported", "self.remote.fetch", "", "probe.app.remote.(Remote).fetch"},
		{"field written on another object", "Meddled", "self.meddled.put", "1", ""},
		{"field assigned from a call on a typed field", "Chained", "self.built.put", "6", put},
		{"local assigned from a call on a typed field", "Chained", "made.put", "5", put},
		{"property with a setter", "Setter", "self.store.put", "1", put},
		{"self rebound by a closure parameter", "Closure", "self.store.put", "7", ""},
		{"setattr with the field's name on another object", "Lit", "self.named.put", "1", ""},
		{"instance __dict__", "DictOpen", "self.store.put", "1", ""},
		{"vars(self)", "VarsOpen", "self.store.put", "1", ""},
		{"__setattr__ hook", "Hooked", "self.store.put", "1", ""},
		{"annotation naming a class through another module", "RemoteParam", "self.remote.fetch", "", "probe.app.remote.(Remote).fetch"},
		{"awaited call of no async function", "AwaitCtor", "self.store.put", "1", ""},
		{"annotation naming a type alias", "AliasField", "self.value.get", "1", ""},
		{"base named through another module", "ViaOther", "self.store.put", "1", put},
		{"parameter shadowing a module function", "ShadowParam", "self.store.put", "1", ""},
		{"write on a staticmethod parameter named self", "Victim", "self.victim.put", "1", ""},
		{"annotation naming a module", "ModuleAnnotation", "self.remote.fetch", "", ""},
		{"dotted annotation", "DottedAnnotation", "self.remote.fetch", "", "probe.app.remote.(Remote).fetch"},
		{"parameter or default", "OrDefault", "self.store.put", "1", put},
	} {
		caller := "probe.app.m.(" + c.caller + ").go"
		if class, method, ok := strings.Cut(c.caller, "."); ok {
			caller = "probe.app.m.(" + class + ")." + method
		}
		got, untyped := pythonCallee(t, graph, caller, c.raw, c.arg)
		switch {
		case c.want == "" && !untyped:
			t.Errorf("%s: %s typed as %s, want untyped", c.name, c.raw, got)
		case c.want != "" && (untyped || got != c.want):
			t.Errorf("%s: %s = %s (untyped %v), want %s", c.name, c.raw, got, untyped, c.want)
		}
	}
	// A typed call is an edge to the method; an untyped one is not.
	for caller, want := range map[string]bool{"probe.app.m.(Child).other": true, "probe.app.m.(Twice).go": false} {
		if got := slices.Contains(graph.Callers[put], caller); got != want {
			t.Errorf("edge %s -> %s = %v, want %v", caller, put, got, want)
		}
	}
}

// A module statement that writes a field on a module-level object (pyjwt's
// `_jwt_global_obj._jws = _jws_global_obj`) is a write on the instances of
// the object's class: it keeps the field typed when it agrees with the
// class's own writes, and leaves it untyped when it does not, or when the
// object's class is not known (then no class's field of that name is typed).
func TestBuilder_PythonFieldWrittenOnModuleObject(t *testing.T) {
	t.Parallel()
	classes := []struct {
		name, field, write, want string
	}{
		{"Agrees", "_agrees", "_agrees_obj = Agrees()\n_agrees_obj._agrees = _jws_global_obj", "encode"},
		{"Constructed", "_constructed", "_constructed_obj = Constructed()\n_constructed_obj._constructed = JWS()", "encode"},
		{"Imported", "_imported", "_imported_obj._imported = _jws_global_obj", "encode"},
		{"Differs", "_differs", "_differs_obj = Differs()\n_differs_obj._differs = _other_obj", ""},
		{"Unknown", "_unknown", "_unknown_obj = Unknown()\n_unknown_obj._unknown = 1", ""},
		{"Rebound", "_rebound", "_rebound_obj = Rebound()\n_rebound_obj = Rebound()\n_rebound_obj._rebound = _jws_global_obj", ""},
		{"Global", "_global", "_global_obj = Global()\n_global_obj._global = _jws_global_obj\n\n\ndef reset():\n    global _global_obj\n    _global_obj = None", ""},
		{"Factory", "_factory", "_factory_obj = factory()\n_factory_obj._factory = _jws_global_obj", ""},
		{"InFunction", "_in_function", "_in_function_obj = InFunction()\n\n\ndef setup():\n    _in_function_obj._in_function = _jws_global_obj", ""},
	}
	var src strings.Builder
	src.WriteString("from .jws import JWS, _jws_global_obj, _other_obj\nfrom .objs import _imported_obj\n\n\ndef factory():\n    return JWS()\n")
	for _, c := range classes {
		fmt.Fprintf(&src, "\n\nclass %s:\n    def __init__(self):\n        self.%s = JWS()\n\n    def go(self, p):\n        return self.%s.encode(p)\n", c.name, c.field, c.field)
	}
	for _, c := range classes {
		src.WriteString("\n\n" + c.write + "\n")
	}
	graph := buildTypedPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/jws.py": `class JWS:
    def encode(self, p):
        return p


class Other:
    def encode(self, p):
        return p


_jws_global_obj = JWS()
_other_obj = Other()
`,
		"app/objs.py": "from .jwt import Imported\n\n_imported_obj = Imported()\n",
		"app/jwt.py":  src.String(),
	})
	for _, c := range classes {
		want := ""
		if c.want != "" {
			want = "probe.app.jws.(JWS)." + c.want
		}
		got, untyped := pythonCallee(t, graph, "probe.app.jwt.("+c.name+").go", "self."+c.field+".encode", "p")
		switch {
		case want == "" && !untyped:
			t.Errorf("%s: typed as %s, want untyped", c.name, got)
		case want != "" && (untyped || got != want):
			t.Errorf("%s: %s (untyped %v), want %s", c.name, got, untyped, want)
		}
	}
}
