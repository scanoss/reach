// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// assertOnlyCallee checks that caller reaches want and none of the others.
func assertOnlyCallee(t *testing.T, graph *CallGraph, caller, want string, not ...string) {
	t.Helper()
	if !hasCaller(graph, want, caller) {
		t.Errorf("%s does not reach %s; callers of it: %v", caller, want, graph.Callers[want])
	}
	for _, other := range not {
		if hasCaller(graph, other, caller) {
			t.Errorf("%s reaches %s, but its object is never one", caller, other)
		}
	}
}

// A factory declares an interface result and builds one implementation. A
// call on the value it returns reaches that implementation's method only:
// h := liba.Standard(); h.Sum(..) reaches standard.Sum and never plain.Sum.
func TestConstructedReceiver_GoFactoryReturningInterface(t *testing.T) {
	t.Parallel()
	g := buildGoTree(t, map[string]string{
		"liba/liba.go": `package liba

type Hasher interface{ Sum(data []byte) []byte }

type standard struct{}

func (standard) Sum(data []byte) []byte { return data }

type plain struct{}

func (*plain) Sum(data []byte) []byte { return data }

func Standard() Hasher { return standard{} }

func Plain() Hasher { return &plain{} }
`,
		"app/main.go": `package main

import "example.com/m/liba"

func useStandard() []byte {
	h := liba.Standard()
	return h.Sum(nil)
}

func usePlain() []byte {
	h := liba.Plain()
	return h.Sum(nil)
}
`,
	})
	standard := "example.com/m/liba.(standard).Sum"
	plain := "example.com/m/liba.(*plain).Sum"
	assertOnlyCallee(t, g, "example.com/m/app.useStandard", standard, plain)
	assertOnlyCallee(t, g, "example.com/m/app.usePlain", plain, standard)
}

func TestConstructedReceiver_PythonFactoryReturningSubclass(t *testing.T) {
	t.Parallel()
	g := buildPythonProject(t, map[string]string{
		"main.py": `import liba


def use_standard():
    h = liba.standard()
    return h.sum(b"x")


def use_plain():
    h = liba.plain()
    return h.sum(b"x")


def use_shared(h):
    h = liba.standard()
    return h.sum(b"x")
`,
		"liba/__init__.py": `class Hasher:
    def sum(self, data):
        raise NotImplementedError


class _Standard(Hasher):
    def sum(self, data):
        return data


class _Plain(Hasher):
    def sum(self, data):
        return bytes(data)


def standard():
    return _Standard()


def plain():
    if not _Plain:
        return None
    return _Plain()
`,
	})
	standard := "probe.liba.(_Standard).sum"
	plain := "probe.liba.(_Plain).sum"
	assertOnlyCallee(t, g, "probe.main.use_standard", standard, plain)
	assertOnlyCallee(t, g, "probe.main.use_plain", plain, standard)
	// A parameter may hold the caller's object instead, so it stays untyped.
	if hasCaller(g, standard, "probe.main.use_shared") {
		t.Errorf("use_shared reaches %s through its parameter h", standard)
	}
}

func TestConstructedReceiver_NodeFactoryReturningSubclass(t *testing.T) {
	t.Parallel()
	g := buildNodeAppWithDependency(t, "dispatch-liba", map[string]string{
		"package.json": `{"name":"dispatch-liba","main":"index.js"}`,
		"index.js": `class Hasher { sum(data) { throw new Error('abstract') } }
class Standard extends Hasher { sum(data) { return data } }
class Plain extends Hasher { sum(data) { return data } }
function standard() { return new Standard(); }
const plain = () => new Plain();
module.exports = { Hasher, standard, plain };
`,
	}, `const liba = require('dispatch-liba');
function useStandard() { const h = liba.standard(); return h.sum('x'); }
function usePlain() { const h = liba.plain(); return h.sum('x'); }
module.exports = { useStandard, usePlain };
`)
	standard := "dispatch-liba/index.(Standard).sum"
	plain := "dispatch-liba/index.(Plain).sum"
	assertOnlyCallee(t, g, "app/index.useStandard", standard, plain)
	assertOnlyCallee(t, g, "app/index.usePlain", plain, standard)
}

const javaHashersSource = `package org.example.liba;

public final class Hashers {
    public static Hasher standard() {
        return new Standard();
    }

    public static Hasher plain() {
        return new Plain();
    }

    public static Hasher anonymous() {
        return new Hasher() {
            @Override
            public byte[] sum(byte[] data) {
                return data;
            }
        };
    }

    private static final class Standard implements Hasher {
        @Override
        public byte[] sum(byte[] data) {
            return data;
        }
    }

    private static final class Plain implements Hasher {
        @Override
        public byte[] sum(byte[] data) {
            return data.clone();
        }
    }
}
`

// The Java shape of the same factory: the interface call no longer fans out
// to every implementation, so the factory that builds the harmless one does
// not reach the other. An anonymous class is not the interface, so a call on
// what such a factory returns keeps the fan-out.
func TestConstructedReceiver_JavaFactoryReturningImplementation(t *testing.T) {
	t.Parallel()
	g := buildJavaGraph(t, map[string]string{
		"org/example/liba/Hasher.java":  "package org.example.liba;\n\npublic interface Hasher {\n    byte[] sum(byte[] data);\n}\n",
		"org/example/liba/Hashers.java": javaHashersSource,
		"org/example/app/Main.java": `package org.example.app;

import org.example.liba.Hasher;
import org.example.liba.Hashers;

public final class Main {
    static byte[] useStandard() {
        Hasher h = Hashers.standard();
        return h.sum(new byte[0]);
    }

    static byte[] usePlain() {
        Hasher h = Hashers.plain();
        return h.sum(new byte[0]);
    }

    static byte[] useAnonymous() {
        Hasher h = Hashers.anonymous();
        return h.sum(new byte[0]);
    }

    private Hasher configured;

    byte[] useRebound(boolean fips) {
        Hasher h = Hashers.plain();
        if (fips) {
            h = this.configured;
        }
        return h.sum(new byte[0]);
    }
}
`,
	})
	standard := "org.example.liba.(Hashers.Standard).sum#1"
	plain := "org.example.liba.(Hashers.Plain).sum#1"
	assertOnlyCallee(t, g, "org.example.app.(Main).useStandard#0", standard, plain)
	assertOnlyCallee(t, g, "org.example.app.(Main).usePlain#0", plain, standard)
	// An anonymous class is not the interface, and a local that something
	// other than the factory also assigns may hold another object: both keep
	// the interface fan-out.
	for _, caller := range []string{"org.example.app.(Main).useAnonymous#0", "org.example.app.(Main).useRebound#1"} {
		if !hasCaller(g, standard, caller) || !hasCaller(g, plain, caller) {
			t.Errorf("%s must keep the interface fan-out; callers of Standard.sum %v, of Plain.sum %v", caller, g.Callers[standard], g.Callers[plain])
		}
	}
}

// receiverProducerOf is the ReceiverProducer of caller's call of method.
func receiverProducerOf(t *testing.T, graph *CallGraph, caller, method string) string {
	t.Helper()
	fn := graph.Functions[caller]
	if fn == nil {
		t.Fatalf("%s is not in the graph", caller)
	}
	for i := range fn.Calls {
		if BaseFunctionName(fn.Calls[i].Callee.Name) == method {
			return fn.Calls[i].ReceiverProducer
		}
	}
	t.Fatalf("%s does not call %s", caller, method)
	return ""
}

// The factory lives in a dependency the graph does not hold, so the graph
// cannot read what it builds. The call then names the factory, for a reader
// that holds its graph: only for a local bound once, by that one call.
func TestConstructedReceiver_NamesAProducerOutsideTheGraph(t *testing.T) {
	t.Parallel()
	g := buildJavaGraph(t, map[string]string{
		"org/example/app/Main.java": `package org.example.app;

import org.example.liba.Hasher;
import org.example.liba.Hashers;

public final class Main {
    static byte[] useStandard() {
        Hasher h = Hashers.standard();
        return h.sum(new byte[0]);
    }

    private Hasher configured;

    byte[] useRebound(boolean fips) {
        Hasher h = Hashers.plain();
        if (fips) {
            h = this.configured;
        }
        return h.sum(new byte[0]);
    }

    static byte[] useParameter(Hasher h) {
        return h.sum(new byte[0]);
    }

    static byte[] useConstructed() {
        Hasher h = new org.example.liba.Fast();
        return h.sum(new byte[0]);
    }

    static byte[] useEither(boolean fips) {
        Hasher h = fips ? Hashers.standard() : Hashers.plain();
        return h.sum(new byte[0]);
    }

    static byte[] useShadowed(boolean fips) {
        if (fips) {
            Hasher h = Hashers.standard();
            return h.sum(new byte[0]);
        }
        Hasher h = Hashers.plain();
        return h.sum(new byte[0]);
    }
}
`,
	})
	if got, want := receiverProducerOf(t, g, "org.example.app.(Main).useStandard#0", "sum"), "org.example.liba.(Hashers).standard#0"; got != want {
		t.Errorf("useStandard: receiver producer %q, want %q", got, want)
	}
	for _, caller := range []string{"useRebound#1", "useParameter#1", "useEither#1", "useShadowed#1"} {
		if got := receiverProducerOf(t, g, "org.example.app.(Main)."+caller, "sum"); got != "" {
			t.Errorf("%s: receiver producer %q, want none: the local is not bound once by one call", caller, got)
		}
	}
	if got := receiverProducerOf(t, g, "org.example.app.(Main).useConstructed#0", "sum"); got != "" {
		t.Errorf("useConstructed: receiver producer %q, want none: a constructor returns nothing to read", got)
	}
}

// A producer the graph declares is read there: the call is resolved, or kept,
// and names no producer for another reader.
func TestConstructedReceiver_NamesNoProducerTheGraphDeclares(t *testing.T) {
	t.Parallel()
	g := buildJavaGraph(t, map[string]string{
		"org/example/liba/Hasher.java":  "package org.example.liba;\n\npublic interface Hasher {\n    byte[] sum(byte[] data);\n}\n",
		"org/example/liba/Hashers.java": javaHashersSource,
		"org/example/app/Main.java": `package org.example.app;

import org.example.liba.Hasher;
import org.example.liba.Hashers;

public final class Main {
    static byte[] useStandard() {
        Hasher h = Hashers.standard();
        return h.sum(new byte[0]);
    }

    static byte[] useAnonymous() {
        Hasher h = Hashers.anonymous();
        return h.sum(new byte[0]);
    }
}
`,
	})
	for _, caller := range []string{"useStandard#0", "useAnonymous#0"} {
		if got := receiverProducerOf(t, g, "org.example.app.(Main)."+caller, "sum"); got != "" {
			t.Errorf("%s: receiver producer %q, want none", caller, got)
		}
	}
}

// A function returning `Box<dyn Trait>` built from one struct: the trait
// method call on its result reaches that struct's impl.
func TestConstructedReceiver_RustBoxedTraitObject(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `pub trait Hasher {
    fn sum(&self, data: &[u8]) -> Vec<u8>;
}

struct Standard;

impl Hasher for Standard {
    fn sum(&self, data: &[u8]) -> Vec<u8> { data.to_vec() }
}

struct Plain { level: u8 }

impl Hasher for Plain {
    fn sum(&self, data: &[u8]) -> Vec<u8> { data.to_vec() }
}

pub fn standard() -> Box<dyn Hasher> {
    Box::new(Standard)
}

pub fn plain() -> Box<dyn Hasher> {
    return Box::new(Plain { level: 1 });
}

pub fn use_standard() -> Vec<u8> {
    let h = standard();
    h.sum(b"x")
}

pub fn use_plain() -> Vec<u8> {
    let h = plain();
    h.sum(b"x")
}
`
	if err := os.WriteFile(filepath.Join(dir, "lib.rs"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	g, err := NewBuilderForEcosystem("rust", NewRustParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "hashers"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	standard := "hashers.(Standard).sum"
	plain := "hashers.(Plain).sum"
	assertOnlyCallee(t, g, "hashers.use_standard", standard, plain)
	assertOnlyCallee(t, g, "hashers.use_plain", plain, standard)
}

// ConstructedClass is what a Java fragment writes as a function's constructs:
// one class, built with a plain `new` on every return that yields an object,
// and nothing as soon as one return yields anything else, including a return
// the parser cannot trace into a source.
func TestConstructedClass_JavaReturns(t *testing.T) {
	t.Parallel()
	g := buildJavaGraph(t, map[string]string{
		"org/example/liba/Hasher.java": "package org.example.liba;\n\npublic interface Hasher {\n    byte[] sum(byte[] data);\n}\n",
		"org/example/liba/Factories.java": `package org.example.liba;

public final class Factories {
    static final class Standard implements Hasher {
        public byte[] sum(byte[] data) { return data; }
    }

    static final class Plain implements Hasher {
        public byte[] sum(byte[] data) { return data; }
    }

    private static Hasher cached;

    static Hasher standard() {
        return new Standard();
    }

    static Hasher orNull(boolean off) {
        if (off) {
            return null;
        }
        return new Standard();
    }

    static Hasher untraceable(boolean fast) {
        if (fast) {
            return new org.example.liba.Box<String>();
        }
        return new Standard();
    }

    static Hasher delegated(boolean fast, Object helper) {
        if (fast) {
            return helper.make();
        }
        return new Standard();
    }

    static Hasher either(boolean fips) {
        if (fips) {
            return new Standard();
        }
        return new Plain();
    }

    static Hasher anonymous() {
        return new Standard() { };
    }

    static Hasher field() {
        return cached;
    }

    static Hasher onlyNull() {
        return null;
    }
}
`,
	})
	standard := FunctionID{Package: "org.example.liba", Type: "Standard"}
	want := map[string]FunctionID{"standard#0": standard, "orNull#1": standard}
	for _, name := range []string{"standard#0", "orNull#1", "untraceable#1", "delegated#2", "either#1", "anonymous#0", "field#0", "onlyNull#0"} {
		key := "org.example.liba.(Factories)." + name
		decl := g.Functions[key]
		if decl == nil {
			t.Fatalf("%s is not in the graph", key)
		}
		got, ok := decl.ConstructedClass()
		wantClass, wantOK := want[name]
		if ok != wantOK || got != wantClass {
			t.Errorf("%s: ConstructedClass() = %+v, %v; want %+v, %v", name, got, ok, wantClass, wantOK)
		}
	}
	// The hole return_sources leave: the tracer names no type for a scoped
	// generic `new`, so the list holds the `new Standard()` alone.
	if sources := g.Functions["org.example.liba.(Factories).untraceable#1"].ReturnSources; len(sources) != 1 {
		t.Errorf("untraceable: %d return sources, want the one this test is about: %+v", len(sources), sources)
	}
	if got, ok := (*FunctionDecl)(nil).ConstructedClass(); ok {
		t.Errorf("nil decl: ConstructedClass() = %+v, want none", got)
	}
}
