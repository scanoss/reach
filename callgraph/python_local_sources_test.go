// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestPythonParser_LocalArgumentSources(t *testing.T) {
	src := `from cryptography.hazmat.primitives.asymmetric import ec

def f(flag):
    bits = 2048
    curve = ec.SECP521R1()
    twice = 1024
    twice = 4096
    if flag:
        cond = 2048
    else:
        cond = 2048
    use(bits, curve, twice, cond, unknown)
`
	fns := parsePythonInline(t, src)
	call := findPythonCallByMethod(findPythonFuncByName(fns, "f"), "use")
	if call == nil || len(call.ArgumentSources) != 5 {
		t.Fatalf("use call = %+v", call)
	}
	bits := call.ArgumentSources[0]
	if len(bits) != 1 || bits[0].Type != "VARIABLE" || bits[0].Name != "bits" || len(bits[0].SourceNodes) != 1 || bits[0].SourceNodes[0].Value != "2048" {
		t.Errorf("bits = %+v, want VARIABLE bits wrapping VALUE 2048", bits)
	}
	curve := call.ArgumentSources[1]
	if len(curve) != 1 || curve[0].Type != "VARIABLE" || len(curve[0].SourceNodes) != 1 || curve[0].SourceNodes[0].Type != "CALL_RESULT" || curve[0].SourceNodes[0].CallTarget == nil {
		t.Fatalf("curve = %+v, want VARIABLE wrapping CALL_RESULT", curve)
	}
	if got := curve[0].SourceNodes[0].CallTarget; got.Name != "SECP521R1" {
		t.Errorf("curve call target = %+v, want SECP521R1", got)
	}
	if got := call.ArgumentSources[2]; got != nil {
		t.Errorf("twice = %+v, want nil: two different literals", got)
	}
	if got := call.ArgumentSources[3]; len(got) != 1 || got[0].SourceNodes[0].Value != "2048" {
		t.Errorf("cond = %+v, want VALUE 2048: both branches agree", got)
	}
	if got := call.ArgumentSources[4]; got != nil {
		t.Errorf("unknown = %+v, want nil", got)
	}
}

// TestPythonParser_LocalArgumentSourcesScaleLinearly pins that locals are
// indexed once per function. Resolving a name by rescanning the function body
// per argument grows with the square of its size.
func TestPythonParser_LocalArgumentSourcesScaleLinearly(t *testing.T) {
	build := func(n int) string {
		var b strings.Builder
		b.WriteString("def f(items):\n")
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "    v%d = %d\n", i, i+1)
			if i%4 == 0 {
				fmt.Fprintf(&b, "    v%d = %d\n", i, i+2)
			}
		}
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, "    gen(v%d)\n", i)
		}
		return b.String()
	}
	measure := func(n int) (visits, work, resolved int, elapsed time.Duration) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "big.py"), []byte(build(n)), 0o644); err != nil {
			t.Fatal(err)
		}
		p := NewPythonParser()
		p.visits = &visits
		p.localWork = &work
		start := time.Now()
		analyses, err := p.ParseDirectory(dir, "pkg")
		if err != nil {
			t.Fatal(err)
		}
		elapsed = time.Since(start)
		for _, a := range analyses {
			for _, fn := range a.Functions {
				for _, call := range fn.Calls {
					if call.Callee.Name == "gen" && len(call.ArgumentSources) == 1 && len(call.ArgumentSources[0]) == 1 {
						resolved++
					}
				}
			}
		}
		return visits, work, resolved, elapsed
	}
	const small, large = 1000, 4000
	smallVisits, smallWork, smallResolved, _ := measure(small)
	largeVisits, largeWork, largeResolved, elapsed := measure(large)
	if want := small - (small+3)/4; smallResolved != want {
		t.Fatalf("resolved %d of %d unambiguous locals", smallResolved, want)
	}
	if want := large - (large+3)/4; largeResolved != want {
		t.Fatalf("resolved %d of %d unambiguous locals", largeResolved, want)
	}
	if ratio := float64(largeVisits) / float64(smallVisits); ratio > 5 {
		t.Fatalf("visits grew %.1fx for a 4x larger function, want about 4x", ratio)
	}
	if ratio := float64(largeWork) / float64(smallWork); smallWork == 0 || ratio > 5 {
		t.Fatalf("index work grew %.1fx (%d to %d) for a 4x larger function, want about 4x", ratio, smallWork, largeWork)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("parsing %d locals took %s, want near-linear time", large, elapsed)
	}
}

// TestPythonParser_LocalConstructorCallRootMustBeAnImport pins that a stored
// zero-argument call resolves only through a dotted name rooted at an import
// that no local name hides.
func TestPythonParser_LocalConstructorCallRootMustBeAnImport(t *testing.T) {
	src := `import threading
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import SECP384R1

imported = ec.SECP521R1()
threaded = threading.local()
unimported = missing.SECP521R1()
bare = SECP384R1()
made = object()


def f():
    use(imported, threaded, unimported, bare, made)


def g(ec):
    use(imported)
`
	fns := parsePythonInline(t, src)
	call := findPythonCallByMethod(findPythonFuncByName(fns, "f"), "use")
	if call == nil || len(call.ArgumentSources) != 5 {
		t.Fatalf("use call = %+v", call)
	}
	for i, want := range []bool{true, true, false, false, false} {
		if got := call.ArgumentSources[i] != nil; got != want {
			t.Errorf("argument %d resolved = %v, want %v: %+v", i, got, want, call.ArgumentSources[i])
		}
	}
	shadowed := findPythonCallByMethod(findPythonFuncByName(fns, "g"), "use")
	if shadowed == nil || len(shadowed.ArgumentSources) != 1 || shadowed.ArgumentSources[0] != nil {
		t.Errorf("a parameter named like the import root must hide the constructor: %+v", shadowed)
	}
}

// A local or module name bound once to a dotted name rooted in an import
// (`variant = Type.ID`) traces to that name as written, a constant as an
// integer or a string literal is; a str enum member folds into its string.
// The same name passed directly is no source. Nothing resolves when the
// root is no import, a local hides the root, the name is bound twice to
// different constants, the value is an attribute of a local object, or the
// function only writes an attribute of the name.
func TestPythonParser_LocalDottedConstants(t *testing.T) {
	t.Parallel()

	src := `import enum
import hashlib
from argon2 import Type
from kmip.core import enums as kenums

MODULE = kenums.CryptographicAlgorithm.AES

class Alg(str, enum.Enum):
    HS256 = "HS256"

def resolved(data, flag):
    variant = Type.ID
    hashlib.new(variant, data)
    hashlib.new(MODULE, data)
    member = Alg.HS256
    hashlib.new(member, data)
    if flag:
        same = Type.I
    else:
        same = Type.I
    hashlib.new(same, data)
    hashlib.new(Type.ID, data)

def unresolved(data, flag, obj):
    missing = unknown.ID
    hashlib.new(missing, data)
    twice = Type.ID
    if flag:
        twice = Type.I
    hashlib.new(twice, data)
    attr = obj.kind
    hashlib.new(attr, data)

def shadowed(data, Type):
    variant = Type.ID
    hashlib.new(variant, data)

def written_attribute(data):
    settings.kind = Type.ID
    hashlib.new(settings, data)
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	want := []string{
		`13 VARIABLE variant{VALUE=Type.ID}`,
		`14 VARIABLE MODULE{VALUE=kenums.CryptographicAlgorithm.AES}`,
		`16 VARIABLE member{FIELD Alg.HS256{VALUE="HS256"}}`,
		`21 VARIABLE same{VALUE=Type.I}`,
		`22`,
		`26`,
		`30`,
		`32`,
		`36`,
		`40`,
	}
	if got := pythonCallArguments(graph, "hashlib.new", 0); !reflect.DeepEqual(got, want) {
		t.Errorf("hashlib.new arguments =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A name written after its binding has no value, only the literals it may
// hold, not exhaustive: a module name a function rebinds through `global`
// (also with an augmented assignment or `del`), a local assigned again with
// something else, augmented, deleted or rebound by a nested function
// through `nonlocal`. A name bound again to the same literal keeps it; one
// bound only to literals holds them as exhaustive may-values.
func TestPythonParser_LocalsWrittenAfterBinding(t *testing.T) {
	t.Parallel()

	src := `import hashlib

KEPT = "sha512"
REBOUND = "sha512"
AUGMENTED = "sha"
DELETED = "sha512"

def configure():
    global REBOUND, AUGMENTED, DELETED
    REBOUND = "md5"
    AUGMENTED += "1"
    del DELETED

def module_names(data):
    hashlib.new(KEPT, data)
    hashlib.new(REBOUND, data)
    hashlib.new(AUGMENTED, data)
    hashlib.new(DELETED, data)

def locals_(data, flag):
    same = "sha512"
    if flag:
        same = "sha512"
    hashlib.new(same, data)
    either = "sha512"
    if flag:
        either = "sha256"
    hashlib.new(either, data)
    mixed = "sha512"
    if flag:
        mixed = data.decode()
    hashlib.new(mixed, data)
    grown = "sha"
    grown += "512"
    hashlib.new(grown, data)
    gone = "sha512"
    del gone
    hashlib.new(gone, data)
    shared = "sha512"

    def reset():
        nonlocal shared
        shared = "md5"

    reset()
    hashlib.new(shared, data)
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	want := []string{
		`15 VARIABLE KEPT{VALUE="sha512"}`,
		`16 VARIABLE REBOUND~"sha512"`,
		`17 VARIABLE AUGMENTED~"sha"`,
		`18 VARIABLE DELETED~"sha512"`,
		`24 VARIABLE same{VALUE="sha512"}`,
		`28 VARIABLE either~"sha512"|"sha256"!`,
		`32 VARIABLE mixed~"sha512"`,
		`35 VARIABLE grown~"sha"`,
		`38 VARIABLE gone~"sha512"`,
		`46 VARIABLE shared~"sha512"`,
	}
	if got := pythonCallArguments(graph, "hashlib.new", 0); !reflect.DeepEqual(got, want) {
		t.Errorf("hashlib.new arguments =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A name bound once to a list or tuple display of plain string and integer
// literals reads as that display, written as at a call (E2.7-py.14b gap 3):
// a tuple always (it cannot change), a list only when it is a function local
// used as a bare call argument and nothing else. A list the function changes
// or hands to anything but a call argument, a module list, a display with
// any other element, and a name bound twice read as nothing.
func TestPythonParser_LocalLiteralDisplays(t *testing.T) {
	src := `ALGS = ["HS256"]
TUP = ("HS256",)


def f(other):
    algs = ["HS256", 'HS384']
    pair = ("RSA-OAEP", "A256GCM")
    single = (2048,)
    changed = ["HS256"]
    changed.append("none")
    mixed = ["HS256", other]
    seen = ["HS512"]
    print(seen[0])
    twice = ("a",)
    twice = ("b",)
    empty = []
    use(algs, pair, single, changed, mixed, seen, twice, empty, ALGS, TUP)
`
	fns := parsePythonInline(t, src)
	call := findPythonCallByMethod(findPythonFuncByName(fns, "f"), "use")
	if call == nil || len(call.ArgumentSources) != 10 {
		t.Fatalf("use call = %+v", call)
	}
	want := []string{`["HS256", 'HS384']`, `("RSA-OAEP", "A256GCM")`, `(2048,)`, "", "", "", "", "", "", `("HS256",)`}
	for i, w := range want {
		got := ""
		if s := call.ArgumentSources[i]; len(s) == 1 && s[0].Type == "VARIABLE" && len(s[0].SourceNodes) == 1 && s[0].SourceNodes[0].Type == "VALUE" {
			got = s[0].SourceNodes[0].Value
		} else if len(s) != 0 {
			got = fmt.Sprintf("%+v", s)
		}
		if got != w {
			t.Errorf("argument %d (%s) = %q, want %q", i, call.Arguments[i], got, w)
		}
	}
}
