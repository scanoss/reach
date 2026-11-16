// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// describePythonSources is describeSources with a variable's may-values
// (`~a|b`, `!` when exhaustive).
func describePythonSources(nodes []SourceNode) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		s := describeSources([]SourceNode{{Type: n.Type, Name: n.Name, Value: n.Value, ParameterIndex: n.ParameterIndex}})
		if len(n.MayValues) > 0 {
			s += "~" + strings.Join(n.MayValues, "|")
			if n.MayValuesExhaustive {
				s += "!"
			}
		}
		if len(n.SourceNodes) > 0 {
			s += "{" + describePythonSources(n.SourceNodes) + "}"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}

// pythonCallArguments lists `<line> <sources of argument index>` for every
// call spelled raw, sorted.
func pythonCallArguments(graph *CallGraph, raw string, index int) []string {
	var got []string
	for _, fn := range graph.Functions {
		for _, c := range fn.Calls {
			if c.Raw != raw {
				continue
			}
			sources := ""
			if index < len(c.ArgumentSources) {
				sources = describePythonSources(c.ArgumentSources[index])
			}
			got = append(got, strings.TrimSpace(fmt.Sprintf("%02d %s", c.Line, sources)))
		}
	}
	sort.Strings(got)
	return got
}

// Inside the body of `if v == X:` / `elif X == v:` (also as an `and`
// conjunct), `if v in (X, Y):` and `case X:` / `case X | Y:` of `match v:`,
// a call's argument v traces to X, or to X and Y. X is a plain string, an
// integer, or a name rooted in an import or a class of the module (`==` or
// `is`); a str enum member folds into its string.
func TestPythonParser_BranchRefinement(t *testing.T) {
	t.Parallel()

	src := `import hashlib
import enum
from cryptography.hazmat.primitives import hashes
from algs import SHA1

class Alg(str, enum.Enum):
    HS256 = "HS256"

def eq(alg, n, data):
    if alg == "sha256":
        hashlib.new(alg, data)
    elif "sha384" == alg and n > 0:
        hashlib.new(alg, data)
    elif n > 0 and (alg == 'md5'):
        hashlib.new(alg, data)
    if (alg == "sha1"):
        while n:
            hashlib.new(alg, data)
    if alg == 16:
        hashlib.new(alg, data)

def member(alg, data):
    if alg in ("sha384", "sha512"):
        hashlib.new(alg, data)
    if alg in ["sha1"]:
        hashlib.new(alg, data)
    if alg in {"a", "a", "b"}:
        hashlib.new(alg, data)
    if alg in ("a", hashes.SHA256):
        hashlib.new(alg, data)

def matched(alg, ok, data):
    match alg:
        case "sha3_256":
            hashlib.new(alg, data)
        case "blake2b" | "blake2s":
            hashlib.new(alg, data)
        case "sha224" if ok:
            hashlib.new(alg, data)
        case hashes.SHA256:
            hashlib.new(alg, data)
        case 1 | hashes.SHA512:
            hashlib.new(alg, data)

def names(alg, data):
    if alg == hashes.SHA256:
        hashlib.new(alg, data)
    if alg is hashes.SHA384:
        hashlib.new(alg, data)
    if alg == SHA1:
        hashlib.new(alg, data)
    if alg == Alg.HS256:
        hashlib.new(alg, data)

def local(data):
    alg = pick()
    if alg == "sha256":
        hashlib.new(alg, data)

def kept(alg, data, self, d):
    match alg:
        case "sha224" if hashlib.new(alg, data):
            pass
    if alg == "a b":
        hashlib.new(alg, data)
    if alg == "x":
        self.alg = 1
        d[alg] = 2
        hashlib.new(alg, data)
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	want := []string{
		`11 VARIABLE alg{VALUE="sha256"}`,
		`13 VARIABLE alg{VALUE="sha384"}`,
		`15 VARIABLE alg{VALUE='md5'}`,
		`18 VARIABLE alg{VALUE="sha1"}`,
		`20 VARIABLE alg{VALUE=16}`,
		`24 VARIABLE alg~"sha384"|"sha512"!`,
		`26 VARIABLE alg{VALUE="sha1"}`,
		`28 VARIABLE alg~"a"|"b"!`,
		`30 VARIABLE alg{VALUE="a",VALUE=hashes.SHA256}`,
		`35 VARIABLE alg{VALUE="sha3_256"}`,
		`37 VARIABLE alg~"blake2b"|"blake2s"!`,
		`39 VARIABLE alg{VALUE="sha224"}`,
		`41 VARIABLE alg{VALUE=hashes.SHA256}`,
		`43 VARIABLE alg{VALUE=1,VALUE=hashes.SHA512}`,
		`47 VARIABLE alg{VALUE=hashes.SHA256}`,
		`49 VARIABLE alg{VALUE=hashes.SHA384}`,
		`51 VARIABLE alg{VALUE=SHA1}`,
		`53 VARIABLE alg{FIELD Alg.HS256{VALUE="HS256"}}`,
		`58 VARIABLE alg{VALUE="sha256"}`,
		`62 VARIABLE alg{VALUE="sha224"}`,
		`65 VARIABLE alg{VALUE="a b"}`,
		`69 VARIABLE alg{VALUE="x"}`,
	}
	if got := pythonCallArguments(graph, "hashlib.new", 0); !reflect.DeepEqual(got, want) {
		t.Errorf("hashlib.new arguments =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// No refinement: an else branch, `!=`, `not in`, a negated or `or`
// condition, a chained comparison, `is` with a literal, a substring test, a
// value that is no fixed one (a local, a call, an f-string, a name bound in
// the function), a pattern that captures, destructures, matches a class or
// anything, a subject that is no name, a body that binds the variable
// (assignment, augmented assignment, loop, comprehension, walrus, `as`
// target, import, del, global, case capture, lambda parameter, nested def or
// its parameter), a use inside a nested def, another variable, and outside
// the branch.
func TestPythonParser_BranchRefinementLeftAlone(t *testing.T) {
	t.Parallel()

	src := `import hashlib
from cryptography.hazmat.primitives import hashes

def left_alone(alg, other, n, data, self):
    if alg == "a":
        pass
    else:
        hashlib.new(alg, data)
    if alg != "a":
        hashlib.new(alg, data)
    if alg not in ("a", "b"):
        hashlib.new(alg, data)
    if not alg == "a":
        hashlib.new(alg, data)
    if alg == "a" or n:
        hashlib.new(alg, data)
    if "a" == alg == other:
        hashlib.new(alg, data)
    if alg is "a":
        hashlib.new(alg, data)
    if alg in "abc":
        hashlib.new(alg, data)
    if alg == other:
        hashlib.new(alg, data)
    if alg == pick():
        hashlib.new(alg, data)
    if alg == f"sha{n}":
        hashlib.new(alg, data)
    if alg in ("a", other):
        hashlib.new(alg, data)
    if alg in ():
        hashlib.new(alg, data)
    if alg == n.SHA256:
        hashlib.new(alg, data)
    match alg:
        case name:
            hashlib.new(alg, data)
    match alg:
        case ("a", "b"):
            hashlib.new(alg, data)
        case "a", "b":
            hashlib.new(alg, data)
        case str():
            hashlib.new(alg, data)
        case "a" as kept:
            hashlib.new(alg, data)
        case _:
            hashlib.new(alg, data)
    match self.alg:
        case "a":
            hashlib.new(alg, data)
    if alg == "a":
        alg = other
        hashlib.new(alg, data)
    if alg == "b":
        for alg in n:
            hashlib.new(alg, data)
    if alg == "c":
        hashlib.new(alg, (alg := other))
    if alg == "d":
        hashlib.new(alg, lambda alg: alg)
    if alg == "e":
        def inner():
            hashlib.new(alg, data)
        inner()
    if other == "f":
        hashlib.new(alg, data)
    if other in ("f", "g"):
        hashlib.new(alg, data)
    if alg is 1:
        hashlib.new(alg, data)
    if alg == "h":
        alg += "x"
        hashlib.new(alg, data)
    if alg == "i":
        hashlib.new(alg, [alg for alg in data])
    if alg == "j":
        with open(data) as alg:
            hashlib.new(alg, data)
    if alg == "k":
        import alg
        hashlib.new(alg, data)
    if alg == "l":
        del alg
        hashlib.new(alg, data)
    if alg == "m":
        global alg
        hashlib.new(alg, data)
    if alg == "n":
        match data:
            case alg:
                hashlib.new(alg, data)
    if alg == "o":
        def alg():
            pass
        hashlib.new(alg, data)
    if alg == "p":
        def shadow(alg):
            pass
        hashlib.new(alg, data)
    if self.alg == "g":
        hashlib.new(alg, data)
    hashlib.new(alg, data)
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	got := pythonCallArguments(graph, "hashlib.new", 0)
	for _, line := range got {
		if strings.Contains(line, "VARIABLE") || strings.Contains(line, "VALUE") {
			t.Errorf("refined: %s", line)
		}
	}
	// One call per guarded position, the nested def's included.
	if len(got) != 40 {
		t.Errorf("%d hashlib.new calls, want 40:\n%s", len(got), strings.Join(got, "\n"))
	}
}

// The innermost guard that names the variable decides.
func TestPythonParser_BranchRefinementInnermost(t *testing.T) {
	t.Parallel()

	src := `import hashlib

def nested(alg, kind, data):
    if alg in ("sha256", "sha512"):
        if kind == "x":
            hashlib.new(alg, data)
        if alg == "sha512":
            hashlib.new(alg, data)
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	want := []string{`06 VARIABLE alg~"sha256"|"sha512"!`, `08 VARIABLE alg{VALUE="sha512"}`}
	if got := pythonCallArguments(graph, "hashlib.new", 0); !reflect.DeepEqual(got, want) {
		t.Errorf("hashlib.new arguments =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A capture pattern binds its name, so a parameter it names is no longer the
// caller's argument; a dotted value pattern binds nothing.
func TestPythonParser_CasePatternBindings(t *testing.T) {
	t.Parallel()

	src := `import hashlib
from cryptography.hazmat.primitives import hashes

def captured(alg, data):
    match data:
        case alg:
            pass
    hashlib.new(alg, data)

def valued(alg, hashes_, data):
    match data:
        case hashes.SHA256:
            pass
    hashlib.new(alg, data)
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	want := []string{`08`, `14 PARAMETER alg#0`}
	if got := pythonCallArguments(graph, "hashlib.new", 0); !reflect.DeepEqual(got, want) {
		t.Errorf("hashlib.new arguments =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
