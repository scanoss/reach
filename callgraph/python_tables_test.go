// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"reflect"
	"strings"
	"testing"
)

// A subscript of a dispatch table (a dict display with literal keys, in
// place or through a name the function or the module binds once to it) is
// the value of the entry its key selects, when the key resolves: a literal,
// a local or module constant, a variable's may-values, the value a branch
// fixes. The value is a literal, a name rooted in an import (kept as
// written; a str enum member folds into its string) or what an argument of
// that shape traces to (a call).
func TestPythonParser_DispatchTables(t *testing.T) {
	t.Parallel()

	src := `import enum
import hashlib
import hmac
from hashlib import sha1
from cryptography.hazmat.primitives import hashes

DIGESTS = {"HS256": hashlib.sha256, 'HS512': hashlib.sha512, "HS1": sha1, 384: hashlib.sha384, "384": hashlib.md5}
NAMES = {
    "a": "sha256",  # default
    "b": 'sha512',
    "a": "sha3_256",
}
KEY = "HS512"

class Alg(str, enum.Enum):
    HS256 = "HS256"

MEMBERS = {"x": Alg.HS256}
CALLS = {"x": hashes.SHA256(), "y": (hashes.SHA512())}

def literal(key, msg):
    hmac.new(key, msg, DIGESTS["HS512"])
    hmac.new(key, msg, DIGESTS['HS256'])
    hmac.new(key, msg, DIGESTS["HS1"])
    hmac.new(key, msg, DIGESTS[384])
    hmac.new(key, msg, {"sha256": hashlib.sha256}["sha256"])
    hmac.new(key, msg, (DIGESTS)["HS512"])
    hmac.new(key, msg, DIGESTS[ "HS512" ])
    return DIGESTS.get("HS256"), DIGESTS.keys()

def named(key, msg):
    alg = "HS256"
    hmac.new(key, msg, DIGESTS[alg])
    hmac.new(key, msg, DIGESTS[KEY])

def strings(key, msg, flag):
    hmac.new(key, msg, NAMES["a"])
    hmac.new(key, msg, NAMES["b"])
    name = "a"
    if flag:
        name = "b"
    hmac.new(key, msg, NAMES[name])

def refined(key, msg, alg):
    if alg == "HS512":
        hmac.new(key, msg, DIGESTS[alg])
    if alg in ("HS256", "HS512", "none"):
        hmac.new(key, msg, DIGESTS[alg])
    match alg:
        case "a" | "b":
            hmac.new(key, msg, NAMES[alg])

def local(key, msg):
    table = {"x": hashlib.md5, "y": hashlib.sha1}
    hmac.new(key, msg, table["y"])

def values(key, msg):
    hmac.new(key, msg, MEMBERS["x"])
    hmac.new(key, msg, CALLS["x"])
    hmac.new(key, msg, digestmod=DIGESTS["HS256"])
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	want := []string{
		`22 VARIABLE DIGESTS["HS512"]{VALUE=hashlib.sha512}`,
		`23 VARIABLE DIGESTS['HS256']{VALUE=hashlib.sha256}`,
		`24 VARIABLE DIGESTS["HS1"]{VALUE=sha1}`,
		`25 VARIABLE DIGESTS[384]{VALUE=hashlib.sha384}`,
		`26 VARIABLE {"sha256":hashlib.sha256}["sha256"]{VALUE=hashlib.sha256}`,
		`27 VARIABLE (DIGESTS)["HS512"]{VALUE=hashlib.sha512}`,
		`28 VARIABLE DIGESTS["HS512"]{VALUE=hashlib.sha512}`,
		`33 VARIABLE DIGESTS[alg]{VALUE=hashlib.sha256}`,
		`34 VARIABLE DIGESTS[KEY]{VALUE=hashlib.sha512}`,
		`37 VARIABLE NAMES["a"]{VALUE="sha3_256"}`,
		`38 VARIABLE NAMES["b"]{VALUE='sha512'}`,
		`42 VARIABLE NAMES[name]~"sha3_256"|'sha512'!`,
		`46 VARIABLE DIGESTS[alg]{VALUE=hashlib.sha512}`,
		`48 VARIABLE DIGESTS[alg]{VALUE=hashlib.sha256,VALUE=hashlib.sha512}`,
		`51 VARIABLE NAMES[alg]~"sha3_256"|'sha512'!`,
		`55 VARIABLE table["y"]{VALUE=hashlib.sha1}`,
		`58 VARIABLE MEMBERS["x"]{FIELD Alg.HS256{VALUE="HS256"}}`,
		`59 VARIABLE CALLS["x"]{CALL_RESULT=hashes.SHA256()}`,
		`60 VARIABLE DIGESTS["HS256"]{VALUE=hashlib.sha256}`,
	}
	if got := pythonCallArguments(graph, "hmac.new", 2); !reflect.DeepEqual(got, want) {
		t.Errorf("hmac.new digest arguments =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// No value: a key that does not resolve (a parameter, a call, a variable
// that may hold something else) or has no entry, a table with an entry that
// is no `literal: value` pair (a spread, a computed key, a comprehension), a
// name bound twice, bound to something else, a parameter, shadowed by a
// local or a comprehension variable, or whose items the file writes (an
// item assignment or deletion, a dict method that changes it), an
// attribute, a slice, a tuple key, and an entry whose value traces to
// nothing, alone or among the entries the keys select.
func TestPythonParser_DispatchTablesLeftAlone(t *testing.T) {
	t.Parallel()

	src := `import hashlib
import hmac

DIGESTS = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}
BASE = {"HS1": hashlib.sha1}
SPREAD = {"HS256": hashlib.sha256, **BASE}
COMPUTED = {"HS256": hashlib.sha256, pick(): hashlib.sha1}
BUILT = {k: hashlib.sha256 for k in ("HS256",)}
TWICE = {"HS256": hashlib.sha256}
TWICE = {"HS256": hashlib.md5}
OTHER = make()
ASSIGNED = {"HS256": hashlib.sha256}
DELETED = {"HS256": hashlib.sha256}
UPDATED = {"HS256": hashlib.sha256}
LOCALS = {"HS256": helper}
SHADOWED = {"HS256": hashlib.sha256}
EMPTY = {}
MIXED = {"a": hashlib.sha256, "b": helper}
FORMATTED = {f"HS{n}": hashlib.sha256, "HS512": hashlib.sha512}
[hmac.new(k, m, DIGESTS["HS256"]) for DIGESTS in pick()]

class Holder:
    TABLE = {"HS256": hashlib.sha256}

def left_alone(key, msg, alg, flag, param={"HS256": hashlib.sha256}):
    hmac.new(key, msg, DIGESTS[alg])
    hmac.new(key, msg, DIGESTS[pick()])
    name = "HS256"
    if flag:
        name = pick()
    hmac.new(key, msg, DIGESTS[name])
    hmac.new(key, msg, DIGESTS["none"])
    hmac.new(key, msg, SPREAD["HS256"])
    hmac.new(key, msg, COMPUTED["HS256"])
    hmac.new(key, msg, BUILT["HS256"])
    hmac.new(key, msg, TWICE["HS256"])
    hmac.new(key, msg, OTHER["HS256"])
    hmac.new(key, msg, param["HS256"])
    hmac.new(key, msg, ASSIGNED["HS256"])
    hmac.new(key, msg, DELETED["HS256"])
    hmac.new(key, msg, UPDATED["HS256"])
    hmac.new(key, msg, LOCALS["HS256"])
    hmac.new(key, msg, Holder.TABLE["HS256"])
    hmac.new(key, msg, DIGESTS["HS256":])
    hmac.new(key, msg, EMPTY["HS256"])
    SHADOWED = pick()
    hmac.new(key, msg, SHADOWED["HS256"])
    hmac.new(key, msg, DIGESTS["HS256", 1])
    if alg in ("a", "b"):
        hmac.new(key, msg, MIXED[alg])
    hmac.new(key, msg, FORMATTED["HS512"])
    if not param:
        param = {"HS256": hashlib.sha256}
    hmac.new(key, msg, param["HS256"])

def writes():
    ASSIGNED["HS256"] = hashlib.md5
    del DELETED["HS256"]
    UPDATED.update(HS256=hashlib.md5)
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	got := pythonCallArguments(graph, "hmac.new", 2)
	for _, line := range got {
		if strings.Contains(line, " ") {
			t.Errorf("resolved: %s", line)
		}
	}
	if len(got) != 23 {
		t.Errorf("%d hmac.new calls, want 23:\n%s", len(got), strings.Join(got, "\n"))
	}
}

// A module that binds names by string (exec, globals()) has no fixed table.
func TestPythonParser_DispatchTablesDynamicModule(t *testing.T) {
	t.Parallel()

	src := `import hashlib
import hmac

DIGESTS = {"HS256": "sha256"}
globals()["DIGESTS"] = {}

def read(key, msg):
    hmac.new(key, msg, DIGESTS["HS256"])
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	if got, want := pythonCallArguments(graph, "hmac.new", 2), []string{"08"}; !reflect.DeepEqual(got, want) {
		t.Errorf("hmac.new digest arguments = %v, want %v", got, want)
	}
}

// A read of a table the function itself writes or binds, with a key that
// does not resolve, may hold any fixed value the display writes for an
// entry: the subscript's may-values, not exhaustive. A module's table read
// with such a key has no source. A local bound once to a table read traces
// to the read: its value when the key resolves, its may-values otherwise.
func TestPythonParser_DispatchTableMayValues(t *testing.T) {
	t.Parallel()

	src := `import hashlib
import hmac

NAMES = {"a": "md5", "b": "sha1"}
DIGESTS = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}

def unknown_key(key, msg, alg):
    hmac.new(key, msg, {"a": "sha224", "b": 'sha384', "c": "sha224"}[alg])
    names = {"a": "sha256", "b": pick(), **more}
    hmac.new(key, msg, names[alg])
    hmac.new(key, msg, NAMES[alg])
    m = {"SHA-1": hashlib.sha1, "SHA-256": hashlib.sha256, 1: 512}
    hmac.new(key, msg, m[pick()])
    empty = {"a": pick()}
    hmac.new(key, msg, empty[alg])

def bound_to_a_read(key, msg, alg):
    m = {"SHA-1": hashlib.sha1, "SHA-256": hashlib.sha256}
    h = m[alg]
    hmac.new(key, msg, h)
    fixed = DIGESTS["HS512"]
    hmac.new(key, msg, fixed)
    module = DIGESTS[alg]
    hmac.new(key, msg, module)
    inline = {"a": "md5"}[alg]
    hmac.new(key, msg, inline)
    twice = m[alg]
    twice = m["SHA-1"]
    hmac.new(key, msg, twice)
    other = alg[0]
    hmac.new(key, msg, other)
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	want := []string{
		`08 VARIABLE {"a":"sha224","b":'sha384',"c":"sha224"}[alg]~"sha224"|'sha384'`,
		`10 VARIABLE names[alg]~"sha256"`,
		`11`,
		`13 VARIABLE m[pick()]~hashlib.sha1|hashlib.sha256|512`,
		`15`,
		`20 VARIABLE h{VARIABLE m[alg]~hashlib.sha1|hashlib.sha256}`,
		`22 VARIABLE fixed{VARIABLE DIGESTS["HS512"]{VALUE=hashlib.sha512}}`,
		`24`,
		`26 VARIABLE inline{VARIABLE {"a":"md5"}[alg]~"md5"}`,
		`29`,
		`31`,
	}
	if got := pythonCallArguments(graph, "hmac.new", 2); !reflect.DeepEqual(got, want) {
		t.Errorf("hmac.new digest arguments =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A table written after its definition keeps the unresolved reading, by a
// module statement or a function: an augmented assignment of the name, a
// rebinding through `global`, and the name handed to code that may write
// its items (passed as an argument, aliased, returned, put in a display,
// through `or` or a conditional). A builtin that reads or copies it, a
// membership test, a loop and a method that changes nothing leave it fixed.
// A function's own table is guarded the same way.
func TestPythonParser_DispatchTablesWrittenAfterDefinition(t *testing.T) {
	t.Parallel()

	src := `import hashlib
import hmac

READ = {"HS512": hashlib.sha512}
AUGMENTED = {"HS512": hashlib.sha512}
AUGMENTED |= {"HS512": hashlib.md5}
REBOUND = {"HS512": hashlib.sha512}
PASSED = {"HS512": hashlib.sha512}
KEYWORD = {"HS512": hashlib.sha512}
ALIASED = {"HS512": hashlib.sha512}
alias = ALIASED
RETURNED = {"HS512": hashlib.sha512}
STORED = {"HS512": hashlib.sha512}
REGISTRY = [STORED]
EITHER = {"HS512": hashlib.sha512}
GLOBAL_AUG = {"HS512": hashlib.sha512}

def configure(flag):
    global REBOUND, GLOBAL_AUG
    REBOUND = {"HS512": hashlib.md5}
    GLOBAL_AUG |= {"HS512": hashlib.md5}
    register(PASSED)
    setup(table=KEYWORD)
    other = (EITHER or {}) if flag else None
    return RETURNED

def reads(key, msg, alg):
    n = len(READ) + len(sorted(READ)) + len(dict(READ))
    if alg in READ:
        pass
    for k in READ:
        print(k, READ.get(k), READ.keys())
    hmac.new(key, msg, READ["HS512"])
    hmac.new(key, msg, AUGMENTED["HS512"])
    hmac.new(key, msg, REBOUND["HS512"])
    hmac.new(key, msg, PASSED["HS512"])
    hmac.new(key, msg, KEYWORD["HS512"])
    hmac.new(key, msg, ALIASED["HS512"])
    hmac.new(key, msg, RETURNED["HS512"])
    hmac.new(key, msg, STORED["HS512"])
    hmac.new(key, msg, EITHER["HS512"])
    hmac.new(key, msg, GLOBAL_AUG["HS512"])

def local(key, msg):
    fixed = {"HS512": hashlib.sha512}
    hmac.new(key, msg, fixed["HS512"])
    passed = {"HS512": hashlib.sha512}
    normalize(passed)
    hmac.new(key, msg, passed["HS512"])
    aliased = {"HS512": hashlib.sha512}
    view = aliased
    hmac.new(key, msg, aliased["HS512"])
    augmented = {"HS512": hashlib.sha512}
    augmented |= {"HS512": hashlib.md5}
    hmac.new(key, msg, augmented["HS512"])
`
	graph := parseInlinePythonFiles(t, map[string]string{"m.py": src})
	want := []string{
		`33 VARIABLE READ["HS512"]{VALUE=hashlib.sha512}`,
		`34`, `35`, `36`, `37`, `38`, `39`, `40`, `41`, `42`,
		`46 VARIABLE fixed["HS512"]{VALUE=hashlib.sha512}`,
		`49`, `52`, `55`,
	}
	if got := pythonCallArguments(graph, "hmac.new", 2); !reflect.DeepEqual(got, want) {
		t.Errorf("hmac.new digest arguments =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
