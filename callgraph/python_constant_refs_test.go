// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// pythonRefsOf lists a parsed file's constant references by function name
// as "line:col text context [operand]" strings.
func pythonRefsOf(analysis *FileAnalysis) map[string][]string {
	out := map[string][]string{}
	for _, fn := range analysis.Functions {
		for _, ref := range fn.ConstantRefs {
			s := fmt.Sprintf("%d:%d-%d %s %s", ref.Line, ref.StartCol, ref.EndCol, ref.Text, ref.Context)
			if ref.Operand != nil {
				var values []string
				for _, node := range ref.Operand.Sources {
					values = append(values, node.Type+"="+node.Name+node.Value)
				}
				s += " [" + ref.Operand.Text + " " + strings.Join(values, ",") + "]"
			}
			if ref.EndLine != 0 {
				s += fmt.Sprintf(" end %d", ref.EndLine)
			}
			key := fn.ID.Name
			if fn.ID.Type != "" {
				key = fn.ID.Type + "." + key
			}
			out[key] = append(out[key], s)
		}
	}
	return out
}

func TestPythonConstantRefs_PositionKinds(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import ssl
import hashlib as hl
from ssl import PROTOCOL_TLSv1 as P, CERT_NONE


def f(alg, ctx):
    if alg == ssl.CERT_REQUIRED or ssl.CERT_OPTIONAL != alg:
        return ssl.PROTOCOL_TLS
    if alg in (ssl.OP_A, ssl.OP_B) or alg not in [P]:
        pass
    if ssl.OP_C in alg or alg < ssl.OP_D:
        pass
    match alg:
        case ssl.PROTOCOL_TLSv1_1:
            pass
        case "x" | ssl.PROTOCOL_TLSv1_2:
            pass
    x = ssl.OP_E
    y: int = ssl.OP_F
    x |= ssl.OP_G
    t = {"HS256": hl.sha256, ssl.KEY: 1}
    s = {ssl.OP_H}
    ctx.load(ssl.Purpose.SERVER_AUTH, mode=CERT_NONE)
    z = ssl.OP_I if alg else (ssl.OP_J)
    w = alg if ssl.OP_K else 0
    if alg == [ssl.OP_M]:
        pass
    v = CERT_NONE if alg else (P)
    return [P, -ssl.OP_L]
`)
	got := pythonRefsOf(analysis)
	want := []string{
		"7:15-32 ssl.CERT_REQUIRED compare [alg PARAMETER=alg]",
		"7:36-53 ssl.CERT_OPTIONAL compare [alg PARAMETER=alg]",
		"8:16-32 ssl.PROTOCOL_TLS return",
		"9:16-24 ssl.OP_A in [alg PARAMETER=alg]",
		"9:26-34 ssl.OP_B in [alg PARAMETER=alg]",
		"9:51-52 ssl.PROTOCOL_TLSv1 in [alg PARAMETER=alg]",
		"11:8-16 ssl.OP_C in [alg PARAMETER=alg]",
		"11:33-41 ssl.OP_D other",
		"14:14-34 ssl.PROTOCOL_TLSv1_1 case [alg PARAMETER=alg]",
		"16:20-40 ssl.PROTOCOL_TLSv1_2 case [alg PARAMETER=alg]",
		"18:9-17 ssl.OP_E assign",
		"19:14-22 ssl.OP_F init",
		"20:10-18 ssl.OP_G assign",
		`21:19-28 hl.sha256 dict ["HS256" VALUE="HS256"]`,
		"21:30-37 ssl.KEY dict",
		"22:10-18 ssl.OP_H array",
		"23:14-37 ssl.Purpose.SERVER_AUTH arg",
		"23:44-53 ssl.CERT_NONE arg",
		"24:9-17 ssl.OP_I assign",
		"24:31-39 ssl.OP_J assign",
		"25:16-24 ssl.OP_K other",
		"26:16-24 ssl.OP_M array",
		"28:9-18 ssl.CERT_NONE assign",
		"28:32-33 ssl.PROTOCOL_TLSv1 assign",
		"29:13-14 ssl.PROTOCOL_TLSv1 array",
		"29:17-25 ssl.OP_L other",
	}
	if !reflect.DeepEqual(got["f"], want) {
		t.Errorf("refs of f:\n got %q\nwant %q", got["f"], want)
	}
}

// A call target, a written attribute, an attribute of a local, a module
// imported but rebound in the function, a decorator and an annotation hold
// no reference.
func TestPythonConstantRefs_NotReferences(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import ssl
import functools
from typing import Optional
from ssl import CERT_NONE


@functools.lru_cache
def f(ctx: ssl.SSLContext, other) -> Optional[ssl.SSLContext]:
    ssl.create_default_context()
    ssl.OPT = 1
    ctx.verify_mode
    del ssl.X
    other.PROTOCOL
    other.ssl
    other.load(ssl)
    match other:
        case CERT_NONE:
            pass
    return ctx


def g(ssl):
    return ssl.CERT_NONE


def h():
    for ssl.x in []:
        pass
    v: ssl.SSLContext = None


holder.ssl


class Handler(ssl.SSLObject, metaclass=functools.Meta):
    def run(self):
        return 1
`)
	if got := pythonRefsOf(analysis); len(got) != 0 {
		t.Errorf("refs = %q, want none", got)
	}
}

// Module and class bodies define names: a reference there is an
// initializer, and a module or class with references but no call still gets
// its synthetic function. A method's reference stays the method's.
func TestPythonConstantRefs_ModuleAndClassBodies(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import ssl
from cryptography.hazmat.primitives import hashes

TLS11 = ssl.PROTOCOL_TLSv1_1
TABLE = {"sha256": hashes.SHA256,
         "sha384": hashes.SHA384}
try:
    import certifi
except ImportError:
    ssl = None
DEFAULT = ssl.PROTOCOL_TLS


class Cfg:
    ALG = hashes.SHA512

    def m(self):
        return hashes.MD5


def k():
    for _ in ():
        def inner():
            return hashes.SM3
`)
	got := pythonRefsOf(analysis)
	want := map[string][]string{
		"<module>": {
			"4:9-29 ssl.PROTOCOL_TLSv1_1 init",
			`5:20-33 hashes.SHA256 dict ["sha256" VALUE="sha256"]`,
			`6:20-33 hashes.SHA384 dict ["sha384" VALUE="sha384"]`,
			"11:11-27 ssl.PROTOCOL_TLS init",
		},
		"Cfg.<clinit>": {"15:11-24 hashes.SHA512 init"},
		"Cfg.m":        {"18:16-26 hashes.MD5 return"},
		"k":            {"24:20-30 hashes.SM3 return"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("refs:\n got %q\nwant %q", got, want)
	}
}

// A reference spanning lines keeps its end line and its text without
// whitespace; an operand traced to a module constant carries its value.
func TestPythonConstantRefs_SpanAndTracedOperand(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import jwt

MODE = "HS256"


def f():
    if MODE == (jwt
                 .algorithms.HMACAlgorithm):
        pass
`)
	want := []string{`7:17-43 jwt.algorithms.HMACAlgorithm compare [MODE VARIABLE=MODE] end 8`}
	if got := pythonRefsOf(analysis); !reflect.DeepEqual(got["f"], want) {
		t.Errorf("refs = %q, want %q", got["f"], want)
	}
}

// A name defined twice in one file keeps the references, stores,
// declarations and casts of both bodies, once each.
func TestPythonConstantRefs_RedefinitionKeepsBothBodies(t *testing.T) {
	t.Parallel()
	graph := buildPythonProject(t, map[string]string{"app/m.py": `import ssl
from typing import cast

try:
    from fast import x

    def f(ctx):
        ctx.fast = True
        a: ssl.SSLContext = cast(ssl.SSLContext, make())
        return ssl.PROTOCOL_TLSv1_2
except ImportError:
    def f(ctx):
        ctx.fast = False
        b: ssl.SSLContext = cast(ssl.SSLContext, make())
        return ssl.PROTOCOL_TLSv1
`})
	fn := graph.Functions["probe.app.m.f"]
	if fn == nil {
		keys := make([]string, 0, len(graph.Functions))
		for key := range graph.Functions {
			keys = append(keys, key)
		}
		t.Fatalf("f not in the graph: %q", keys)
	}
	var texts []string
	for _, ref := range fn.ConstantRefs {
		texts = append(texts, ref.Text)
	}
	if want := []string{"ssl.SSLContext", "ssl.PROTOCOL_TLSv1", "ssl.SSLContext", "ssl.PROTOCOL_TLSv1_2"}; !reflect.DeepEqual(texts, want) {
		t.Errorf("refs of f = %q, want %q", texts, want)
	}
	var stored []string
	for _, store := range fn.AttributeStores {
		stored = append(stored, store.Value.Text)
	}
	if want := []string{"False", "True"}; !reflect.DeepEqual(stored, want) {
		t.Errorf("stores of f = %q, want %q", stored, want)
	}
	var declared []string
	for _, d := range fn.Declarations {
		declared = append(declared, d.Name)
	}
	if want := []string{"b", "a"}; !reflect.DeepEqual(declared, want) || len(fn.Casts) != 2 {
		t.Errorf("declarations of f = %q, want %q; casts %d, want 2", declared, want, len(fn.Casts))
	}
}

// A field compared with a constant (`self.f`, `cls.f`) carries the fixed
// values its class assigns to it: `f = X` in the class body, `self.f = X` /
// `cls.f = X` in its methods, X a plain string, an integer or a name rooted
// in an import. A value that is not fixed adds nothing, and neither do a
// nested class, a nested def, another object's attribute or another field;
// a field the class assigns no fixed value has no source, like a field of
// another object. The class is the innermost one around the comparison, and
// a value's names are read as the module binds them, whatever the comparing
// method binds.
func TestPythonConstantRefs_ComparedFieldWrites(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import ssl
from ssl import CERT_NONE


class Policy:
    mode = ssl.CERT_OPTIONAL
    level = 3

    def __init__(self, mode, other):
        self.mode = mode
        self.other = ssl.OP_ALL
        if mode is None:
            self.mode = ssl.CERT_REQUIRED
        other.mode = ssl.OP_NO_SSLv2

    @classmethod
    def relaxed(cls):
        cls.mode = CERT_NONE
        cls.mode = "none"
        cls.mode = ssl.CERT_REQUIRED

        def helper(self):
            self.mode = ssl.OP_NO_SSLv3

    class Inner:
        mode = ssl.OP_NO_TLSv1

        def check(self):
            return self.mode == ssl.OP_G

    def shadowing(self, CERT_NONE):
        return self.mode == ssl.OP_H

    def strict(self, peer):
        if self.mode == ssl.CERT_REQUIRED:
            return True
        if (self.level) in (ssl.OP_A, ssl.OP_B):
            return True
        if self.unset == ssl.OP_C or peer.mode == ssl.OP_D:
            return True
        match self.mode:
            case ssl.CERT_NONE:
                return False
        return cls.mode != ssl.OP_E


def free(self):
    return self.mode == ssl.OP_F
`)
	field := `FIELD=self.mode,VALUE=ssl.CERT_OPTIONAL,VALUE=ssl.CERT_REQUIRED,VALUE=CERT_NONE,VALUE="none"`
	want := map[string][]string{
		"Policy.strict": {
			"35:25-42 ssl.CERT_REQUIRED compare [self.mode " + field + "]",
			"37:29-37 ssl.OP_A in [(self.level) FIELD=self.level,VALUE=3]",
			"37:39-47 ssl.OP_B in [(self.level) FIELD=self.level,VALUE=3]",
			"39:26-34 ssl.OP_C compare [self.unset ]",
			"39:51-59 ssl.OP_D compare [peer.mode ]",
			"42:18-31 ssl.CERT_NONE case [self.mode " + field + "]",
			"44:28-36 ssl.OP_E compare [cls.mode " + strings.Replace(field, "self.mode", "cls.mode", 1) + "]",
		},
		"Policy.Inner.check": {"29:33-41 ssl.OP_G compare [self.mode FIELD=self.mode,VALUE=ssl.OP_NO_TLSv1]"},
		"Policy.shadowing":   {"32:29-37 ssl.OP_H compare [self.mode " + field + "]"},
		"free":               {"48:25-33 ssl.OP_F compare [self.mode ]"},
	}
	got := map[string][]string{}
	for name, refs := range pythonRefsOfDeep(analysis) {
		if name != "Policy.<init>" && name != "Policy.relaxed" && name != "Policy.<clinit>" && name != "Policy.Inner.<clinit>" && name != "helper" && name != "Policy.helper" {
			got[name] = refs
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("compared fields:\n got %q\nwant %q", got, want)
	}
}

// pythonRefsOfDeep is pythonRefsOf with each operand source's own sources.
func pythonRefsOfDeep(analysis *FileAnalysis) map[string][]string {
	out := map[string][]string{}
	for _, fn := range analysis.Functions {
		for _, ref := range fn.ConstantRefs {
			s := fmt.Sprintf("%d:%d-%d %s %s", ref.Line, ref.StartCol, ref.EndCol, ref.Text, ref.Context)
			if ref.Operand != nil {
				var values []string
				for _, node := range ref.Operand.Sources {
					values = append(values, node.Type+"="+node.Name+node.Value)
					for _, child := range node.SourceNodes {
						values = append(values, child.Type+"="+child.Name+child.Value)
					}
				}
				s += " [" + ref.Operand.Text + " " + strings.Join(values, ",") + "]"
			}
			key := fn.ID.Name
			if fn.ID.Type != "" {
				key = fn.ID.Type + "." + key
			}
			out[key] = append(out[key], s)
		}
	}
	return out
}
