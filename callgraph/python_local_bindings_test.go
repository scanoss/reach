// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"reflect"
	"testing"
)

// pythonBindingsOf lists a parsed file's local bindings by function name as
// "name line:col effect line:col block line:col loop line:col" strings.
func pythonBindingsOf(analysis *FileAnalysis) map[string][]string {
	out := map[string][]string{}
	for _, fn := range analysis.Functions {
		for _, b := range fn.LocalBindings {
			key := fn.ID.Name
			if fn.ID.Type != "" {
				key = fn.ID.Type + "." + key
			}
			out[key] = append(out[key], fmt.Sprintf("%s %d:%d effect %d:%d block %d:%d loop %d:%d", b.Name, b.Line, b.Col,
				b.EffectLine, b.EffectCol, b.BlockEndLine, b.BlockEndCol, b.LoopLine, b.LoopCol))
		}
	}
	return out
}

// A name a function binds more than once with a call among the values gets
// each binding with where it takes effect, the block that always runs it
// and the outermost loop around it (E2.7-py.14b gap 2). A name bound once,
// or never to a call, gets none; neither does a name a global or nonlocal
// statement names. A with item, a for loop's target, an except clause's
// name, del, an import and a nested def bind too; an augmented assignment
// and an assignment expression count without a binding of their own.
func TestPythonLocalBindings(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `from M2Crypto import EVP

e = EVP.Cipher("aes_128_cbc", k, iv, 1)
e.update(x)
e = EVP.Cipher("bf_cbc", k, iv, 1)


def straight(x, k, iv, c):
    once = make()
    e = EVP.Cipher("aes_128_cbc", k, iv, 1)
    if c:
        e = EVP.Cipher("bf_cbc", k, iv, 1)
    for item in x:
        e.update(item)
        e = other
    a = b = make()
    b = None
    with open_it() as w:
        w = make()
    del w
    s = 1
    s = 2


def parameter(k):
    k = make(k)


def bound_elsewhere(c):
    g = make()
    g = make()
    global g


def exceptions():
    try:
        err = make()
    except ValueError as err:
        pass
    err += 1


def defs():
    f = make()

    def f():
        pass
    import os as f
    for f in items():
        pass


class Holder:
    h = make()
    h = make()
`)
	got := pythonBindingsOf(analysis)
	want := map[string][]string{
		"<module>": {
			"e 3:1 effect 3:40 block 56:1 loop 0:0",
			"e 5:1 effect 5:35 block 56:1 loop 0:0",
		},
		"straight": {
			"e 10:5 effect 10:44 block 22:10 loop 0:0",
			"e 12:9 effect 12:43 block 12:43 loop 0:0",
			"e 15:9 effect 15:18 block 15:18 loop 13:5",
			"b 16:5 effect 16:19 block 22:10 loop 0:0",
			"b 17:5 effect 17:13 block 22:10 loop 0:0",
			"w 18:10 effect 18:24 block 22:10 loop 0:0",
			"w 19:9 effect 19:19 block 19:19 loop 0:0",
			"w 20:5 effect 20:10 block 22:10 loop 0:0",
		},
		"parameter": {"k 26:5 effect 26:16 block 26:16 loop 0:0"},
		"exceptions": {
			"err 37:9 effect 37:21 block 37:21 loop 0:0",
			"err 38:5 effect 39:9 block 39:13 loop 0:0",
		},
		"defs": {
			"f 44:5 effect 44:15 block 50:13 loop 0:0",
			"f 46:5 effect 47:13 block 50:13 loop 0:0",
			"f 48:5 effect 48:19 block 50:13 loop 0:0",
			"f 49:5 effect 50:9 block 50:13 loop 49:5",
		},
		"Holder.<clinit>": {
			"h 54:5 effect 54:15 block 55:15 loop 0:0",
			"h 55:5 effect 55:15 block 55:15 loop 0:0",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("local bindings\n got %v\nwant %v", got, want)
	}
}

// Every name of a tuple or list pattern assigned a call is a binding with
// its element and the call's position, also a name bound once; a name after
// a starred target or in a nested pattern holds no fixed element and is not
// listed (E2.7-py.14b gap 4).
func TestPythonLocalBindingsUnpacked(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import rsa


def f(xs):
    pub, priv = rsa.newkeys(2048)
    (a, _) = make()
    [b, *rest, c] = make()
    d, (e, g) = make()
    h, i = 1, 2
`)
	var got []string
	for _, fn := range analysis.Functions {
		for _, b := range fn.LocalBindings {
			if b.Unpacked {
				got = append(got, fmt.Sprintf("%s %d:%d element %d value %d:%d", b.Name, b.Line, b.Col, b.Element, b.ValueLine, b.ValueCol))
			}
		}
	}
	want := []string{
		"priv 5:5 element 1 value 5:17",
		"pub 5:5 element 0 value 5:17",
		"_ 6:5 element 1 value 6:14",
		"a 6:5 element 0 value 6:14",
		"b 7:5 element 0 value 7:21",
		"d 8:5 element 0 value 8:17",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unpacked bindings\n got %v\nwant %v", got, want)
	}
}

// A parameter the body rebinds counts as a binding with a call among the
// values (the caller's), so its rebindings are listed even when none of them
// is a call: a reader then knows the caller's value no longer reaches a use
// after them (E2.7-py.14b gap 5).
func TestPythonLocalBindingsRebindParameter(t *testing.T) {
	t.Parallel()
	got := pythonBindingsOf(parsePythonSource(t, `def f(acct, flag):
    if flag:
        acct = None
    acct.sign()


def g(acct):
    return acct.sign()
`))
	want := map[string][]string{"f": {"acct 3:9 effect 3:20 block 3:20 loop 0:0"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("local bindings %v, want %v", got, want)
	}
}
