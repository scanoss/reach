// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"sort"
	"testing"
)

// A builtin call is not a call of the module: `len(x)` was keyed
// `<module>.len`. A name the module or the function rebinds keeps its call,
// and a builtin that calls a function argument still registers the callback.
func TestPythonParser_BuiltinCallsNotExported(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import hashlib
from codecs import open
from helpers import *

hash = hashlib.sha256


class Failure(ValueError):
    pass


def format(value):
    return str(value)


def work(data, input):
    if not isinstance(data, bytes) or len(data) == 0:
        raise ValueError("empty")
    print(repr(data))
    sorted([data], key=format)
    hash(data)
    open("f")
    input()
    Failure("x")
    format(data)
    from_star(data)

    def max(a):
        return a
    return max(data)


def method_like(self):
    return self.len()


def annotated(data: bytes) -> bytes:
    return bytes(data)
`)
	var work *FunctionDecl
	for i := range analysis.Functions {
		if analysis.Functions[i].ID.Name == "work" {
			work = &analysis.Functions[i]
		}
	}
	if work == nil {
		t.Fatal("work not found")
	}
	for i := range analysis.Functions {
		if fn := &analysis.Functions[i]; fn.ID.Name == "method_like" && (len(fn.Calls) != 1 || fn.Calls[0].Raw != "self.len") {
			t.Errorf("self.len() is an attribute call, not the builtin; calls %+v", fn.Calls)
		}
		if fn := &analysis.Functions[i]; fn.ID.Name == "annotated" && len(fn.Calls) != 0 {
			t.Errorf("a parameter annotated bytes does not rebind bytes; calls %+v", fn.Calls)
		}
	}
	var got []string
	for _, call := range work.Calls {
		got = append(got, call.Callee.String())
	}
	sort.Strings(got)
	want := []string{"codecs.open", "consumer.app.Failure", "consumer.app.format", "consumer.app.from_star", "consumer.app.hash", "consumer.app.input", "consumer.app.max"}
	if !slices.Equal(got, want) {
		t.Errorf("work's calls = %v, want %v", got, want)
	}
	var callbacks []string
	for _, ref := range work.ImplicitCalls {
		callbacks = append(callbacks, ref.Callee.String())
	}
	if !slices.Contains(callbacks, "consumer.app.format") {
		t.Errorf("sorted(key=format) still registers its callback; implicit calls %v", callbacks)
	}
}
