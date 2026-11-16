// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"
)

// A comment inside an argument list is not part of any argument: the
// arguments are the list's argument nodes, a comment with a comma or a quote
// splits nothing, and the argument sources stay index-parallel. A list
// without comments keeps the text split.
func TestPythonParser_ArgumentsAroundComments(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import hashlib


def f(pool, request, salt):
    pool.urlopen(
        method=request.method,  # type: ignore[arg-type]  # a, "b
        url="u",
        # retries, timeout
        body=b"x",
    )
    return hashlib.pbkdf2_hmac("sha256", b"pw", salt, 1000)  # n, m
`)
	want := map[string][]string{
		"pool.urlopen":        {"method=request.method", `url="u"`, `body=b"x"`},
		"hashlib.pbkdf2_hmac": {`"sha256"`, `b"pw"`, "salt", "1000"},
	}
	for _, fn := range analysis.Functions {
		for _, call := range fn.Calls {
			args, ok := want[call.Raw]
			if !ok {
				continue
			}
			delete(want, call.Raw)
			if !slices.Equal(call.Arguments, args) {
				t.Errorf("%s arguments %q, want %q", call.Raw, call.Arguments, args)
			}
			if len(call.ArgumentSources) != len(call.Arguments) {
				t.Errorf("%s: %d argument sources for %d arguments", call.Raw, len(call.ArgumentSources), len(call.Arguments))
			}
		}
	}
	for raw := range want {
		t.Errorf("no call %s", raw)
	}
}

// A generator expression passed without parentheses of its own is the call's
// one argument, commas of its targets included, with one argument source.
func TestPythonParser_GeneratorArgument(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `def f(users, items):
    users.update(k for k, _ in items)
    return users.get(1)
`)
	want := map[string][]string{
		"users.update": {"k for k, _ in items"},
		"users.get":    {"1"},
	}
	for _, fn := range analysis.Functions {
		for _, call := range fn.Calls {
			args, ok := want[call.Raw]
			if !ok {
				continue
			}
			delete(want, call.Raw)
			if !slices.Equal(call.Arguments, args) {
				t.Errorf("%s arguments %q, want %q", call.Raw, call.Arguments, args)
			}
			if len(call.ArgumentSources) != len(call.Arguments) {
				t.Errorf("%s: %d argument sources for %d arguments", call.Raw, len(call.ArgumentSources), len(call.Arguments))
			}
		}
	}
	for raw := range want {
		t.Errorf("no call %s", raw)
	}
}
