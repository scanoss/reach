// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"
)

// A local built from a class that declares no method of its own is typed
// with that class, and its calls reach the methods it inherits: from the
// module, from a from-import, and through another module's import.
func TestBuilder_PythonLocalOfAMethodlessClass(t *testing.T) {
	t.Parallel()
	graph := buildTypedPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/base.py": `class Base:
    def run(self, data):
        return data


class Quiet(Base):
    pass
`,
		"app/views.py": "from app.base import Quiet\n",
		"app/m.py": `from app.base import Base, Quiet
from app import views


class Fast(Base):
    pass


def same_module(data):
    fast = Fast()
    return fast.run(data)


def imported(data):
    quiet = Quiet()
    return quiet.run(data)


def through_other_module(data):
    quiet = views.Quiet()
    return quiet.run(data)
`,
	})
	const run = "probe.app.base.(Base).run"
	for _, c := range []struct{ caller, want string }{
		{"same_module", "probe.app.m.(Fast).run"},
		{"imported", "probe.app.base.(Quiet).run"},
		{"through_other_module", "probe.app.views.(Quiet).run"},
	} {
		caller := "probe.app.m." + c.caller
		raw := "fast.run"
		if c.caller != "same_module" {
			raw = "quiet.run"
		}
		if got, untyped := pythonCallee(t, graph, caller, raw, "data"); untyped || got != c.want {
			t.Errorf("%s: %s = %s (untyped %v), want %s", c.caller, raw, got, untyped, c.want)
		}
		if !slices.Contains(graph.Callers[run], caller) {
			t.Errorf("no edge %s -> %s", caller, run)
		}
	}
}
