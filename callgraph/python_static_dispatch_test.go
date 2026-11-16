// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"
)

// A super() call and a class instantiation bind one declaration: neither
// fans out to the overrides of the callee's subclasses (siblings of the
// caller's class included). A self call, cls(...) and a method on a typed
// local keep their dispatch.
func TestBuilder_PythonSuperAndInstantiationDoNotDispatch(t *testing.T) {
	t.Parallel()
	graph := buildPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/m.py": `class Base:
    def __init__(self):
        self.n = 0

    def run(self):
        return self.step()

    def step(self):
        return 0

    @classmethod
    def make(cls):
        return cls()


class Fast(Base):
    def __init__(self):
        super().__init__()

    def step(self):
        return super().step()


class Slow(Base):
    def __init__(self):
        super().__init__()

    def step(self):
        return 2


def build():
    return Base()


def local():
    b = Base()
    return b.step()
`,
		"app/use.py": `from app.m import Base


def build():
    return Base()
`,
	})
	has := func(caller, callee string) bool { return slices.Contains(graph.Callers[callee], caller) }
	const (
		baseInit, fastInit, slowInit = "probe.app.m.(Base).<init>", "probe.app.m.(Fast).<init>", "probe.app.m.(Slow).<init>"
		baseStep, fastStep, slowStep = "probe.app.m.(Base).step", "probe.app.m.(Fast).step", "probe.app.m.(Slow).step"
	)
	for _, c := range []struct {
		caller, callee string
		want           bool
	}{
		{"probe.app.m.build", baseInit, true},
		{"probe.app.m.build", fastInit, false},
		{"probe.app.m.build", slowInit, false},
		{"probe.app.use.build", baseInit, true},
		{"probe.app.use.build", fastInit, false},
		{"probe.app.use.build", slowInit, false},
		{fastInit, baseInit, true},
		{fastInit, slowInit, false},
		{fastStep, baseStep, true},
		{fastStep, slowStep, false},
		{"probe.app.m.(Base).run", baseStep, true},
		{"probe.app.m.(Base).run", fastStep, true},
		{"probe.app.m.(Base).run", slowStep, true},
		{"probe.app.m.(Base).make", baseInit, true},
		{"probe.app.m.(Base).make", fastInit, true},
		{"probe.app.m.local", baseStep, true},
		{"probe.app.m.local", fastStep, true},
	} {
		if got := has(c.caller, c.callee); got != c.want {
			t.Errorf("edge %s -> %s = %v, want %v", c.caller, c.callee, got, c.want)
		}
	}
}
