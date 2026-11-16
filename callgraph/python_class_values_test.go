// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"
)

// A class handed around as a value (stored in a table, passed, returned,
// raised, assigned) gets a name_only edge from the function that reads it to
// the class object `pkg.(K).<class>`; a class only tested, caught or
// annotated gets none, nor does a name in a stub.
func TestBuilder_PythonClassValueEdges(t *testing.T) {
	t.Parallel()

	graph := buildPythonTree(t, map[string]string{
		"reg/__init__.py": "",
		"reg/other.py":    "class Other:\n    pass\n",
		"reg/algs.py": "from cryptography.hazmat.primitives.ciphers import modes\nfrom reg.other import Other\nfrom reg.other import helper\n" +
			"class A:\n    def sign(self):\n        return 1\n" +
			"class B:\n    pass\n" +
			"TABLE = {'a': A}\n" +
			"def run():\n    register(Other)\n    return modes.CBC\n" +
			"class C(B):\n    pass\n" +
			"@register(B)\ndef decorated():\n    return 1\n" +
			"def check(x):\n    if isinstance(x, B):\n        raise Other\n    try:\n        pass\n    except A:\n        pass\n    y: B = None\n    register(helper)\n    return x\n",
		"reg/stub.pyi": "from reg.algs import A\nT = [A]\n",
	}, "")

	callers := func(callee string) []string {
		out := slices.Clone(graph.Callers[callee])
		slices.Sort(out)
		return out
	}
	for callee, want := range map[string][]string{
		"reg.algs.(A).<class>":                                       {"reg.algs.<module>"},
		"reg.other.(Other).<class>":                                  {"reg.algs.check", "reg.algs.run"},
		"cryptography.hazmat.primitives.ciphers.modes.(CBC).<class>": {"reg.algs.run"},
		"reg.algs.(B).<class>":                                       nil, // only tested and annotated
		"reg.other.(helper).<class>":                                 nil, // a function, spelled as one
	} {
		if got := callers(callee); !slices.Equal(got, want) {
			t.Errorf("callers of %s = %v, want %v", callee, got, want)
		}
	}
	for key, res := range graph.EdgeResolutions {
		if _, callee, ok := EdgeResolutionEndpoints(key, res); ok && callee == "reg.other.(Other).<class>" && res.Kind != EdgeKindNameOnly {
			t.Errorf("class value edge %q is %s, want name_only", key, res.Kind)
		}
	}
}
