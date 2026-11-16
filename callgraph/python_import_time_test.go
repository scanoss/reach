// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"
)

// Importing a module runs its top level and its packages': the importer's
// <module> (or the function holding the import) calls each module's
// <module>, and <module> calls the <clinit> of each class it defines.
func TestBuilder_PythonImportTimeEdges(t *testing.T) {
	t.Parallel()

	graph := buildPythonTree(t, map[string]string{
		"pkg/__init__.py": "from .core import Signer\nfrom . import tables\nimport dep.algorithms\nimport hashlib\n",
		"pkg/core.py": "import hashlib\nfrom typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    from pkg.typed import T\n" +
			"class Signer:\n    DIGEST = hashlib.sha256(b'x')\n    class Inner:\n        D = hashlib.md5(b'y')\n" +
			"    def sign(self):\n        import pkg.lazy\n        return 1\n",
		"pkg/tables.py": "from pkg.algs import A\nTABLE = {'a': A()}\n",
		"pkg/algs.py":   "class A:\n    def sign(self):\n        return 1\n",
		"pkg/typed.py":  "import os\nos.urandom(1)\n",
		"pkg/lazy.py":   "import os\nos.urandom(2)\n",
		"pkg/stub.pyi":  "import pkg.lazy\nclass S:\n    X = make()\n",
	}, "")

	callers := func(callee string) []string {
		out := slices.Clone(graph.Callers[callee])
		slices.Sort(out)
		return out
	}
	for callee, want := range map[string][]string{
		"pkg.core.<module>":                {"pkg.<module>"},
		"pkg.tables.<module>":              {"pkg.<module>"},
		"pkg.lazy.<module>":                {"pkg.core.(Signer).sign"},
		"pkg.core.(Signer).<clinit>":       {"pkg.core.<module>"},
		"pkg.core.(Signer.Inner).<clinit>": {"pkg.core.(Signer).<clinit>"},
		"pkg.<module>":                     {"pkg.core.(Signer).sign", "pkg.tables.<module>"},
		"dep.<module>":                     {"pkg.<module>"},
		"dep.algorithms.<module>":          {"pkg.<module>"},
		"pkg.typed.<module>":               nil, // under TYPE_CHECKING
		"hashlib.<module>":                 nil, // standard library
		"pkg.algs.<module>":                nil, // declares no top-level code
		"pkg.algs.A.<module>":              nil, // a name, not a module
		"pkg.core.Signer.<module>":         nil,
		"pkg.stub.(S).<clinit>":            nil, // a stub never runs
	} {
		if got := callers(callee); !slices.Equal(got, want) {
			t.Errorf("callers of %s = %v, want %v", callee, got, want)
		}
	}
	if _, ok := graph.Functions["pkg.<module>"]; !ok {
		t.Fatal("an import-only __init__.py has no <module> to hold its imports")
	}
}
