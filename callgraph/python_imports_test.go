// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Every binding of every import statement is recorded in source order, with
// its module (relative ones resolved against the file's package), the name
// a from-import takes, the alias, and whether it sits in a function or class
// body. Imports in module-level blocks are module-level.
func TestPythonParser_RecordsImports(t *testing.T) {
	t.Parallel()
	graph := buildPythonTree(t, map[string]string{
		"pkg/__init__.py": "",
		"pkg/sub/__init__.py": `import hashlib
import a.b
import a.b as z, os
from x import y
from x import y as w, v
from . import sib
from .core import Signer
from ..top import t
from ....too.far import q
from x import *
try:
    import fast as crypto
except ImportError:
    import slow as crypto
if TYPE_CHECKING:
    from typing import Any


def f():
    import inner
    from x import late as lt
    return inner.go(lt)


class C:
    from x import attr
`,
	}, "")
	var got []PythonImport
	for path, imports := range graph.PythonImports {
		if strings.HasSuffix(filepath.ToSlash(path), "pkg/sub/__init__.py") {
			got = imports
		}
	}
	want := []PythonImport{
		{Line: 1, Module: "hashlib"},
		{Line: 2, Module: "a.b"},
		{Line: 3, Module: "a.b", Alias: "z"},
		{Line: 3, Module: "os"},
		{Line: 4, Module: "x", Name: "y"},
		{Line: 5, Module: "x", Name: "y", Alias: "w"},
		{Line: 5, Module: "x", Name: "v"},
		{Line: 6, Module: "pkg.sub", Name: "sib"},
		{Line: 7, Module: "pkg.sub.core", Name: "Signer"},
		{Line: 8, Module: "pkg.top", Name: "t"},
		{Line: 10, Module: "x", Name: "*"},
		{Line: 12, Module: "fast", Alias: "crypto"},
		{Line: 14, Module: "slow", Alias: "crypto"},
		{Line: 16, Module: "typing", Name: "Any"},
		{Line: 20, Module: "inner", Local: true},
		{Line: 21, Module: "x", Name: "late", Alias: "lt", Local: true},
		{Line: 26, Module: "x", Name: "attr", Local: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("imports\n got %+v\nwant %+v", got, want)
	}
}

// A project parsed under a root module keys its own modules under it, and
// its imports name them the same way; a dependency's module keeps its
// spelling. A file outside the project (a dependency's source) records no
// imports.
func TestBuilder_PythonImportsQualifiedLikeCalls(t *testing.T) {
	t.Parallel()
	root := writePythonTree(t, map[string]string{
		"app/__init__.py": "",
		"app/digest.py":   "import hashlib\n",
		"main.py":         "from app.digest import digest\nimport app.digest as d\nimport jwt\n",
	})
	dep := writePythonTree(t, map[string]string{"jwt/__init__.py": "from .api_jwt import encode\n"})
	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "probe"}, {Dir: dep, Version: "2.13.0"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	var got []PythonImport
	for path, imports := range graph.PythonImports {
		switch {
		case filepath.Base(path) == "main.py":
			got = imports
		case strings.HasPrefix(path, dep):
			t.Errorf("dependency file %s records imports %+v", path, imports)
		}
	}
	want := []PythonImport{
		{Line: 1, Module: "probe.app.digest", Name: "digest"},
		{Line: 2, Module: "probe.app.digest", Alias: "d"},
		{Line: 3, Module: "jwt"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("imports\n got %+v\nwant %+v", got, want)
	}
}
