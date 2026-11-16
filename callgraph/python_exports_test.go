// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"reflect"
	"testing"
)

const (
	exportsInitSrc = `from .api import encode, Signer as PublicSigner, _private, _hidden_alias
from .core import *
from .open import *
from dep.impl import *
from dep.impl import thing as dep_thing, DepClass
from . import util
from pkg.absolute import absolute_fn
from pkg.Shadow import Shadow
from dep import thing
try:
    from .fast import impl
except ImportError:
    from .slow import impl
__all__ = ["encode", "_private", "PublicSigner"]
__all__ += ["extra", "_plus"]
__all__.extend(["more", "_ext"])
__all__.append("_appended")
extra = util.helper
more = util.helper
_appended = util.helper
_plus = util.helper
_ext = util.helper
_unlisted = util.helper
signer = PublicSigner()
signer_sign = signer.sign
made = util.helper()
made_sign = made.sign
try:
    from ._speedups import fast_helper
except ImportError:
    fast_helper = util.helper


def late():
    from .api import unbound as local_only
    return local_only
`
	exportsAPISrc = `import hashlib
import pkg
import pkg.util as u


class Signer:
    def __init__(self):
        self.k = 1

    def sign(self, d):
        return d


class Base:
    def base_m(self):
        return 1


class Child(Base):
    pass


TYPE: int


_obj = Signer()
encode = _obj.sign
_child = Child()
inherited = _child.base_m
unbound = Signer.sign
nested = Child.base_m
external = hashlib.sha256
_hidden_alias = Signer.sign


def _private():
    return 1


alias_fn = _private
via_pkg = pkg.util.helper
via_alias = u.helper
`
	exportsSubSrc = `from ..api import encode as enc
from pkg import PublicSigner
from ..open import *
from ..star_a import *
`
)

// A public name of a project module that names a declaration made elsewhere
// in the project maps to it: re-exports (relative, absolute, aliased, through
// a package), star imports (by __all__, else every name without an
// underscore), __all__ (which also makes an underscore name public), and
// module-level aliases of a function, of a method on a class, and of a bound
// method of a module-level instance (inherited methods through the MRO). A
// name bound to its own declaration, a module, an instance, an import inside
// a function, a dependency or a cycle maps to nothing.
func TestBuilder_PythonExports(t *testing.T) {
	t.Parallel()
	root := writePythonTree(t, map[string]string{
		"pkg/__init__.py":     exportsInitSrc,
		"pkg/api.py":          exportsAPISrc,
		"pkg/core.py":         "__all__ = (\"star_fn\", \"Kept\")\n\n\ndef star_fn():\n    return 1\n\n\ndef hidden():\n    return 2\n\n\nclass Kept:\n    def go(self):\n        return 1\n",
		"pkg/core.pyi":        "def star_fn() -> int: ...\n",
		"pkg/open.py":         "def visible():\n    return 1\n\n\ndef _hidden():\n    return 2\n\n\nclass Shown:\n    def go(self):\n        return 1\n\n\n_x = visible()\n",
		"pkg/util.py":         "try:\n    from ._c import helper, Fast\nexcept ImportError:\n    def helper():\n        return 1\n\n    class Fast:\n        def go(self):\n            return 1\n",
		"pkg/star_a.py":       "from .star_b import *\n\n\ndef in_a():\n    return 1\n",
		"pkg/star_b.py":       "from .star_a import *\n",
		"pkg/absolute.py":     "def absolute_fn():\n    return 1\n",
		"pkg/Shadow.py":       "class Shadow:\n    def go(self):\n        return 1\n",
		"pkg/slow.py":         "def impl():\n    return 1\n",
		"pkg/cyc_a.py":        "from .cyc_b import loop\n",
		"pkg/cyc_b.py":        "from .cyc_a import loop\n",
		"pkg/sub/__init__.py": exportsSubSrc,
	})
	dep := writePythonTree(t, map[string]string{
		"dep/__init__.py": "from .impl import thing\n",
		"dep/impl.py":     "def thing():\n    return 1\n\n\nclass DepClass:\n    def go(self):\n        return 1\n",
	})
	graph, err := NewBuilderForEcosystem("python", NewPythonParser()).
		BuildFromDirectories([]PackageDir{{Dir: root}, {Dir: dep, Version: "1.0"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	want := map[string]string{
		"pkg.encode":           "pkg.api.(Signer).sign",
		"pkg.PublicSigner":     "pkg.api.(Signer)",
		"pkg._private":         "pkg.api._private",
		"pkg.star_fn":          "pkg.core.star_fn",
		"pkg.visible":          "pkg.open.visible",
		"pkg.Shown":            "pkg.open.(Shown)",
		"pkg.Shadow":           "pkg.Shadow.(Shadow)",
		"pkg.absolute_fn":      "pkg.absolute.absolute_fn",
		"pkg.impl":             "pkg.slow.impl",
		"pkg.extra":            "pkg.util.helper",
		"pkg.more":             "pkg.util.helper",
		"pkg._appended":        "pkg.util.helper",
		"pkg._plus":            "pkg.util.helper",
		"pkg._ext":             "pkg.util.helper",
		"pkg.fast_helper":      "pkg.util.helper",
		"pkg.signer_sign":      "pkg.api.(Signer).sign",
		"pkg.Kept":             "pkg.core.(Kept)",
		"pkg.api.encode":       "pkg.api.(Signer).sign",
		"pkg.api.inherited":    "pkg.api.(Base).base_m",
		"pkg.api.unbound":      "pkg.api.(Signer).sign",
		"pkg.api.nested":       "pkg.api.(Base).base_m",
		"pkg.api.via_pkg":      "pkg.util.helper",
		"pkg.api.via_alias":    "pkg.util.helper",
		"pkg.api.alias_fn":     "pkg.api._private",
		"pkg.sub.enc":          "pkg.api.(Signer).sign",
		"pkg.sub.PublicSigner": "pkg.api.(Signer)",
		"pkg.sub.visible":      "pkg.open.visible",
		"pkg.sub.Shown":        "pkg.open.(Shown)",
		"pkg.sub.in_a":         "pkg.star_a.in_a",
		"pkg.star_b.in_a":      "pkg.star_a.in_a",
	}
	if !reflect.DeepEqual(graph.PythonExports, want) {
		for k, v := range graph.PythonExports {
			if want[k] != v {
				t.Errorf("unexpected export %s -> %s", k, v)
			}
		}
		for k, v := range want {
			if graph.PythonExports[k] != v {
				t.Errorf("missing export %s -> %s (got %q)", k, v, graph.PythonExports[k])
			}
		}
	}
}

// A builder reused for another build resolves that build's exports alone.
func TestBuilder_PythonExportsReusedBuilder(t *testing.T) {
	t.Parallel()
	builder := NewBuilderForEcosystem("python", NewPythonParser())
	first := writePythonTree(t, map[string]string{"a/__init__.py": "from .m import f\n", "a/m.py": "def f():\n    return 1\n"})
	second := writePythonTree(t, map[string]string{"b/__init__.py": "from .m import g\n", "b/m.py": "def g():\n    return 1\n"})
	if _, err := builder.BuildFromDirectories([]PackageDir{{Dir: first}}, nil); err != nil {
		t.Fatal(err)
	}
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: second}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string]string{"b.g": "b.m.g"}; !reflect.DeepEqual(graph.PythonExports, want) {
		t.Fatalf("exports %v, want %v", graph.PythonExports, want)
	}
}
