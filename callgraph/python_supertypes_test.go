// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"reflect"
	"testing"
)

// Every class a Python file declares has a Supertypes entry: its bases
// resolved through the class scopes, the module, its imports and the
// builtins, the way Python looks the names up.
func TestPythonParser_SupertypesResolveBases(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import abc
import cryptography.hazmat.primitives.asymmetric.rsa
import typing as t
from typing import Generic, TypeVar
from cryptography.hazmat.primitives import hashes
from jwt.algorithms import Algorithm as JwtAlgorithm
from .base import LocalBase
from star import *

T = TypeVar("T")


class Plain:
    pass


class FromObject(object):
    pass


class Signer(JwtAlgorithm, abc.ABC, metaclass=abc.ABCMeta):
    pass


class Keyed(cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey):
    pass


class Hashing(hashes.HashAlgorithm, Generic[T]):
    pass


class Local(Plain, LocalBase):
    pass


class Failure(ValueError):
    pass


class FromStar(StarBase):
    pass


class Aliased(t.Protocol):
    pass


if True:
    class InBlock(Signer):
        pass


class Outer:
    class Inner:
        pass

    class Sibling(Inner):
        class Deep(Inner):
            pass

    class Shadow(Plain):
        pass
`)
	want := map[string][]string{
		"consumer.app.Plain":              {},
		"consumer.app.FromObject":         {},
		"consumer.app.Signer":             {"jwt.algorithms.Algorithm", "abc.ABC"},
		"consumer.app.Keyed":              {"cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey"},
		"consumer.app.Hashing":            {"cryptography.hazmat.primitives.hashes.HashAlgorithm"},
		"consumer.app.Local":              {"consumer.app.Plain", "consumer.base.LocalBase"},
		"consumer.app.Failure":            {"builtins.ValueError"},
		"consumer.app.FromStar":           {"consumer.app.StarBase"},
		"consumer.app.Aliased":            {"typing.Protocol"},
		"consumer.app.InBlock":            {"consumer.app.Signer"},
		"consumer.app.Outer":              {},
		"consumer.app.Outer.Inner":        {},
		"consumer.app.Outer.Sibling":      {"consumer.app.Outer.Inner"},
		"consumer.app.Outer.Sibling.Deep": {"consumer.app.Outer.Inner"},
		"consumer.app.Outer.Shadow":       {"consumer.app.Plain"},
	}
	if !reflect.DeepEqual(analysis.Supertypes, want) {
		for owner, bases := range want {
			if got, ok := analysis.Supertypes[owner]; !ok || !reflect.DeepEqual(got, bases) {
				t.Errorf("Supertypes[%s] = %v (present %v), want %v", owner, got, ok, bases)
			}
		}
		for owner, got := range analysis.Supertypes {
			if _, ok := want[owner]; !ok {
				t.Errorf("unexpected Supertypes[%s] = %v", owner, got)
			}
		}
	}
}

// A project's bases are keyed the way the graph keys its modules, and the
// graph exports them: a fragment's supertypes are what the stitch builds the
// cross-component hierarchy from.
func TestBuilder_PythonSupertypesQualifiedAndExported(t *testing.T) {
	t.Parallel()
	graph := buildPythonProject(t, map[string]string{
		"app/__init__.py": "",
		"app/base.py":     "class Base:\n    def sign(self):\n        return 1\n",
		"app/leaf.py":     "import hashlib\nfrom app.base import Base\n\n\nclass Leaf(Base, hashlib.Hash):\n    pass\n",
	})
	got := graph.ExportSupertypes()
	want := map[string][]string{
		"probe.app.base.Base": {},
		"probe.app.leaf.Leaf": {"probe.app.base.Base", "hashlib.Hash"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("ExportSupertypes() = %v, want %v", got, want)
	}
}
