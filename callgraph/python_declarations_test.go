// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"reflect"
	"testing"
)

func pythonFunctionKey(fn *FunctionDecl) string {
	if fn.ID.Type != "" {
		return fn.ID.Type + "." + fn.ID.Name
	}
	return fn.ID.Name
}

func TestPythonDeclarationsAndCasts(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import typing
from typing import cast, Optional
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT: Optional[rsa.RSAPrivateKey] = None


class Holder:
    key: rsa.RSAPrivateKey
    size: int = 2048

    def __init__(self, raw):
        self.pub: rsa.RSAPublicKey = cast(rsa.RSAPublicKey, load(raw))
        k: rsa.RSAPrivateKey = rsa.generate_private_key(65537, 2048)
        name: str = "x"
        label: "Label" = (
            "a"
        )
        other: Holder = raw
        t = typing.cast(  rsa.RSAPrivateKey , (load(raw)))
        u = cast(rsa.RSAPrivateKey, raw)
        v = other.cast(rsa.RSAPrivateKey, load(raw))
`)
	got := map[string][]string{}
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		for _, d := range fn.Declarations {
			got[pythonFunctionKey(fn)] = append(got[pythonFunctionKey(fn)], fmt.Sprintf("decl %d:%d-%d/%d %s %s %q", d.Line, d.StartCol, d.EndCol, d.EndLine, d.Type, d.Name, d.Init))
		}
		for _, c := range fn.Casts {
			got[pythonFunctionKey(fn)] = append(got[pythonFunctionKey(fn)], fmt.Sprintf("cast %d:%d-%d/%d %s inner %d:%d", c.Line, c.StartCol, c.EndCol, c.EndLine, c.Type, c.InnerLine, c.InnerCol))
		}
	}
	want := map[string][]string{
		"<module>":        {`decl 5:1-44/0 Optional[rsa.RSAPrivateKey] DEFAULT "null"`},
		"Holder.<clinit>": {`decl 9:5-27/0 rsa.RSAPrivateKey key ""`},
		"Holder.<init>": {
			`decl 13:9-71/0 rsa.RSAPublicKey self.pub "cast"`,
			`decl 14:9-69/0 rsa.RSAPrivateKey k "call"`,
			`decl 16:9-10/18 "Label" label "literal"`,
			`decl 19:9-28/0 Holder other "other"`,
			"cast 13:38-71/0 rsa.RSAPublicKey inner 13:61",
			"cast 20:13-59/0 rsa.RSAPrivateKey inner 20:48",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("declarations and casts:\n got %q\nwant %q", got, want)
	}
}

func TestPythonAbstractMethods(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import abc
import typing
from abc import abstractmethod
from typing import Protocol


class Hash(abc.ABC):
    @abstractmethod
    def update(self, data):
        self.check(data)

    @abc.abstractproperty
    def name(self):
        return "x"

    def digest(self):
        raise NotImplementedError("subclass")

    def copy(self):
        """Copy."""
        raise NotImplementedError

    def reset(self):
        pass

    def finalize(self):
        if self:
            raise NotImplementedError
        return 1

    @staticmethod
    def check(data):
        ...


class Signer(Protocol[int]):
    def sign(self, data):
        """Sign data."""
        ...

    def verify(self, data):
        return self.sign(data)

    def close(self):
        pass

    def fail(self):
        raise ValueError("no")


class Verifier(typing.Protocol):
    def check(self, sig):
        ...


def module_level():
    raise NotImplementedError
`)
	got := map[string]bool{}
	for i := range analysis.Functions {
		got[pythonFunctionKey(&analysis.Functions[i])] = analysis.Functions[i].Abstract
	}
	want := map[string]bool{
		"Hash.update": true, "Hash.name": true, "Hash.digest": true, "Hash.copy": true,
		"Hash.reset": false, "Hash.finalize": false, "Hash.check": false,
		"Signer.sign": true, "Signer.verify": false, "Signer.close": true, "Signer.fail": false,
		"Verifier.check": true, "module_level": false,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("abstract:\n got %v\nwant %v", got, want)
	}
}
