// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func parseNodeSource(t testing.TB, src string) *FileAnalysis {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "lib.js"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewNodeParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	return analyses[0]
}

func nodeCallNames(fn *FunctionDecl) []string {
	names := make([]string, 0, len(fn.Calls))
	for i := range fn.Calls {
		names = append(names, fn.Calls[i].Callee.Name)
	}
	sort.Strings(names)
	return names
}

// A CommonJS module declares its functions by assignment, and an anonymous
// callback is a function of its own, named by where it starts.
func TestNodeParser_AssignedFunctionsAndCallbacks(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, `var crypto = require('crypto');

var hash = exports.hash = function (data) {
  return crypto.createHash('sha256').update(data).digest('hex');
};

module.exports.sign = function (data, key) {
  return new Promise(function (resolve) {
    var signer = crypto.createSign('SHA256');
    signer.update(data);
    resolve(signer.sign(key));
  });
};

Hasher.prototype.run = (data) => [data].map((d) => crypto.randomBytes(d));

function Hasher() {}
`)
	byID := map[string]*FunctionDecl{}
	for i := range analysis.Functions {
		byID[analysis.Functions[i].ID.String()] = &analysis.Functions[i]
	}
	for id, want := range map[string][]string{
		"app/lib.hash":              {"createHash", "digest", "update"},
		"app/lib.sign":              nil,
		"app/lib.<anonymous>@8:22":  {"createSign", "resolve", "sign", "update"},
		"app/lib.(Hasher).run":      {"map"},
		"app/lib.<anonymous>@15:45": {"randomBytes"},
	} {
		fn := byID[id]
		if fn == nil {
			t.Errorf("no declaration %s; got %v", id, nodeDeclIDs(byID))
			continue
		}
		if got := nodeCallNames(fn); !equalStrings(got, want) {
			t.Errorf("%s calls = %v, want %v", id, got, want)
		}
	}
	if sign := byID["app/lib.<anonymous>@8:22"]; sign != nil {
		for i := range sign.Calls {
			if call := &sign.Calls[i]; call.Callee.Name == "update" && call.ReceiverVar != "signer" {
				t.Errorf("signer.update ReceiverVar = %q, want signer", call.ReceiverVar)
			}
		}
	}
	// Nothing runs at module scope but the require, so there is no <module>.
	if fn := byID["app/lib."+moduleInitMethodName]; fn != nil {
		t.Errorf("unexpected %s with calls %v", moduleInitMethodName, nodeCallNames(fn))
	}
}

// Module-scope calls belong to a synthetic <module> declaration, and a call on
// a variable the module declares records that variable as its receiver.
func TestNodeParser_ModuleScope(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, `const EC = require('elliptic').ec;
const ec = new EC('secp256k1');

function sign(msg) {
  return ec.sign(msg);
}
`)
	var module, sign *FunctionDecl
	for i := range analysis.Functions {
		switch analysis.Functions[i].ID.Name {
		case moduleInitMethodName:
			module = &analysis.Functions[i]
		case "sign":
			sign = &analysis.Functions[i]
		}
	}
	if module == nil || len(module.Calls) != 1 || module.Calls[0].Callee.String() != "elliptic.(ec).<init>" || module.Calls[0].AssignedVar != "ec" {
		t.Fatalf("module declaration = %+v, want one elliptic.ec constructor call bound to ec", module)
	}
	if module.FunctionType != functionTypeModuleInit || module.StartLine != 1 {
		t.Errorf("module declaration type %q from line %d", module.FunctionType, module.StartLine)
	}
	if sign == nil || len(sign.Calls) != 1 || sign.Calls[0].ReceiverVar != "ec" {
		t.Fatalf("sign = %+v, want one call on the module's ec", sign)
	}
}

func nodeDeclIDs(m map[string]*FunctionDecl) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// A class assigned to the exports declares its methods under its own name, or,
// when anonymous, under the name it is exported as.
func TestNodeParser_ClassAssignedToExports(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, "module.exports = class CryptographyKey {\n  constructor(buf) {}\n  getBuffer() {}\n};\nexports.Signer = class {\n  sign() {}\n};\n")
	got := map[string]bool{}
	for _, fn := range analysis.Functions {
		got[fn.OwnerName+"."+fn.ID.Name] = true
	}
	for _, want := range []string{"CryptographyKey.constructor", "CryptographyKey.getBuffer", "Signer.sign"} {
		if !got[want] {
			t.Errorf("%s not declared; got %v", want, got)
		}
	}
}

// A callback or a function declared inside a class method, a class field or
// the value of a destructuring declaration is a function of its own, as one in
// a top-level function is: its calls are in the graph, under it.
func TestNodeParser_FunctionsNestedInClassesAndDestructuringsAreDeclared(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, `const crypto_1 = require('crypto');
class T {
  h(xs) { return xs.map((p) => crypto_1.createHash('sha1').update(p).digest()); }
  run() { function inner() { return crypto_1.randomBytes(4); } return inner(); }
  field = (x) => crypto_1.createHmac('sha256', x);
  static make = function () { return crypto_1.createSign('RSA-SHA256'); };
}
{
  const { server } = setup({ verify: check((key) => crypto_1.createVerify('RSA-SHA256')) });
}
`)
	found := make(map[string]string)
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		for _, call := range fn.Calls {
			if call.Callee.Package == "crypto" {
				found[call.Callee.Name] = fn.ID.Name
			}
		}
	}
	want := map[string]string{
		"createHash":   "<anonymous>@3:25",
		"randomBytes":  "inner",
		"createHmac":   "<anonymous>@5:11",
		"createSign":   "<anonymous>@6:17",
		"createVerify": "<anonymous>@9:44",
	}
	for callee, fn := range want {
		if found[callee] != fn {
			t.Errorf("crypto.%s: called from %q, want %q", callee, found[callee], fn)
		}
	}
}

// A call in a default parameter value is a call of the function, which
// evaluates it on each call that omits the argument.
func TestNodeParser_DefaultParameterCallsBelongToTheFunction(t *testing.T) {
	t.Parallel()

	analysis := parseNodeSource(t, `const crypto = require('crypto');
function sign(message, key, aux = crypto.randomBytes(32)) { return aux; }
const wrap = async (alg, { salt = crypto.randomBytes(16) } = {}) => salt;
`)
	found := make(map[string][]string)
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		for _, call := range fn.Calls {
			found[fn.ID.Name] = append(found[fn.ID.Name], call.Callee.String())
		}
	}
	for _, name := range []string{"sign", "wrap"} {
		if got := found[name]; len(got) != 1 || got[0] != "crypto.randomBytes" {
			t.Errorf("%s calls %q, want [crypto.randomBytes]", name, got)
		}
	}
}
