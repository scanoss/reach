// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/scanoss/reach/callgraph/contracts"
)

// nodePropertyReadsOf builds a project of the given files and returns the
// property reads the graph holds for name.
func nodePropertyReadsOf(t *testing.T, files map[string]string, name string) []NodePropertyRead {
	t.Helper()
	graph := buildNodeFiles(t, files)
	for path, reads := range graph.NodePropertyReads {
		if filepath.Base(path) == name {
			return reads
		}
	}
	return nil
}

func nodeReadRaws(reads []NodePropertyRead) []string {
	raws := make([]string, len(reads))
	for i := range reads {
		raws[i] = reads[i].Raw
	}
	return raws
}

func assertNodeReadRaws(t *testing.T, got []NodePropertyRead, want ...string) {
	t.Helper()
	raws := nodeReadRaws(got)
	if strings.Join(raws, "\n") != strings.Join(want, "\n") {
		t.Errorf("property reads:\n got  %q\n want %q", raws, want)
	}
}

// nodeCallTarget returns the target key of the call written raw in the graph.
func nodeCallTarget(t *testing.T, graph *CallGraph, raw string) string {
	t.Helper()
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			if fn.Calls[i].Raw == raw {
				return fn.Calls[i].Callee.String()
			}
		}
	}
	t.Fatalf("no call %q in the graph", raw)
	return ""
}

// A read is keyed exactly as a call of the same expression in the same place:
// each case is built twice, once reading the expression and once calling it,
// and the read's target must be the call's.
func TestNodePropertyReadKeyedAsTheCall(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		src    string // %s is where the expression is read or called
		expr   string
		target string
	}{
		{
			name:   "namespace import",
			src:    "import * as acme from 'acme-crypto';\nconst h = %s;\n",
			expr:   "acme.enums.hash.md5",
			target: "acme-crypto.enums.hash.md5",
		},
		{
			name:   "require",
			src:    "const acme = require('acme-crypto');\nconst m = %s;\n",
			expr:   "acme.mode.ECB",
			target: "acme-crypto.mode.ECB",
		},
		{
			name:   "inline require",
			src:    "const m = %s;\n",
			expr:   "require('acme-crypto').mode.ECB",
			target: "acme-crypto.mode.ECB",
		},
		{
			name:   "destructured require",
			src:    "const { mode } = require('acme-crypto');\nconst m = %s;\n",
			expr:   "mode.ECB",
			target: "acme-crypto.mode.ECB",
		},
		{
			// Without a KB entry for the imported class nothing types c, so
			// the call, and the read, stay caller-local; with one, the
			// contract pass types both (TestNodePropertyReadTypedByContract).
			name:   "instance of an imported class",
			src:    "import * as acme from 'acme-crypto';\nfunction print(p) {\n  const c = new acme.Cert(p);\n  return %s;\n}\n",
			expr:   "c.fingerprint",
			target: "app/mod.fingerprint",
		},
		{
			name:   "instance of a project class",
			src:    "class Cert { constructor(p) { this.p = p; } }\nfunction print(p) {\n  const c = new Cert(p);\n  return %s;\n}\n",
			expr:   "c.fingerprint",
			target: "app/mod.(Cert).fingerprint",
		},
		{
			name:   "read on a new expression",
			src:    "class Cert { constructor(p) { this.p = p; } }\nfunction print(p) {\n  return %s;\n}\n",
			expr:   "new Cert(p).fingerprint",
			target: "app/mod.(Cert).fingerprint",
		},
		{
			name:   "read on a new expression of an imported class",
			src:    "import * as acme from 'acme-crypto';\nfunction print(p) {\n  return %s;\n}\n",
			expr:   "new acme.Cert(p).fingerprint",
			target: "app/mod.fingerprint",
		},
		{
			name:   "global crypto object",
			src:    "function keys() {\n  return %s;\n}\n",
			expr:   "crypto.subtle.keyFormats",
			target: "(SubtleCrypto).keyFormats",
		},
		{
			name:   "unresolved receiver stays caller-local",
			src:    "function print(cipher) {\n  return %s;\n}\n",
			expr:   "cipher.mode.tag",
			target: "app/mod.tag",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reads := nodePropertyReadsOf(t, map[string]string{"mod.js": strings.Replace(tc.src, "%s", tc.expr, 1)}, "mod.js")
			if len(reads) != 1 || reads[0].Raw != tc.expr {
				t.Fatalf("reads = %+v, want the one read %q", reads, tc.expr)
			}
			called := buildNodeFiles(t, map[string]string{"mod.js": strings.Replace(tc.src, "%s", tc.expr+"()", 1)})
			if callTarget := nodeCallTarget(t, called, tc.expr); reads[0].TargetKey != callTarget {
				t.Errorf("read target = %q, the call %s() targets %q", reads[0].TargetKey, tc.expr, callTarget)
			}
			if reads[0].TargetKey != tc.target {
				t.Errorf("read target = %q, want %q", reads[0].TargetKey, tc.target)
			}
			if want := tc.expr[strings.LastIndex(tc.expr, ".")+1:]; reads[0].MethodName != want {
				t.Errorf("method name = %q, want %q", reads[0].MethodName, want)
			}
		})
	}
}

func TestNodePropertyReadReceiverAndAssignedVar(t *testing.T) {
	t.Parallel()

	src := "import * as acme from 'acme-crypto';\n" +
		"const x = acme.mode.ECB;\n" +
		"let y;\n" +
		"y = acme.mode.CBC;\n" +
		"function print(p) {\n" +
		"  const c = new acme.Cert(p);\n" +
		"  const fp = c.fingerprint;\n" +
		"  return fp;\n" +
		"}\n"
	reads := nodePropertyReadsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeReadRaws(t, reads, "acme.mode.ECB", "acme.mode.CBC", "c.fingerprint")
	if len(reads) != 3 {
		return
	}
	if reads[0].AssignedVar != "x" || reads[0].ReceiverVar != "" || reads[0].CallerKey != moduleKeyOf("app/mod") {
		t.Errorf("const read = %+v, want assigned x, no receiver, module caller", reads[0])
	}
	if reads[1].AssignedVar != "y" {
		t.Errorf("assigned read = %+v, want assigned y", reads[1])
	}
	if reads[2].ReceiverVar != "c" || reads[2].AssignedVar != "fp" || reads[2].CallerKey != "app/mod.print" {
		t.Errorf("instance read = %+v, want receiver c, assigned fp, caller app/mod.print", reads[2])
	}
}

func TestNodePropertyReadInArgumentsAndObjectValues(t *testing.T) {
	t.Parallel()

	src := "const acme = require('acme-crypto');\n" +
		"seal(acme.mode.GCM, { alg: acme.enums.hash.sha256, ['k']: 1 });\n" +
		"const tpl = `${acme.version}`;\n" +
		"const o = acme['mode']['CTR'];\n"
	reads := nodePropertyReadsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeReadRaws(t, reads, "acme.mode.GCM", "acme.enums.hash.sha256", "acme.version", "acme['mode']['CTR']")
	for _, r := range reads {
		if r.Raw == "acme['mode']['CTR']" && (r.TargetKey != "acme-crypto.mode.CTR" || r.MethodName != "CTR") {
			// The object `acme['mode']` resolves as `acme.mode`, as for a call.
			t.Errorf("subscript read = %+v, want acme-crypto.mode.CTR", r)
		}
		if r.Raw == "acme.enums.hash.sha256" && r.TargetKey != "acme-crypto.enums.hash.sha256" {
			t.Errorf("object value read = %+v", r)
		}
	}
}

func TestNodePropertyReadNotListed(t *testing.T) {
	t.Parallel()

	src := "import * as acme from 'acme-crypto';\n" +
		"acme.a.b();\n" +
		"new acme.k.Cert();\n" +
		"acme.x = 1;\n" +
		"acme.y.z += 1;\n" +
		"acme.count++;\n" +
		"delete acme.p;\n" +
		"const { q } = acme;\n" +
		"[acme.r] = [1];\n" +
		"({ s: acme.s } = {});\n" +
		"class K { constructor() { this.x = 1; return this.x; } }\n" +
		"module.exports.y = 1;\n" +
		"const e = exports.z;\n" +
		"const u = module.exports.w;\n" +
		"const lit = { [acme.key]: 1 };\n" +
		"for (acme.i in lit) {}\n"
	if reads := nodePropertyReadsOf(t, map[string]string{"mod.js": src}, "mod.js"); len(reads) != 0 {
		t.Errorf("property reads = %q, want none", nodeReadRaws(reads))
	}
}

func TestNodePropertyReadOutermostOfChainOnly(t *testing.T) {
	t.Parallel()

	src := "import * as acme from 'acme-crypto';\nconst v = acme.enums.hash.md5;\n"
	reads := nodePropertyReadsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeReadRaws(t, reads, "acme.enums.hash.md5")
}

func TestNodePropertyReadTypeScriptTypesAreNotReads(t *testing.T) {
	t.Parallel()

	src := "import * as acme from 'acme-crypto';\n" +
		"type Mode = typeof acme.mode;\n" +
		"interface Box { m: typeof acme.mode.ECB }\n" +
		"function pick(m: typeof acme.mode.CBC, c: acme.Cert): acme.Cert {\n" +
		"  return c;\n" +
		"}\n" +
		"const g = acme.mode.GCM as typeof acme.mode.CTR;\n"
	reads := nodePropertyReadsOf(t, map[string]string{"mod.ts": src}, "mod.ts")
	assertNodeReadRaws(t, reads, "acme.mode.GCM")
}

func TestNodePropertyReadExactSpan(t *testing.T) {
	t.Parallel()

	src := "import * as acme from 'acme-crypto';\n" +
		"seal(payload, acme.enums.hash.md5);\n" +
		"const long = acme\n  .mode\n  .ECB;\n"
	reads := nodePropertyReadsOf(t, map[string]string{"mod.js": src}, "mod.js")
	if len(reads) != 2 {
		t.Fatalf("reads = %+v, want two", reads)
	}
	// Line 2 is `seal(payload, acme.enums.hash.md5);`: the read starts at the
	// 15th character and its last is the 33rd, so the exclusive end is 34.
	want := NodePropertyRead{
		CallerKey: moduleKeyOf("app/mod"), TargetKey: "acme-crypto.enums.hash.md5", MethodName: "md5",
		Raw: "acme.enums.hash.md5", Line: 2, StartCol: 15, EndCol: 34,
	}
	if !reflect.DeepEqual(reads[0], want) {
		t.Errorf("read:\n got  %+v\n want %+v", reads[0], want)
	}
	line := strings.Split(src, "\n")[1]
	if line[reads[0].StartCol-1:reads[0].EndCol-1] != reads[0].Raw {
		t.Errorf("source[%d:%d] = %q, want %q", reads[0].StartCol, reads[0].EndCol, line[reads[0].StartCol-1:reads[0].EndCol-1], reads[0].Raw)
	}
	multi := reads[1]
	if multi.Line != 3 || multi.EndLine != 5 || multi.StartCol != 14 || multi.EndCol != 7 || multi.Raw != "acme\n  .mode\n  .ECB" {
		t.Errorf("multi-line read = %+v, want 3:14 to 5:7", multi)
	}
}

// Reads change no other part of the graph: the same source with every read
// blanked out, columns kept, builds the same functions, calls and callers.
func TestNodePropertyReadsLeaveTheGraphUnchanged(t *testing.T) {
	t.Parallel()

	src := "import * as acme from 'acme-crypto';\n" +
		"const ec = new acme.Curve('p256');\n" +
		"const tag = acme.mode.GCM;\n" +
		"export function sign(msg) {\n" +
		"  const key = ec.genKeyPair();\n" +
		"  const pub = key.pub;\n" +
		"  const fp = ec.curve.name;\n" +
		"  return key.sign(msg);\n" +
		"}\n"
	reads := []string{"acme.mode.GCM", "key.pub", "ec.curve.name"}
	blank := src
	for _, r := range reads {
		blank = strings.Replace(blank, r, "0"+strings.Repeat(" ", len(r)-1), 1)
	}
	with := buildNodeFiles(t, map[string]string{"mod.js": src})
	without := buildNodeFiles(t, map[string]string{"mod.js": blank})
	if got := nodeReadRaws(with.NodePropertyReads[nodeOnlyFile(t, with.NodePropertyReads)]); strings.Join(got, "|") != strings.Join(reads, "|") {
		t.Fatalf("reads = %q, want %q", got, reads)
	}
	if len(without.NodePropertyReads) != 0 {
		t.Fatalf("blanked source still has reads: %+v", without.NodePropertyReads)
	}
	if a, b := nodeGraphShape(with), nodeGraphShape(without); !reflect.DeepEqual(a, b) {
		t.Errorf("graph changed by reads:\n with    %v\n without %v", a, b)
	}
}

func nodeOnlyFile(t *testing.T, reads map[string][]NodePropertyRead) string {
	t.Helper()
	if len(reads) != 1 {
		t.Fatalf("reads of %d files, want one", len(reads))
	}
	for path := range reads {
		return path
	}
	return ""
}

// nodeGraphShape is the functions, calls (target, text, span, receiver,
// assigned variable) and caller index of a graph, in a comparable form.
func nodeGraphShape(graph *CallGraph) []string {
	var out []string
	for key, fn := range graph.Functions {
		out = append(out, "fn "+key+" "+strings.Join(fn.ModuleVars, ","))
		for i := range fn.Calls {
			c := &fn.Calls[i]
			out = append(out, strings.Join([]string{
				"call", key, c.Callee.String(), c.Raw, c.ReceiverVar, c.AssignedVar, c.ChainID,
				strconv.Itoa(c.Line), strconv.Itoa(c.StartCol), strconv.Itoa(c.EndLine), strconv.Itoa(c.EndCol),
			}, " "))
		}
	}
	for callee, callers := range graph.Callers {
		sorted := append([]string(nil), callers...)
		sort.Strings(sorted)
		out = append(out, "callers "+callee+" "+strings.Join(sorted, ","))
	}
	sort.Strings(out)
	return out
}

// A read on a variable a contracted call produced takes the type the KB
// gives the variable, as resolveNodeAssignedVarCallees types a call on it;
// a read before the binding, or after a rebinding, is left alone.
func TestNodePropertyReadTypedByContract(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: node
library:
  name: acme-test
contracts:
  - method: acme-crypto.makeCert
    arity: 1
    return:
      type: acme-crypto.Cert
      confidence: high
  - method: acme-crypto.Cert.verify
    arity: 0
    return:
      type: boolean
      confidence: high
`))
	if err != nil {
		t.Fatalf("load test KB: %v", err)
	}
	fn := &FunctionDecl{
		ID:       FunctionID{Package: "app/mod", Name: "print"},
		FilePath: "mod.js",
		Calls: []FunctionCall{{
			Callee: FunctionID{Package: "acme-crypto", Name: "makeCert"}, Arguments: []string{"p"},
			AssignedVar: "c", Line: 2, StartCol: 13, EndLine: 2, EndCol: 27,
		}},
	}
	site := func(line int) *nodePropertyReadSite {
		return &nodePropertyReadSite{callerKey: "app/mod.print", call: FunctionCall{
			Callee: FunctionID{Package: "app/mod", Name: "fingerprint"}, ReceiverVar: "c",
			Raw: "c.fingerprint", FilePath: "mod.js", Line: line, StartCol: 3, EndLine: line, EndCol: 16,
		}}
	}
	before, after := site(1), site(3)
	graph := &CallGraph{Functions: map[string]*FunctionDecl{"app/mod.print": fn}}
	graph.nodePropertyReads = []*nodePropertyReadSite{before, after}
	finishNodePropertyReads(graph, kb)
	reads := graph.NodePropertyReads["mod.js"]
	if len(reads) != 2 {
		t.Fatalf("reads = %+v", reads)
	}
	if reads[0].TargetKey != "app/mod.fingerprint" {
		t.Errorf("read before the binding = %q, want it untyped", reads[0].TargetKey)
	}
	if reads[1].TargetKey != "acme-crypto.(Cert).fingerprint" {
		t.Errorf("read after the binding = %q, want acme-crypto.(Cert).fingerprint", reads[1].TargetKey)
	}
	if len(fn.Calls) != 1 || fn.Calls[0].Callee.String() != "acme-crypto.makeCert" {
		t.Errorf("the function's calls changed: %+v", fn.Calls)
	}
}
