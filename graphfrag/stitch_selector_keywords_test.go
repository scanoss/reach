// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"slices"
	"testing"
)

var (
	pyProject = ComponentKey{Purl: "pkg:pypi/app", Version: "1.0.0"}
	pyLibrary = ComponentKey{Purl: "pkg:pypi/tokens", Version: "2.0.0"}
)

const pySign = "tokens.sign"

func pyParameter(name string, index int) []SourceNode {
	return []SourceNode{{Type: sourceNodeParameter, Name: name, ParameterIndex: &index}}
}

func pyPositional(index int, value string) Parameter {
	return Parameter{ParameterIndex: index, ArgumentExpression: value, ResolvedValue: value}
}

func pyKeyword(index int, keyword, value string) Parameter {
	return Parameter{ParameterIndex: index, Keyword: keyword, ArgumentExpression: value, ResolvedValue: value}
}

// pySelectorFixture is a project calling a library's
//
//	def sign(payload, key, alg="HS256", *, digest=None):
//	    jwt.encode(payload, key, algorithm=alg)
//	    hashlib.new(digest)
//
// once per argument list of calls.
func pySelectorFixture(calls ...[]Parameter) (DependencyGraph, map[ComponentKey]Fragment) {
	root := Fragment{Component: pyProject, Functions: []Function{{Signature: "app.main.run"}}}
	for i, params := range calls {
		root.ExternalCalls = append(root.ExternalCalls, ExternalCall{
			Caller: "app.main.run", TargetSignature: pySign, Resolution: ResolutionExact, MethodName: "sign",
			Arity: len(params), CallSite: 10 + i, EntryCall: &CallSite{Line: 10 + i, Parameters: params},
		})
	}
	library := Fragment{Component: pyLibrary, Functions: []Function{{Signature: pySign}}}
	return DependencyGraph{pyProject: {pyLibrary}}, map[ComponentKey]Fragment{pyProject: root, pyLibrary: library}
}

func pySelectorValues(t *testing.T, call SelectorCall, calls ...[]Parameter) []string {
	t.Helper()
	deps, fragments := pySelectorFixture(calls...)
	res, err := StitchWithOptions(pyProject, deps, fragments, StitchOptions{EntryRootedOnly: true, SelectorCalls: []SelectorCall{call}})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	return variantSummary(res.SelectorValues()[0])
}

// A Python caller fills a parameter by position or by keyword: the keyword
// argument of the parameter's name is its value wherever it is written, a
// keyword argument of another name standing at the parameter's position is
// not, and neither is an argument after a `*args` spread or one the call
// leaves to the default. The variant keeps the terminal call's keyword, so
// a `param[2|algorithm]` condition selects it.
func TestSelectorValues_PythonKeywordArguments(t *testing.T) {
	t.Parallel()
	encode := SelectorCall{Component: pyLibrary, Function: pySign, Parameters: []Parameter{
		pyPositional(0, ""), pyPositional(1, ""),
		{ParameterIndex: 2, Keyword: "algorithm", VariableName: "alg", ArgumentExpression: "alg", SourceNodes: pyParameter("alg", 2)},
	}}
	encode.Parameters[0].ResolvedValue, encode.Parameters[1].ResolvedValue = "p", "k"
	got := pySelectorValues(t, encode,
		[]Parameter{pyPositional(0, "p"), pyPositional(1, "k"), pyPositional(2, `"HS384"`)},
		[]Parameter{pyPositional(0, "p"), pyPositional(1, "k"), pyKeyword(2, "alg", `"RS256"`)},
		[]Parameter{pyKeyword(0, "alg", `"ES256"`), pyKeyword(1, "payload", "p"), pyKeyword(2, "key", "k")},
		[]Parameter{pyPositional(0, "p"), pyPositional(1, "k"), pyKeyword(2, "digest", `"PS256"`)},
		[]Parameter{pyPositional(0, "*args"), pyPositional(1, "k"), pyPositional(2, `"HS512"`)},
		[]Parameter{pyPositional(0, "p"), pyPositional(1, "k")},
	)
	want := []string{`2:"ES256":reachable:`, `2:"HS384":reachable:`, `2:"RS256":reachable:`}
	if !slices.Equal(got, want) {
		t.Fatalf("variants = %v, want %v", got, want)
	}
	deps, fragments := pySelectorFixture([]Parameter{pyPositional(0, "p"), pyPositional(1, "k"), pyKeyword(2, "alg", `"RS256"`)})
	res, err := StitchWithOptions(pyProject, deps, fragments, StitchOptions{EntryRootedOnly: true, SelectorCalls: []SelectorCall{encode}})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	if variant := res.SelectorValues()[0].Variants[0]; variant.Parameters[2].Keyword != "algorithm" {
		t.Errorf("the variant's argument lost its keyword: %+v", variant.Parameters[2])
	}
}

// A keyword-only parameter has no position (-1): a caller passes it by its
// name alone, and another keyword-only parameter's value is not its own.
func TestSelectorValues_PythonKeywordOnlyParameter(t *testing.T) {
	t.Parallel()
	digest := SelectorCall{Component: pyLibrary, Function: pySign, Parameters: []Parameter{
		{ParameterIndex: 0, VariableName: "digest", ArgumentExpression: "digest", SourceNodes: pyParameter("digest", -1)},
	}}
	got := pySelectorValues(t, digest,
		[]Parameter{pyPositional(0, "p"), pyPositional(1, "k"), pyKeyword(2, "digest", `"sha512"`)},
		[]Parameter{pyPositional(0, "p"), pyPositional(1, "k"), pyPositional(2, `"sha1"`)},
		[]Parameter{pyPositional(0, "p"), pyPositional(1, "k"), pyKeyword(2, "other", `"md5"`)},
	)
	if want := []string{`0:"sha512":reachable:`}; !slices.Equal(got, want) {
		t.Fatalf("variants = %v, want %v", got, want)
	}
	// Two keyword-only parameters of one function: each takes the value
	// passed under its own name.
	pair := SelectorCall{Component: pyLibrary, Function: pySign, Parameters: []Parameter{
		{ParameterIndex: 0, VariableName: "digest", ArgumentExpression: "digest", SourceNodes: pyParameter("digest", -1)},
		{ParameterIndex: 1, VariableName: "salt", ArgumentExpression: "salt", SourceNodes: pyParameter("salt", -1)},
	}}
	got = pySelectorValues(t, pair, []Parameter{pyKeyword(0, "salt", `"abc"`), pyKeyword(1, "digest", `"sha512"`)})
	if want := []string{`0:"sha512":reachable:`, `1:"abc":reachable:`}; !slices.Equal(got, want) {
		t.Fatalf("variants = %v, want %v", got, want)
	}
	// Two keyword-only parameters in one argument: each binds its own.
	both := selectorParameters(append(pyParameter("digest", -1), pyParameter("salt", -1)...))
	if len(both) != 2 {
		t.Fatalf("parameters = %v, want digest and salt", both)
	}
	nodes := append(pyParameter("digest", -1), SourceNode{Type: sourceNodeValue, Value: "V"})
	if got, _ := resolveBoundSourceNodes(nodes, selectorParameter{index: -1, name: "digest"}, "V", true); got != "V" {
		t.Errorf("digest bound to V resolves %q", got)
	}
	if got, _ := resolveBoundSourceNodes(nodes, selectorParameter{index: -1, name: "salt"}, "V", true); got != "" {
		t.Errorf("salt bound to V resolves digest's argument to %q", got)
	}
	// A parameter with a position is told by it, whatever a node calls it.
	if got, _ := resolveBoundSourceNodes(pyParameter("renamed", 2), selectorParameter{index: 2, name: "alg"}, "V", true); got != "V" {
		t.Errorf("the parameter at 2 bound to V resolves %q", got)
	}
	// A negative position without a name, or another one, names no parameter.
	if got := selectorParameters(append(pyParameter("", -1), pyParameter("x", -2)...)); len(got) != 0 {
		t.Errorf("parameters = %v, want none", got)
	}
}
