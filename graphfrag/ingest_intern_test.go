// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
	"unsafe"
)

// internFixture is a fragment that repeats its caller, target, file path and
// argument provenance on two calls, as a decoded document does on thousands.
const internFixture = `{
	"schema_version":"graph-fragment-1.2",
	"functions":[{"key":"a.(A).run#0","function_name":"a.A.run","file_path":"a/A.java","return_type":"void"},
	             {"key":"a.(A).go#0","function_name":"a.A.go","file_path":"a/A.java","return_type":"void"}],
	"external_calls":[
		{"caller_key":"a.(A).run#0","target_key":"b.(B).call#1","target_canonical_signature":"b.B.call(java.lang.String): void","resolution":"exact","method_name":"call","arity":1,"line":3,
		 "entry_call":{"line":3,"parameters":[{"parameter_index":0,"type":"java.lang.String","argument_expression":"alg",
		   "source_nodes":[{"type":"PARAMETER","name":"alg","location":{"file_path":"a/A.java","line":2}},
		                   {"type":"VALUE","value":"AES"},{"type":"VALUE","value":"DES"}]}]}},
		{"caller_key":"a.(A).run#0","target_key":"b.(B).call#1","target_canonical_signature":"b.B.call(java.lang.String): void","resolution":"exact","method_name":"call","arity":1,"line":4,
		 "entry_call":{"line":4,"parameters":[{"parameter_index":0,"type":"java.lang.String","argument_expression":"alg",
		   "source_nodes":[{"type":"PARAMETER","name":"alg","location":{"file_path":"a/A.java","line":2}}]}]}}
	]
}`

func sameStorage(a, b string) bool { return unsafe.StringData(a) == unsafe.StringData(b) }

// ToFragment keeps one copy of each string a fragment repeats, and the values
// are the decoder's.
func TestToFragmentSharesRepeatedStrings(t *testing.T) {
	t.Parallel()
	frag, err := DecodeFragment(ComponentKey{Purl: "pkg:maven/a/a", Version: "1"}, []byte(internFixture))
	if err != nil {
		t.Fatal(err)
	}
	var plain GraphFragmentExport
	if err := json.Unmarshal([]byte(internFixture), &plain); err != nil {
		t.Fatal(err)
	}
	first, second := frag.ExternalCalls[0], frag.ExternalCalls[1]
	p1, p2 := first.EntryCall.Parameters[0], second.EntryCall.Parameters[0]
	pairs := map[string][2]string{
		"caller":           {first.Caller, second.Caller},
		"target":           {first.TargetSignature, second.TargetSignature},
		"canonical target": {first.TargetCanonicalSignature, second.TargetCanonicalSignature},
		"method":           {first.MethodName, second.MethodName},
		"parameter type":   {p1.Type, p2.Type},
		"argument":         {p1.ArgumentExpression, p2.ArgumentExpression},
		"source node type": {p1.SourceNodes[0].Type, p2.SourceNodes[0].Type},
		"source node name": {p1.SourceNodes[0].Name, p2.SourceNodes[0].Name},
		"location":         {p1.SourceNodes[0].Location.FilePath, p2.SourceNodes[0].Location.FilePath},
		"function file":    {frag.Functions[0].FilePath, frag.Functions[1].FilePath},
		"file and node":    {frag.Functions[0].FilePath, p2.SourceNodes[0].Location.FilePath},
	}
	for name, pair := range pairs {
		if pair[0] != pair[1] || !sameStorage(pair[0], pair[1]) {
			t.Errorf("%s: %q and %q are separate copies", name, pair[0], pair[1])
		}
	}
	if want := plain.ToFragment(ComponentKey{Purl: "pkg:maven/a/a", Version: "1"}); !reflect.DeepEqual(frag, want) {
		t.Fatalf("fragment differs from a plain decode:\n%+v\n%+v", frag, want)
	}
}

// Converted slices hold exactly their elements, and an absent list stays nil.
func TestToFragmentSizesSlicesExactly(t *testing.T) {
	t.Parallel()
	frag, err := DecodeFragment(ComponentKey{Purl: "pkg:maven/a/a", Version: "1"}, []byte(internFixture))
	if err != nil {
		t.Fatal(err)
	}
	for name, lc := range map[string][2]int{
		"functions":      {len(frag.Functions), cap(frag.Functions)},
		"external calls": {len(frag.ExternalCalls), cap(frag.ExternalCalls)},
		"parameters":     {len(frag.ExternalCalls[0].EntryCall.Parameters), cap(frag.ExternalCalls[0].EntryCall.Parameters)},
		"source nodes":   {len(frag.ExternalCalls[0].EntryCall.Parameters[0].SourceNodes), cap(frag.ExternalCalls[0].EntryCall.Parameters[0].SourceNodes)},
	} {
		if lc[0] != lc[1] {
			t.Errorf("%s: len %d cap %d", name, lc[0], lc[1])
		}
	}
	if frag.InternalEdges != nil || frag.ExternalCalls[0].EntryCall.Parameters[0].SourceNodes[0].SourceNodes != nil {
		t.Fatal("an absent list decoded non-nil")
	}
}
