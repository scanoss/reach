// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
)

// A stored fragment writes its internal edges compact; expanding them gives
// back the edges the exporter built in memory, every field and the call
// site, so a re-detection reads the stored graph as the scan read it.
func TestExpandInternalEdgesRestoresTheExportedEdges(t *testing.T) {
	const document = `{
	  "schema_version": "graph-fragment-1.19",
	  "functions": [{"key": "app.(A).run#0"}, {"key": "app.(B).seal#1"}],
	  "internal_edge_strings": ["", "exact", "app.B", "seal", "b", "out", "c1", "app.BImpl"],
	  "internal_edges_compact": [[0, 1, 7, 1, 2, 3, 1, 4, 5, 6, 9, 30, 7, 8, {"line": 7, "parameters": [{"parameter_index": 0, "argument_expression": "data"}]}]]
	}`
	var export GraphFragmentExport
	if err := json.Unmarshal([]byte(document), &export); err != nil {
		t.Fatal(err)
	}
	export.ExpandInternalEdges()
	want := []GraphFragmentEdge{{
		CallerKey: "app.(A).run#0", CalleeKey: "app.(B).seal#1", Line: 7, Resolution: "exact", DeclaredType: "app.B",
		MethodName: "seal", Arity: 1, ReceiverVar: "b", AssignedVar: "out", ChainID: "c1", StartCol: 9, EndCol: 30,
		ResolvedReceiverType: "app.BImpl", EndLine: 8,
		EntryCall: &GraphFragmentCallSite{Line: 7, Parameters: []GraphFragmentParameter{{ParameterIndex: 0, ArgumentExpression: "data"}}},
	}}
	if !reflect.DeepEqual(export.InternalEdges, want) {
		t.Errorf("internal edges = %+v, want %+v", export.InternalEdges, want)
	}
	if export.CompactInternalEdges != nil || export.InternalEdgeStrings != nil {
		t.Error("the compact form is left behind")
	}
}

// A call anchor is a positional array and decodes back to itself.
func TestCallAnchorRoundTrip(t *testing.T) {
	anchor := GraphFragmentCallAnchor{Function: 3, Line: 12, StartCol: 9, EndCol: 40, Kind: "method_invocation", Path: `block[0]/expression_statement[2]/method_invocation[0]`}
	data, err := json.Marshal(anchor)
	if err != nil {
		t.Fatal(err)
	}
	if want := `[3,12,9,40,"method_invocation","block[0]/expression_statement[2]/method_invocation[0]"]`; string(data) != want {
		t.Errorf("encoded = %s, want %s", data, want)
	}
	var decoded GraphFragmentCallAnchor
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, anchor) {
		t.Errorf("decoded = %+v, want %+v", decoded, anchor)
	}
}

// An anchor of a chain link writes the chain last; one of no chain leaves it
// out.
func TestCallAnchorWritesTheChainOnlyOfALink(t *testing.T) {
	link := GraphFragmentCallAnchor{Function: 1, Line: 4, StartCol: 5, EndCol: 9, Kind: "method_invocation", Path: "p", ChainID: "12"}
	data, err := json.Marshal(link)
	if err != nil {
		t.Fatal(err)
	}
	if want := `[1,4,5,9,"method_invocation","p","12"]`; string(data) != want {
		t.Errorf("encoded = %s, want %s", data, want)
	}
	var decoded GraphFragmentCallAnchor
	if err := json.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(decoded, link) {
		t.Errorf("decoded = %+v, %v; want %+v", decoded, err, link)
	}
}

// A 1.21 anchor carries the call: its target, text, arguments and their
// provenance, and writes an empty chain to reach them.
func TestCallAnchorCarriesTheCall(t *testing.T) {
	anchor := GraphFragmentCallAnchor{
		Function: 2, Line: 7, StartCol: 3, EndCol: 30, Kind: "method_invocation", Path: "p",
		Callee: "javax.crypto.(Cipher).getInstance#1", Raw: "Cipher.getInstance", Arguments: []string{`"AES"`},
		ArgumentSources: [][]GraphFragmentRawSource{{{Type: "VALUE", Value: `"AES"`, Guard: &GraphFragmentRawGuard{ParameterIndex: 1, Value: "x"}}}},
	}
	data, err := json.Marshal(anchor)
	if err != nil {
		t.Fatal(err)
	}
	want := `[2,7,3,30,"method_invocation","p","","javax.crypto.(Cipher).getInstance#1","Cipher.getInstance",["\"AES\""],` +
		`[[{"type":"VALUE","value":"\"AES\"","guard":{"parameter_index":1,"value":"x"}}]]]`
	if string(data) != want {
		t.Errorf("encoded = %s, want %s", data, want)
	}
	var decoded GraphFragmentCallAnchor
	if err := json.Unmarshal(data, &decoded); err != nil || !reflect.DeepEqual(decoded, anchor) {
		t.Errorf("decoded = %+v, %v; want %+v", decoded, err, anchor)
	}
	// A call without arguments stops at its text.
	bare := GraphFragmentCallAnchor{Function: 2, Line: 7, Kind: "k", Path: "p", Callee: "a.(B).c#0"}
	data, _ = json.Marshal(bare)
	if want := `[2,7,0,0,"k","p","","a.(B).c#0"]`; string(data) != want {
		t.Errorf("encoded = %s, want %s", data, want)
	}
}
