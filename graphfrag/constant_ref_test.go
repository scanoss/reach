// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
)

// A constant reference is a positional array; end_line is written only for
// a reference over several lines, and both forms decode back.
func TestGraphFragmentConstantRefRoundTrip(t *testing.T) {
	t.Parallel()
	for want, ref := range map[string]GraphFragmentConstantRef{
		`[3,10,5,14,"Alg.HS256","equals"]`: {Function: 3, Line: 10, StartCol: 5, EndCol: 14, Text: "Alg.HS256", Context: "equals"},
		`[0,7,9,4,"a.b.Alg.X","return",8]`: {Function: 0, Line: 7, StartCol: 9, EndCol: 4, EndLine: 8, Text: "a.b.Alg.X", Context: "return"},
	} {
		data, err := json.Marshal(ref)
		if err != nil || string(data) != want {
			t.Fatalf("marshal %+v = %s, %v; want %s", ref, data, err, want)
		}
		var back GraphFragmentConstantRef
		if err := json.Unmarshal(data, &back); err != nil || back != ref {
			t.Fatalf("unmarshal %s = %+v, %v; want %+v", data, back, err, ref)
		}
	}
}

// A reference in a comparison appends its operand, as a parameter object,
// after end_line (0 on one line); it decodes back.
func TestGraphFragmentConstantRefOperandRoundTrip(t *testing.T) {
	t.Parallel()
	idx := 0
	ref := GraphFragmentConstantRef{Function: 1, Line: 4, StartCol: 13, EndCol: 22, Text: "Alg.HS256", Context: "equals",
		Operand: &GraphFragmentParameter{ArgumentExpression: "alg", VariableName: "alg",
			SourceNodes: []GraphFragmentSourceNode{{Type: "PARAMETER", Name: "alg", ParameterIndex: &idx}}}}
	want := `[1,4,13,22,"Alg.HS256","equals",0,{"parameter_index":0,"variable_name":"alg","argument_expression":"alg",` +
		`"source_nodes":[{"type":"PARAMETER","name":"alg","parameter_index":0}]}]`
	data, err := json.Marshal(ref)
	if err != nil || string(data) != want {
		t.Fatalf("marshal = %s, %v; want %s", data, err, want)
	}
	var back GraphFragmentConstantRef
	if err := json.Unmarshal(data, &back); err != nil || !reflect.DeepEqual(back, ref) {
		t.Fatalf("unmarshal %s = %+v, %v; want %+v", data, back, err, ref)
	}
}

// A 1.16 fragment has no constant_refs and decodes with none.
func TestGraphFragmentWithoutConstantRefsDecodes(t *testing.T) {
	t.Parallel()
	var export GraphFragmentExport
	if err := json.Unmarshal([]byte(`{"schema_version":"graph-fragment-1.16","functions":[]}`), &export); err != nil || export.ConstantRefs != nil {
		t.Fatalf("decode = %+v, %v; want no constant refs", export.ConstantRefs, err)
	}
}

// Declarations and casts are positional arrays; end_line is written only for
// one over several lines, and both forms decode back.
func TestGraphFragmentDeclarationAndCastRoundTrip(t *testing.T) {
	t.Parallel()
	for want, decl := range map[string]GraphFragmentDeclaration{
		`[2,5,9,37,"X509Certificate","cert","null"]`: {Function: 2, Line: 5, StartCol: 9, EndCol: 37, Type: "X509Certificate", Name: "cert", Init: "null"},
		`[0,7,9,4,"a.B[]","b","",8]`:                 {Function: 0, Line: 7, StartCol: 9, EndCol: 4, EndLine: 8, Type: "a.B[]", Name: "b"},
	} {
		data, err := json.Marshal(decl)
		if err != nil || string(data) != want {
			t.Fatalf("marshal %+v = %s, %v; want %s", decl, data, err, want)
		}
		var back GraphFragmentDeclaration
		if err := json.Unmarshal(data, &back); err != nil || back != decl {
			t.Fatalf("unmarshal %s = %+v, %v; want %+v", data, back, err, decl)
		}
	}
	for want, cast := range map[string]GraphFragmentCast{
		`[1,7,16,61,"X509Certificate",7,34]`: {Function: 1, Line: 7, StartCol: 16, EndCol: 61, Type: "X509Certificate", InnerLine: 7, InnerCol: 34},
		`[1,7,16,9,"T",8,5,8]`:               {Function: 1, Line: 7, StartCol: 16, EndCol: 9, EndLine: 8, Type: "T", InnerLine: 8, InnerCol: 5},
	} {
		data, err := json.Marshal(cast)
		if err != nil || string(data) != want {
			t.Fatalf("marshal %+v = %s, %v; want %s", cast, data, err, want)
		}
		var back GraphFragmentCast
		if err := json.Unmarshal(data, &back); err != nil || back != cast {
			t.Fatalf("unmarshal %s = %+v, %v; want %+v", data, back, err, cast)
		}
	}
	var short GraphFragmentCast
	if err := json.Unmarshal([]byte(`[1,7,16,61,"T",7]`), &short); err == nil {
		t.Fatalf("a cast with 6 fields decoded: %+v", short)
	}
}

// A 1.17 fragment has no declarations or casts and decodes with none.
func TestGraphFragmentWithoutDeclarationsDecodes(t *testing.T) {
	t.Parallel()
	var export GraphFragmentExport
	data := `{"schema_version":"graph-fragment-1.17","functions":[],"constant_refs":[[0,1,1,5,"A.B","arg"]]}`
	if err := json.Unmarshal([]byte(data), &export); err != nil || export.Declarations != nil || export.Casts != nil || len(export.ConstantRefs) != 1 {
		t.Fatalf("decode = %+v, %v; want constant refs and no declarations or casts", export, err)
	}
}
