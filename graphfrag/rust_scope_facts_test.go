// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
)

// An item is a positional array; end_line is written only for an item over
// several lines, or as 0 before a type alias's aliased type and keyword
// column or a fn's params, and every form decodes back.
func TestGraphFragmentItemRoundTrip(t *testing.T) {
	t.Parallel()
	for want, item := range map[string]GraphFragmentItem{
		`[4,5,26,"const","K"]`:                                              {Line: 4, StartCol: 5, EndCol: 26, Kind: "const", Name: "K"},
		`[9,1,2,"impl","acme_kdf::Kdf\u003cH\u003e",13]`:                    {Line: 9, StartCol: 1, EndCol: 2, EndLine: 13, Kind: "impl", Name: "acme_kdf::Kdf<H>"},
		`[1,1,32,"type","Pair",0,"AcmeGcm\u003cT, U12\u003e",1]`:            {Line: 1, StartCol: 1, EndCol: 32, Kind: "type", Name: "Pair", Type: "AcmeGcm<T, U12>", KeywordCol: 1},
		`[3,1,30,"type","Multi",4,"acme::Mode\u003cacme::Cipher\u003e",12]`: {Line: 3, StartCol: 1, EndCol: 30, EndLine: 4, Kind: "type", Name: "Multi", Type: "acme::Mode<acme::Cipher>", KeywordCol: 12},
		`[2,5,2,"fn","sign",4,"",0,[[2,13,18,"\u0026self","",0,true],[2,20,41,"key","\u0026acme::SigningKey"],[3,9,4,"mut m","Path\u003cG\u003e",4]]]`: {
			Line: 2, StartCol: 5, EndCol: 2, EndLine: 4, Kind: "fn", Name: "sign",
			Params: []GraphFragmentParam{
				{Line: 2, StartCol: 13, EndCol: 18, Pattern: "&self", Self: true},
				{Line: 2, StartCol: 20, EndCol: 41, Pattern: "key", Type: "&acme::SigningKey"},
				{Line: 3, StartCol: 9, EndCol: 4, EndLine: 4, Pattern: "mut m", Type: "Path<G>"},
			},
		},
	} {
		data, err := json.Marshal(item)
		if err != nil || string(data) != want {
			t.Fatalf("marshal %+v = %s, %v; want %s", item, data, err, want)
		}
		var back GraphFragmentItem
		if err := json.Unmarshal(data, &back); err != nil || !reflect.DeepEqual(back, item) {
			t.Fatalf("unmarshal %s = %+v, %v; want %+v", data, back, err, item)
		}
	}
}

// A Rust import carries its declaration's span and use tree; a Python import
// encodes as before, without them.
func TestGraphFragmentRustImportEncodes(t *testing.T) {
	t.Parallel()
	export := GraphFragmentExport{
		Imports: map[string][]GraphFragmentImport{
			"src/lib.rs":  {{Line: 2, StartCol: 1, EndCol: 55, Module: "acme_kdf::other", Name: "Thing", Alias: "T", Text: "acme_kdf::{Kdf, other::Thing as T}"}},
			"app/main.py": {{Line: 1, Module: "acme_kdf"}},
		},
		Items: map[string][]GraphFragmentItem{"src/lib.rs": {{Line: 4, StartCol: 1, EndCol: 2, EndLine: 6, Kind: "fn", Name: "derive"}}},
	}
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	var back GraphFragmentExport
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Imports, export.Imports) || !reflect.DeepEqual(back.Items, export.Items) {
		t.Fatalf("round trip:\n got %+v %+v\nwant %+v %+v", back.Imports, back.Items, export.Imports, export.Items)
	}
	py, _ := json.Marshal(export.Imports["app/main.py"][0])
	if string(py) != `{"line":1,"module":"acme_kdf"}` {
		t.Errorf("python import = %s, want the 1.25 form", py)
	}
	rs, _ := json.Marshal(export.Imports["src/lib.rs"][0])
	if want := `{"line":2,"module":"acme_kdf::other","name":"Thing","alias":"T","start_col":1,"end_col":55,"text":"acme_kdf::{Kdf, other::Thing as T}"}`; string(rs) != want {
		t.Errorf("rust import = %s, want %s", rs, want)
	}
}

// A binary expression is a positional array; its trailing lines are written
// only up to the last that is not on the expression's first line, and every
// form decodes back. A 1.29 item array still decodes.
func TestGraphFragmentBinaryExprRoundTrip(t *testing.T) {
	t.Parallel()
	for want, expr := range map[string]GraphFragmentBinaryExpr{
		`[3,13,22,"*","s","base",14,17,"app.mul"]`:        {Line: 3, StartCol: 13, EndCol: 22, Op: "*", Left: "s", Right: "base", LeftEndCol: 14, RightStartCol: 17, Function: "app.mul"},
		`[5,9,6,"+","\u0026a","(b\n    * c)",11,14,"",6]`: {Line: 5, StartCol: 9, EndCol: 6, EndLine: 6, Op: "+", Left: "&a", Right: "(b\n    * c)", LeftEndCol: 11, RightStartCol: 14},
		`[7,5,10,"==","x","y",6,9,"app.(K).f",8,0,8]`:     {Line: 7, StartCol: 5, EndCol: 10, EndLine: 8, Op: "==", Left: "x", Right: "y", LeftEndCol: 6, RightStartCol: 9, RightLine: 8, Function: "app.(K).f"},
	} {
		data, err := json.Marshal(expr)
		if err != nil || string(data) != want {
			t.Fatalf("marshal %+v = %s, %v; want %s", expr, data, err, want)
		}
		var back GraphFragmentBinaryExpr
		if err := json.Unmarshal(data, &back); err != nil || back != expr {
			t.Fatalf("unmarshal %s = %+v, %v; want %+v", data, back, err, expr)
		}
	}
	var old GraphFragmentItem
	if err := json.Unmarshal([]byte(`[9,1,2,"fn","run",13]`), &old); err != nil || old.Params != nil {
		t.Fatalf("1.29 fn item = %+v, %v; want no params", old, err)
	}
	var export GraphFragmentExport
	if err := json.Unmarshal([]byte(`{"binary_exprs":{"src/lib.rs":[[3,13,22,"*","s","base",14,17,"app.mul"]]}}`), &export); err != nil || len(export.BinaryExprs["src/lib.rs"]) != 1 {
		t.Fatalf("binary_exprs = %+v, %v", export.BinaryExprs, err)
	}
}
