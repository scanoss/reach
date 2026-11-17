// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
)

// An item is a positional array; end_line is written only for an item over
// several lines, and both forms decode back.
func TestGraphFragmentItemRoundTrip(t *testing.T) {
	t.Parallel()
	for want, item := range map[string]GraphFragmentItem{
		`[4,5,26,"const","K"]`:                           {Line: 4, StartCol: 5, EndCol: 26, Kind: "const", Name: "K"},
		`[9,1,2,"impl","acme_kdf::Kdf\u003cH\u003e",13]`: {Line: 9, StartCol: 1, EndCol: 2, EndLine: 13, Kind: "impl", Name: "acme_kdf::Kdf<H>"},
	} {
		data, err := json.Marshal(item)
		if err != nil || string(data) != want {
			t.Fatalf("marshal %+v = %s, %v; want %s", item, data, err, want)
		}
		var back GraphFragmentItem
		if err := json.Unmarshal(data, &back); err != nil || back != item {
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
