// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// An import's kind is written only when set, so a Python import (and any
// fragment written before Node imports had a kind) keeps its JSON, and it
// reads back as written.
func TestGraphFragmentImportKindIsOptional(t *testing.T) {
	export := graphfrag.GraphFragmentExport{Imports: map[string][]graphfrag.GraphFragmentImport{
		"src/a.py": {{Line: 1, Module: "zork.lib", Name: "frob"}},
		"src/b.js": {{Line: 2, Module: "node:zork", Alias: "z", Kind: "require"}},
	}}
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `{"line":1,"module":"zork.lib","name":"frob"}`) {
		t.Errorf("Python import JSON changed: %s", text)
	}
	if !strings.Contains(text, `{"line":2,"module":"node:zork","alias":"z","kind":"require"}`) {
		t.Errorf("Node import JSON lacks its kind: %s", text)
	}
	var back graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.Imports, export.Imports) {
		t.Errorf("imports read back as %+v, want %+v", back.Imports, export.Imports)
	}
}
