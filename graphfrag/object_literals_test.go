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

// Object literals are written by file path with their span, text and caller
// key, end_line only for one that spans lines, and read back as written.
func TestGraphFragmentObjectLiteralsRoundTrip(t *testing.T) {
	export := graphfrag.GraphFragmentExport{ObjectLiterals: map[string][]graphfrag.GraphFragmentObjectLiteral{
		"src/a.js": {
			{Line: 2, StartCol: 28, EndCol: 55, Text: "{ mode: 'quux', rounds: 3 }", CallerKey: "app/a.<module>"},
			{Line: 4, StartCol: 13, EndLine: 6, EndCol: 2, Text: "{\n  level: 9,\n}", CallerKey: "app/a.build"},
		},
	}}
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	want := `"object_literals":{"src/a.js":[` +
		`{"line":2,"start_col":28,"end_col":55,"text":"{ mode: 'quux', rounds: 3 }","caller_key":"app/a.\u003cmodule\u003e"},` +
		`{"line":4,"start_col":13,"end_line":6,"end_col":2,"text":"{\n  level: 9,\n}","caller_key":"app/a.build"}]}`
	if !strings.Contains(text, want) {
		t.Errorf("object literal JSON:\n got  %s\n want it to hold %s", text, want)
	}
	var back graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.ObjectLiterals, export.ObjectLiterals) {
		t.Errorf("object literals read back as %+v, want %+v", back.ObjectLiterals, export.ObjectLiterals)
	}
	empty, err := json.Marshal(graphfrag.GraphFragmentExport{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(empty), "object_literals") {
		t.Errorf("a fragment without object literals writes the field: %s", empty)
	}
}
