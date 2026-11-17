// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
)

// A string literal encodes as a positional array, end_line only when the
// literal spans lines, and decodes back.
func TestGraphFragmentStringRoundTrip(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		s    GraphFragmentString
		json string
	}{
		{GraphFragmentString{Line: 3, StartCol: 45, EndCol: 55, Text: `"zork-128"`}, `[3,45,55,"\"zork-128\""]`},
		{GraphFragmentString{Line: 9, StartCol: 14, EndCol: 4, EndLine: 10, Text: "\"a\\\nb\""}, `[9,14,4,"\"a\\\nb\"",10]`},
	} {
		data, err := json.Marshal(tc.s)
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != tc.json {
			t.Errorf("encoded %s, want %s", data, tc.json)
		}
		var back GraphFragmentString
		if err := json.Unmarshal(data, &back); err != nil || back != tc.s {
			t.Errorf("decoded %+v (%v), want %+v", back, err, tc.s)
		}
	}
}

// strings is optional: a fragment without it decodes with none, and a
// reader that does not know the field decodes a fragment with it.
func TestGraphFragmentStringsOptional(t *testing.T) {
	t.Parallel()
	var without GraphFragmentExport
	if err := json.Unmarshal([]byte(`{"schema_version":"`+SchemaVersion+`"}`), &without); err != nil || without.Strings != nil {
		t.Fatalf("fragment without strings: %v, %+v", err, without.Strings)
	}
	with := GraphFragmentExport{SchemaVersion: SchemaVersion, Strings: map[string][]GraphFragmentString{
		"main.c": {{Line: 1, StartCol: 5, EndCol: 10, Text: `"abc"`}},
	}}
	data, err := json.Marshal(with)
	if err != nil {
		t.Fatal(err)
	}
	var back GraphFragmentExport
	if err := json.Unmarshal(data, &back); err != nil || !reflect.DeepEqual(back.Strings, with.Strings) {
		t.Fatalf("round trip: %v, %+v", err, back.Strings)
	}
	var older struct {
		SchemaVersion string `json:"schema_version"`
	}
	if err := json.Unmarshal(data, &older); err != nil || older.SchemaVersion != SchemaVersion {
		t.Fatalf("older reader: %v, %q", err, older.SchemaVersion)
	}
}
