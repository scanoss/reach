// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestStructuralExportDropsOnlyTheCryptoSections(t *testing.T) {
	in := []byte(`{
  "scan_metadata": {"root_module": "g:a", "rules_version": "r1", "crypto_operation_count": 2, "supporting_call_count": 1, "crypto_entry_point_count": 1, "function_count": 3},
  "schema_version": "graph-fragment-1.22",
  "functions": [{"key": "A.f#0"}],
  "source_lines": {"A.java": {"3": "x"}},
  "future_section": [1, 2],
  "crypto_annotations": [{"function_key": "A.f#0"}],
  "supporting_calls": [{}],
  "crypto_entry_points": [{}]
}`)
	out, err := StructuralExport(in)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = `{"schema_version":"graph-fragment-1.22",`
	if string(out[:len(prefix)]) != prefix {
		t.Fatalf("export starts %q, want schema_version first", out[:len(prefix)])
	}
	var got map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	_ = json.Unmarshal([]byte(`{
  "schema_version": "graph-fragment-1.22",
  "scan_metadata": {"root_module": "g:a", "function_count": 3},
  "functions": [{"key": "A.f#0"}],
  "source_lines": {"A.java": {"3": "x"}},
  "future_section": [1, 2]
}`), &want)
	if !reflect.DeepEqual(got, want) {
		t.Errorf("structural export\n got %s\nwant %v", out, want)
	}
	if _, err := StructuralExport([]byte(`{"functions":[]}`)); err == nil {
		t.Error("a document without schema_version must be refused")
	}
}
