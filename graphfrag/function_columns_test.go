// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"testing"
)

// A function's columns (1.38+) survive ingest and re-encoding, so a store that
// keeps a fragment and annotates it later still tells a callback written on
// its caller's line from the caller.
func TestFunctionColumnsRoundTrip(t *testing.T) {
	raw := []byte(`{
		"schema_version": "graph-fragment-1.38",
		"scan_metadata": {"root_module": "acme", "graph_algo_version": "graph-algo-node-8"},
		"functions": [
			{"key": "acme/index.gen", "function_name": "gen", "file_path": "index.js", "start_line": 3, "end_line": 9, "start_col": 1, "end_col": 2},
			{"key": "acme/index.<anonymous>@3:28", "function_name": "<anonymous>", "file_path": "index.js", "start_line": 3, "end_line": 5, "start_col": 28, "end_col": 4}
		]
	}`)
	frag, err := DecodeFragment(ComponentKey{Purl: "pkg:npm/acme", Version: "1.0.0"}, raw)
	if err != nil {
		t.Fatalf("DecodeFragment: %v", err)
	}
	if got := frag.Functions[1]; got.StartCol != 28 || got.EndCol != 4 {
		t.Fatalf("decoded columns = %d..%d, want 28..4", got.StartCol, got.EndCol)
	}
	data, err := EncodeFragment(frag)
	if err != nil {
		t.Fatalf("EncodeFragment: %v", err)
	}
	var back GraphFragmentExport
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	cols := map[string][2]int{}
	for _, fn := range back.Functions {
		cols[fn.Key] = [2]int{fn.StartCol, fn.EndCol}
	}
	if cols["acme/index.gen"] != [2]int{1, 2} || cols["acme/index.<anonymous>@3:28"] != [2]int{28, 4} {
		t.Errorf("re-encoded columns = %v", cols)
	}
}
