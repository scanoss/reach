// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package cardmatch

import (
	"path/filepath"
	"testing"
)

// Explain names the stage that decides each entry at each site of a line,
// as the scan runs it: a producer that does not reach a sibling block is
// rejected at the insides stage, a reported one is a finding, a taint sink
// no source reaches stops at the taint stage, and a line with no call lists
// the calls around it (go-port audit F7). A Rust, C or Node fragment is
// refused: its own matcher decides it.
func TestExplain(t *testing.T) {
	assets, frag, _ := rustFixtureAt(t, goProducerDir)
	for _, c := range []struct {
		file    string
		line    int
		stage   string
		finding bool
	}{
		{"src/mode.go", 12, stageReported, true},
		{"src/sibling.go", 16, stageInsides, false},
		{"src/mode.go", 34, stageInsides, false}, // block from blk.Other(key)
	} {
		ex, err := assets.Explain(frag, "mode", c.file, c.line)
		if err != nil {
			t.Fatal(err)
		}
		if len(ex.Steps) != 1 || ex.Steps[0].Stage != c.stage || ex.Steps[0].Finding != c.finding {
			t.Errorf("%s:%d: %+v, want stage %s", c.file, c.line, ex.Steps, c.stage)
		}
	}
	ex, err := assets.Explain(frag, "mode", "src/mode.go", 11)
	if err != nil {
		t.Fatal(err)
	}
	if len(ex.Steps) != 0 || len(ex.Nearby) == 0 {
		t.Errorf("a line with no call: steps %v nearby %v", ex.Steps, ex.Nearby)
	}
	tassets, tfrag, _ := rustFixtureAt(t, filepath.Join("testdata", "go_taint"))
	ex, err = tassets.Explain(tfrag, "value", "src/main.go", 29)
	if err != nil {
		t.Fatal(err)
	}
	// The rule's two sinks: lib.Sign(...) reaches the taint stage, $O.Use(...)
	// is no call of the line.
	if len(ex.Steps) != 2 || ex.Steps[0].Stage != stageTaint || ex.Steps[1].Stage != stageCall {
		t.Errorf("clean(k): %+v, want the taint stage, then the call stage", ex.Steps)
	}
	if _, err := assets.Explain(frag, "no-such-rule", "src/mode.go", 12); err == nil {
		t.Error("an unknown rule: want an error")
	}
	rassets, rfrag, _ := rustFixtureAt(t, rustTaintDir)
	if _, err := rassets.Explain(rfrag, "value", "src/main.rs", 5); err == nil {
		t.Error("a rust fragment: want an error (the Rust matcher decides it)")
	}
}
