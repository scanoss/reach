// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"reflect"
	"testing"
)

// SuppressedSummaryOnly drops the per-edge records and nothing else: the
// export, whose verdicts read only whether an edge was refused, is the same.
func TestStitch_SuppressedSummaryOnlyKeepsTheExport(t *testing.T) {
	t.Parallel()
	unknownEdge := func() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
		root, deps, fragments := nameOnlySinkFixture(false)
		f := fragments[root]
		f.ExternalCalls[0].Resolution = ResolutionUnknown
		fragments[root] = f
		return root, deps, fragments
	}
	cases := map[string]struct {
		fixture        func() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment)
		wantSuppressed bool
	}{
		"name_only":    {func() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) { return nameOnlySinkFixture(false) }, true},
		"unknown":      {unknownEdge, true},
		"typed beside": {func() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) { return nameOnlySinkFixture(true) }, true},
		"no refusal": {func() (ComponentKey, DependencyGraph, map[ComponentKey]Fragment) {
			return composeFixtureWithLeg(ResolutionExact)
		}, false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root, deps, fragments := tc.fixture()
			full, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			summary, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true, SuppressedSummaryOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if got := len(full.Suppressed) > 0; got != tc.wantSuppressed {
				t.Fatalf("fixture suppresses = %v, want %v", got, tc.wantSuppressed)
			}
			if len(summary.Suppressed) != 0 {
				t.Fatalf("summary kept %d suppressed records, want none", len(summary.Suppressed))
			}
			meta := ScanMeta{Ecosystem: "java"}
			if a, b := full.ToCallgraphExport(root, meta), summary.ToCallgraphExport(root, meta); !reflect.DeepEqual(a, b) {
				t.Fatalf("exports differ:\nfull    %+v\nsummary %+v", a.FindingGraphs, b.FindingGraphs)
			}
		})
	}
}

// The forward closure reads the records, so it keeps them.
func TestStitch_SuppressedSummaryOnlyKeepsRecordsForForwardClosure(t *testing.T) {
	t.Parallel()
	root, deps, fragments := nameOnlySinkFixture(false)
	res, err := StitchWithOptions(root, deps, fragments, StitchOptions{EntryRootedOnly: true, SuppressedSummaryOnly: true, ForwardClosure: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Suppressed) != 1 || res.Suppressed[0].Reason != SuppressReasonNameOnly {
		t.Fatalf("suppressed = %+v, want the name_only record", res.Suppressed)
	}
}
