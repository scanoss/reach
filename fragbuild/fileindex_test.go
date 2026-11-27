// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"testing"

	"github.com/scanoss/reach/callgraph"
)

// TestColumnAwareContainment_Index pins the containment rule itself: the
// innermost function whose span holds the start position wins, a function that
// starts later on the position's line does not hold it, and a position without
// a column keeps the line-only answer.
func TestColumnAwareContainment_Index(t *testing.T) {
	outer := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Name: "outer"}, StartLine: 1, StartCol: 1, EndLine: 5, EndCol: 2}
	arrow := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Name: "arrow"}, StartLine: 2, StartCol: 40, EndLine: 2, EndCol: 60}
	inner := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Name: "inner"}, StartLine: 2, StartCol: 45, EndLine: 2, EndCol: 55}
	later := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Name: "later"}, StartLine: 4, StartCol: 3, EndLine: 4, EndCol: 20}
	noCols := &callgraph.FunctionDecl{ID: callgraph.FunctionID{Name: "noCols"}, StartLine: 7, EndLine: 9}
	idx := &FunctionFileIndex{byFile: map[string][]*callgraph.FunctionDecl{"f": {outer, arrow, inner, later, noCols}}}

	for _, tc := range []struct {
		name      string
		line, col int
		want      *callgraph.FunctionDecl
	}{
		{"before the arrow on its line", 2, 3, outer},
		{"inside the arrow", 2, 41, arrow},
		{"inside the nested function", 2, 46, inner},
		{"at the arrow's exclusive end", 2, 60, outer},
		{"no column keeps the innermost by line", 2, 0, inner},
		{"function without columns is judged by line", 8, 1, noCols},
		{"before the callback on a later line", 4, 2, outer},
		{"inside the callback on a later line", 4, 5, later},
		{"outside every span", 6, 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := idx.Containing("f", tc.line, tc.col); got != tc.want {
				t.Fatalf("Containing(%d, %d) = %v, want %v", tc.line, tc.col, got, tc.want)
			}
		})
	}
}
