// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"maps"
	"slices"

	"github.com/scanoss/reach/callgraph"
)

// FunctionFileIndex groups functions by the file that declares them, each
// file's functions in the order of their keys in the graph.
type FunctionFileIndex struct {
	byFile map[string][]*callgraph.FunctionDecl
}

// NewFunctionFileIndex indexes functions in key order, so declarations
// Containing cannot tell apart keep one order on every run.
func NewFunctionFileIndex(artifacts *Artifacts, functions map[string]*callgraph.FunctionDecl) *FunctionFileIndex {
	idx := &FunctionFileIndex{byFile: make(map[string][]*callgraph.FunctionDecl)}
	for _, key := range slices.Sorted(maps.Keys(functions)) {
		fn := functions[key]
		if fn == nil || fn.FilePath == "" {
			continue
		}
		file := artifacts.AbsPath(fn.FilePath)
		idx.byFile[file] = append(idx.byFile[file], fn)
	}
	return idx
}

// Containing returns the innermost function of file whose span holds the
// position (line, col). Spans nest (a synthetic <clinit> may cover the whole
// class around the real method, a JS callback sits inside its caller), so the
// tightest span wins, with the function ID as a deterministic tie-break, and
// among declarations with the same span and ID the first in key order.
//
// Containment is column-aware: a function that starts later on the
// position's own line, as the arrow function passed to `readFile(..., (e) => {`,
// does not hold a position that starts before it. A zero col, or a function
// whose parser records no columns, is judged by lines alone, which is the
// behavior for every line a single function covers.
func (idx *FunctionFileIndex) Containing(file string, line, col int) *callgraph.FunctionDecl {
	var best *callgraph.FunctionDecl
	for _, fn := range idx.byFile[file] {
		if !spanHolds(fn, line, col) {
			continue
		}
		if best == nil || tighterSpan(fn, best) {
			best = fn
		}
	}
	return best
}

func spanHolds(fn *callgraph.FunctionDecl, line, col int) bool {
	if line < fn.StartLine || line > fn.EndLine {
		return false
	}
	if col <= 0 {
		return true
	}
	if line == fn.StartLine && fn.StartCol > 0 && col < fn.StartCol {
		return false
	}
	if line == fn.EndLine && fn.EndCol > 0 && col >= fn.EndCol {
		return false
	}
	return true
}

// tighterSpan reports whether a is nested inside b: fewer lines, else later
// start, else (on equal spans) first by function key, so the choice is stable
// across map iteration orders.
func tighterSpan(a, b *callgraph.FunctionDecl) bool {
	spanA := a.EndLine - a.StartLine
	spanB := b.EndLine - b.StartLine
	if spanA != spanB {
		return spanA < spanB
	}
	if a.StartLine != b.StartLine {
		return a.StartLine > b.StartLine
	}
	if a.StartCol != b.StartCol {
		return a.StartCol > b.StartCol
	}
	return a.ID.String() < b.ID.String()
}
