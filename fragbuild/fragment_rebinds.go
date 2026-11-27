// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"slices"
	"strings"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
)

// WritesRebindLines reports whether a fragment of the scanned ecosystem
// carries rebind_lines: one whose calls are rebuilt with the arguments the
// scan saw (call_anchors, graph-fragment-1.21), in the languages
// FragmentCarriesCalls lists.
func WritesRebindLines(ctx *Context) bool {
	return FragmentCarriesCalls(ctx)
}

// BuildGraphFragmentRebinds records, for each function in functionIndex, the
// lines a reader needs to tell whether a variable is rebound between its
// assignment and its use: for each
// variable a call of the function passes, the lines from after the first line
// that can start the check (the function's, or its first call's) to before
// its last call that may rebind it. A function whose source cannot be read is
// recorded unread, so every variable in it reads as rebound.
func BuildGraphFragmentRebinds(ctx *Context, functionIndex map[string]int) []graphfrag.GraphFragmentRebind { //nolint:gocognit // one pass over each function's lines and names
	if !WritesRebindLines(ctx) {
		return nil
	}
	keys := make([]string, len(functionIndex))
	for key, index := range functionIndex {
		keys[index] = key
	}
	patterns := RebindPatternCache{}
	var out []graphfrag.GraphFragmentRebind
	for index, key := range keys {
		decl := ctx.Graph.Functions[key]
		if decl == nil {
			continue
		}
		names, first, last := rebindCandidates(decl, ctx.Ecosystem)
		if len(names) == 0 || last <= first+1 {
			continue
		}
		file := Excerpts(ctx).File(ctx.AbsPath(decl.FilePath))
		if file.Unavailable() != "" || last-1 > file.Lines() {
			out = append(out, graphfrag.GraphFragmentRebind{Function: index})
			continue
		}
		lines := make(map[string][]int)
		for line := first + 1; line < last; line++ {
			text := string(file.Line(line))
			for _, name := range names {
				if strings.Contains(text, name) && LineMayRebind(text, patterns.Patterns(name)) {
					lines[name] = append(lines[name], line)
				}
			}
		}
		for _, name := range names {
			if len(lines[name]) > 0 {
				out = append(out, graphfrag.GraphFragmentRebind{Function: index, Name: name, Lines: lines[name]})
			}
		}
	}
	return out
}

// rebindCandidates are, sorted, the variables decl's calls pass as bare
// arguments (the only names the pass follows in it), and the first and last
// line a rebind check in decl can span: from the function's first line or
// its first call, to its last call.
func rebindCandidates(decl *callgraph.FunctionDecl, ecosystem string) (names []string, first, last int) {
	first = decl.StartLine
	for i := range decl.Calls {
		call := &decl.Calls[i]
		if call.Line > 0 && (first <= 0 || call.Line < first) {
			first = call.Line
		}
		last = max(last, call.Line)
		for _, arg := range call.Arguments {
			if _, name := PassedVariable(arg, ecosystem); IsSimpleIdentifier(name) && !slices.Contains(names, name) {
				names = append(names, name)
			}
		}
	}
	slices.Sort(names)
	return names, first, last
}
