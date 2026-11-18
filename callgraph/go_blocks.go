// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import sitter "github.com/smacker/go-tree-sitter"

// GoBlock is the extent of one block of a Go function body: the body itself,
// an if or else body, a for body, a bare `{...}`, a function literal's body,
// or a clause of a switch, type switch or select, whose statements form a
// block of their own from the `case` (or `default`) to the clause's end. A
// detector tells from these whether a call lies in the rest of the block that
// assigns a variable, or in a block nested in it, and not in a sibling such
// as the next case or the else.
type GoBlock struct {
	// Function is the key of the function that holds the block; for one in a
	// package-level var initializer, the file's <varinit> declaration.
	Function string
	// StartLine, StartCol, EndLine and EndCol locate the block (columns
	// 1-based, end exclusive).
	StartLine, StartCol, EndLine, EndCol int
}

// goBlockAt reads node as a GoBlock, false when it is none.
func goBlockAt(node *sitter.Node) (GoBlock, bool) {
	if node.Type() != goNodeBlock && !goCaseScopes[node.Type()] {
		return GoBlock{}, false
	}
	start, end := node.StartPoint(), node.EndPoint()
	if node.Type() != goNodeBlock {
		// A clause's node runs on over the terminator and whitespace before
		// the next clause; it ends where its last statement (or its colon)
		// does.
		for i := int(node.ChildCount()) - 1; i >= 0; i-- {
			if c := node.Child(i); c.Type() != "\n" && c.Type() != ";" {
				end = c.EndPoint()
				break
			}
		}
	}
	return GoBlock{
		StartLine: int(start.Row) + 1, StartCol: int(start.Column) + 1,
		EndLine: int(end.Row) + 1, EndCol: int(end.Column) + 1,
	}, true
}

// goFactMark is where a function's Go facts start in a FileAnalysis.
type goFactMark struct{ values, blocks int }

func markGoFacts(analysis *FileAnalysis) goFactMark {
	return goFactMark{values: len(analysis.GoValues), blocks: len(analysis.GoBlocks)}
}

// keyGoFacts gives the values and blocks recorded since from the function
// key.
func keyGoFacts(analysis *FileAnalysis, from goFactMark, key string) {
	for i := from.values; i < len(analysis.GoValues); i++ {
		analysis.GoValues[i].Function = key
	}
	for i := from.blocks; i < len(analysis.GoBlocks); i++ {
		analysis.GoBlocks[i].Function = key
	}
}
