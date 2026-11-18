// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"bytes"
	"context"
	"slices"
	"sort"

	sitter "github.com/smacker/go-tree-sitter"
)

// A preprocessor conditional that splits a statement (an #ifdef around one
// `else if` arm of a chain, an #if/#else pair that each open a block) is not
// C to tree-sitter: the function holding it ends at the first error and the
// rest of its body is lost. OpenGrep reads such a file. cFunctionTree gives
// the function walk a tree it can read: the file's own when it parses, else
// the file reparsed with its conditional directives blanked, and, if that
// still fails, with its #elif and #else branches blanked too, whichever has
// fewer errors. Blanking keeps every byte offset and line break, so positions
// are the file's. Only the functions the file's own tree reads with an error,
// or misses where an error stands, are taken from the reparsed tree
// (cMergeFunctions).

// cFunctionTree returns the root and source the functions of a file are read
// from, and the tree to close when it is not the file's own (nil).
func cFunctionTree(parser *sitter.Parser, root *sitter.Node, src []byte) (*sitter.Node, []byte, *sitter.Tree) {
	if !root.HasError() {
		return root, src, nil
	}
	best, bestSrc, bestErrors := root, src, cErrorCount(root)
	var bestTree *sitter.Tree
	for _, dropElse := range []bool{false, true} {
		alt := cBlankConditionals(src, dropElse)
		if alt == nil {
			break
		}
		tree, err := parser.ParseCtx(context.TODO(), nil, alt)
		if err != nil {
			continue
		}
		if errors := cErrorCount(tree.RootNode()); errors < bestErrors {
			if bestTree != nil {
				bestTree.Close()
			}
			best, bestSrc, bestErrors, bestTree = tree.RootNode(), alt, errors, tree
			if errors == 0 {
				break
			}
			continue
		}
		tree.Close()
	}
	return best, bestSrc, bestTree
}

// cBrokenFunctionLines lists the line ranges of a file's own tree that hold
// a function definition with an error, or an error outside any function (the
// rest of a body the parser cut short).
func cBrokenFunctionLines(root *sitter.Node) [][2]int {
	var out [][2]int
	for i := 0; i < int(root.ChildCount()); i++ {
		cBrokenLines(root.Child(i), &out)
	}
	return out
}

func cBrokenLines(n *sitter.Node, out *[][2]int) {
	switch {
	case n.Type() == cNodeFunctionDefinition:
		if n.HasError() {
			*out = append(*out, [2]int{int(n.StartPoint().Row) + 1, int(n.EndPoint().Row) + 1})
		}
		return
	case n.IsError():
		*out = append(*out, [2]int{int(n.StartPoint().Row) + 1, int(n.EndPoint().Row) + 1})
		return
	case !n.HasError():
		return
	}
	for i := 0; i < int(n.ChildCount()); i++ {
		cBrokenLines(n.Child(i), out)
	}
}

// cMergeFunctions keeps every function of the file's own tree that parsed
// and adds those of the reparsed tree that lie in a broken range and overlap
// no kept function. A broken function of the own tree that a reparsed one
// covers becomes the reparsed one with the calls, declarations and field
// stores of both: the own tree may have read a branch the reparse blanked
// (an #else branch), the reparse what the own tree lost after the error.
func cMergeFunctions(own []FunctionDecl, broken [][2]int, alt []FunctionDecl) []FunctionDecl {
	if len(broken) == 0 {
		return own
	}
	inBroken := func(f *FunctionDecl) bool {
		for _, r := range broken {
			if f.StartLine <= r[1] && r[0] <= f.EndLine {
				return true
			}
		}
		return false
	}
	overlaps := func(a, b *FunctionDecl) bool { return a.StartLine <= b.EndLine && b.StartLine <= a.EndLine }
	var good, bad []FunctionDecl
	for i := range own {
		if cFunctionBroken(&own[i], broken) {
			bad = append(bad, own[i])
		} else {
			good = append(good, own[i])
		}
	}
	out := good
	var added []FunctionDecl
	for i := range alt {
		f := alt[i]
		if !inBroken(&f) || slices.ContainsFunc(good, func(g FunctionDecl) bool { return overlaps(&f, &g) }) {
			continue
		}
		for j := range bad {
			if overlaps(&f, &bad[j]) && bad[j].StartLine == f.StartLine {
				cUnionBodies(&f, &bad[j])
			}
		}
		added = append(added, f)
	}
	for i := range bad {
		if !slices.ContainsFunc(added, func(a FunctionDecl) bool { return overlaps(&bad[i], &a) }) {
			out = append(out, bad[i])
		}
	}
	out = append(out, added...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].StartLine < out[j].StartLine })
	return out
}

// cUnionBodies adds to f the calls, declarations and field stores of g that
// f does not list at the same place, in source order.
func cUnionBodies(f, g *FunctionDecl) {
	type at struct{ line, col int }
	calls := map[at]bool{}
	for _, c := range f.Calls {
		calls[at{c.Line, c.StartCol}] = true
	}
	for _, c := range g.Calls {
		if !calls[at{c.Line, c.StartCol}] {
			f.Calls = append(f.Calls, c)
		}
	}
	sort.SliceStable(f.Calls, func(i, j int) bool {
		a, b := f.Calls[i], f.Calls[j]
		return a.Line < b.Line || (a.Line == b.Line && a.StartCol < b.StartCol)
	})
	decls := map[at]bool{}
	for _, d := range f.Declarations {
		decls[at{d.Line, d.StartCol}] = true
	}
	for _, d := range g.Declarations {
		if !decls[at{d.Line, d.StartCol}] {
			f.Declarations = append(f.Declarations, d)
		}
	}
	sort.SliceStable(f.Declarations, func(i, j int) bool {
		a, b := f.Declarations[i], f.Declarations[j]
		return a.Line < b.Line || (a.Line == b.Line && a.StartCol < b.StartCol)
	})
	stores := map[at]bool{}
	for _, st := range f.AttributeStores {
		stores[at{st.Line, st.StartCol}] = true
	}
	for _, st := range g.AttributeStores {
		if !stores[at{st.Line, st.StartCol}] {
			f.AttributeStores = append(f.AttributeStores, st)
		}
	}
	sort.SliceStable(f.AttributeStores, func(i, j int) bool {
		a, b := f.AttributeStores[i], f.AttributeStores[j]
		return a.Line < b.Line || (a.Line == b.Line && a.StartCol < b.StartCol)
	})
}

// cFunctionBroken: the function's definition is one of the broken ranges.
func cFunctionBroken(f *FunctionDecl, broken [][2]int) bool {
	for _, r := range broken {
		if r[0] <= f.StartLine && f.EndLine <= r[1] {
			return true
		}
	}
	return false
}

// cErrorCount counts the error and missing nodes of a tree.
func cErrorCount(root *sitter.Node) int {
	n := 0
	walkCNodes(root, func(node *sitter.Node) {
		if node.IsError() || node.IsMissing() {
			n++
		}
	})
	return n
}

// cBlankConditionals returns src with the lines of every conditional
// directive (#if, #ifdef, #ifndef, #elif, #else, #endif, continuation lines
// included) replaced by spaces and, with dropElse, the lines of every #elif
// and #else branch too. It returns nil when src has no conditional directive.
func cBlankConditionals(src []byte, dropElse bool) []byte {
	out := append([]byte(nil), src...)
	var inElse []bool // per open conditional: is its current branch #elif/#else
	found := false
	continued := false // the previous line was a directive ending in '\'
	for start := 0; start < len(out); {
		end := bytes.IndexByte(out[start:], '\n')
		if end < 0 {
			end = len(out)
		} else {
			end += start
		}
		line := out[start:end]
		blank := false
		if continued {
			blank = true
		} else {
			switch cConditionalKeyword(line) {
			case "if", "ifdef", "ifndef":
				inElse = append(inElse, false)
				blank = true
			case "elif", "else":
				if len(inElse) > 0 {
					inElse[len(inElse)-1] = true
				}
				blank = true
			case "endif":
				if len(inElse) > 0 {
					inElse = inElse[:len(inElse)-1]
				}
				blank = true
			}
			if blank {
				found = true
			}
		}
		if !blank && dropElse {
			for _, e := range inElse {
				if e {
					blank = true
					break
				}
			}
		}
		continued = blank && bytes.HasSuffix(bytes.TrimRight(line, "\r"), []byte("\\"))
		if blank {
			for i := range line {
				if line[i] != '\r' {
					line[i] = ' '
				}
			}
		}
		start = end + 1
	}
	if !found {
		return nil
	}
	return out
}

// cConditionalKeyword is the conditional directive a line opens ("if",
// "ifdef", "ifndef", "elif", "else", "endif"), or "".
func cConditionalKeyword(line []byte) string {
	rest := bytes.TrimLeft(line, " \t")
	if len(rest) == 0 || rest[0] != '#' {
		return ""
	}
	rest = bytes.TrimLeft(rest[1:], " \t")
	end := 0
	for end < len(rest) && (rest[end] >= 'a' && rest[end] <= 'z') {
		end++
	}
	switch word := string(rest[:end]); word {
	case "if", "ifdef", "ifndef", "elif", "else", "endif":
		return word
	}
	return ""
}
