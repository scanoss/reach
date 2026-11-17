// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import sitter "github.com/smacker/go-tree-sitter"

// NodeObjectLiteral is one outermost object expression of a JavaScript or
// TypeScript file: a call argument, a variable initializer, a return value, an
// array element, an assigned value. An object written inside another object
// expression, its method bodies included, is part of that object's Text and is
// not listed on its own. An empty object, an object destructuring pattern and
// a TypeScript object type are not object expressions here.
//
// Line and EndLine are 1-based; StartCol and EndCol are 1-based, start
// inclusive, end exclusive. Text is the object's exact source. CallerKey is the
// key of the innermost function whose span holds the object, the key its call
// sites carry; at module level it is the module's `<module>` key, which the
// module's own top-level calls carry.
type NodeObjectLiteral struct {
	Line      int
	StartCol  int
	EndLine   int
	EndCol    int
	Text      string
	CallerKey string
}

// collectNodeObjectLiterals lists, in source order, the outermost non-empty
// object expressions of the file, each keyed by the tightest of functions
// that holds it, or by the module key when none does.
func collectNodeObjectLiterals(root *sitter.Node, src []byte, functions []FunctionDecl, modulePath string) []NodeObjectLiteral {
	moduleKey := FunctionID{Package: modulePath, Name: moduleInitMethodName}.String()
	var out []NodeObjectLiteral
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n == nil {
			return
		}
		if n.Type() == nodeObjectLiteral {
			if nodeObjectHasMembers(n) {
				start, end := n.StartPoint(), n.EndPoint()
				lit := NodeObjectLiteral{
					Line:     int(start.Row) + 1,
					StartCol: int(start.Column) + 1,
					EndLine:  int(end.Row) + 1,
					EndCol:   int(end.Column) + 1,
					Text:     n.Content(src),
				}
				lit.CallerKey = enclosingNodeFunctionKey(functions, lit, moduleKey)
				out = append(out, lit)
			}
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	return out
}

// nodeObjectHasMembers reports whether an object expression holds anything
// but comments: `{}` and `{ /* none */ }` match no property pattern.
func nodeObjectHasMembers(n *sitter.Node) bool {
	for i := 0; i < int(n.NamedChildCount()); i++ {
		if n.NamedChild(i).Type() != "comment" {
			return true
		}
	}
	return false
}

// enclosingNodeFunctionKey returns the key of the function with the tightest
// span that holds lit. Spans of one file nest, so the holder that starts last
// is the innermost; a class's `<clinit>`, which spans the class body, loses to
// any method inside it.
func enclosingNodeFunctionKey(functions []FunctionDecl, lit NodeObjectLiteral, fallback string) string {
	key := fallback
	bestLine, bestCol := 0, 0
	for i := range functions {
		fn := &functions[i]
		if fn.ID.Name == moduleInitMethodName && fn.ID.Type == "" {
			continue
		}
		if !nodeSpanHolds(fn, lit) {
			continue
		}
		if fn.StartLine > bestLine || (fn.StartLine == bestLine && fn.StartCol > bestCol) {
			key, bestLine, bestCol = fn.ID.String(), fn.StartLine, fn.StartCol
		}
	}
	return key
}

// nodeSpanHolds reports whether the function's span holds the object's span.
func nodeSpanHolds(fn *FunctionDecl, lit NodeObjectLiteral) bool {
	startsBefore := fn.StartLine < lit.Line || (fn.StartLine == lit.Line && fn.StartCol <= lit.StartCol)
	endsAfter := fn.EndLine > lit.EndLine || (fn.EndLine == lit.EndLine && fn.EndCol >= lit.EndCol)
	return startsBefore && endsAfter
}
