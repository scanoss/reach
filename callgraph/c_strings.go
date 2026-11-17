// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// cStringMaxBytes is the longest string literal a C or C++ file lists:
// crypto names are short, and a longer literal (a log message, a usage text)
// would only grow the fragment of a log-heavy project.
const cStringMaxBytes = 256

// CString is one string literal of a C or C++ file, as written: Text holds
// the literal with its prefix and quotes (`L"x"`). Line, StartCol and EndCol
// locate it (columns 1-based, EndCol one past the last character, as calls
// carry them); EndLine is set only for a literal continued over lines.
type CString struct {
	Line, StartCol, EndCol, EndLine int
	Text                            string
}

// cStringLiterals lists the string literals of a file in source order: every
// string_literal node, each piece of a concatenation on its own, at any
// depth (function bodies, global initializers, attributes). An #include's
// path is not one, and a #define's body is not parsed; a literal longer
// than cStringMaxBytes is left out.
func cStringLiterals(root *sitter.Node, src []byte) []CString {
	var out []CString
	walkCNodes(root, func(n *sitter.Node) {
		if n.Type() != cNodeStringLiteral || n.EndByte()-n.StartByte() > cStringMaxBytes {
			return
		}
		if p := n.Parent(); p != nil && p.Type() == cNodePreprocInclude {
			return
		}
		start, end := n.StartPoint(), n.EndPoint()
		s := CString{
			Line: int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
			Text: n.Content(src),
		}
		if end.Row != start.Row {
			s.EndLine = int(end.Row) + 1
		}
		out = append(out, s)
	})
	return out
}
