// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// CInclude is one #include directive of a C or C++ file, as written.
//
// Header is the path between the delimiters (`mbedtls/rsa.h` for both
// `#include <mbedtls/rsa.h>` and `#include "mbedtls/rsa.h"`); System is true
// for the angle-bracket form. Text is the directive's source text without its
// line break; StartCol and EndCol are 1-based, EndCol one past the last
// character, as calls carry them. Conditional is true when the directive sits
// inside a preprocessor conditional (#if, #ifdef, #ifndef, #elif, #else).
type CInclude struct {
	Line        int
	StartCol    int
	EndCol      int
	Header      string
	System      bool
	Text        string
	Conditional bool
}

// cIncludeOf reads one preproc_include node; ok is false when it names no
// header (`#include MACRO`).
func cIncludeOf(node *sitter.Node, src []byte) (CInclude, bool) {
	path := node.ChildByFieldName("path")
	if path == nil {
		return CInclude{}, false
	}
	written := strings.TrimSpace(path.Content(src))
	system := path.Type() == "system_lib_string"
	if !system && path.Type() != cNodeStringLiteral {
		return CInclude{}, false
	}
	header := strings.Trim(written, "<>\"")
	if header == "" {
		return CInclude{}, false
	}
	text := strings.TrimRight(node.Content(src), "\r\n")
	start := node.StartPoint()
	return CInclude{
		Line:        int(start.Row) + 1,
		StartCol:    int(start.Column) + 1,
		EndCol:      int(start.Column) + 1 + len(text),
		Header:      header,
		System:      system,
		Text:        text,
		Conditional: cInsideConditional(node),
	}, true
}

// cInsideConditional reports whether node sits inside a preprocessor
// conditional block.
func cInsideConditional(node *sitter.Node) bool {
	for p := node.Parent(); p != nil; p = p.Parent() {
		switch p.Type() {
		case "preproc_if", "preproc_ifdef", "preproc_elif", "preproc_else", "preproc_elifdef":
			return true
		}
	}
	return false
}
