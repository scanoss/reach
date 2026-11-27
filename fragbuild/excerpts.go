// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"bytes"
	"path/filepath"
	"unicode/utf8"

	"github.com/scanoss/reach/graphfrag"
)

// excerptCacheBytes bounds the source an export keeps in memory. Excerpts of
// one file read the same file, so a file is read once while the files in use
// fit under the bound.
const excerptCacheBytes = 64 << 20

// SourceExcerpts cuts excerpts out of the files a scan analyzed.
// It reads only files under the project root or a dependency source directory
// the scan resolved, after resolving symlinks, so a path in the graph cannot
// make an export quote a file outside them.
type SourceExcerpts struct {
	roots    []string
	readFile func(string) ([]byte, error)
	files    map[string]*SourceFile
	// order lists files in the order they were cached, oldest first.
	order []string
	bytes int
}

// SourceFile is one file's text, split into lines, or why it has none.
type SourceFile struct {
	content     []byte
	lineStarts  []int
	unavailable string
}

// NewSourceExcerpts reads files under the artifacts' roots through readFile.
func NewSourceExcerpts(artifacts *Artifacts, readFile func(string) ([]byte, error)) *SourceExcerpts {
	x := &SourceExcerpts{readFile: readFile, files: make(map[string]*SourceFile)}
	add := func(dir string) {
		if dir == "" {
			return
		}
		root := artifacts.AbsPath(dir)
		if resolved, err := filepath.EvalSymlinks(root); err == nil {
			root = resolved
		}
		x.roots = append(x.roots, root)
	}
	add(artifacts.ProjectRoot)
	for i := range artifacts.Dependencies {
		add(artifacts.Dependencies[i].Dir)
	}
	return x
}

// Excerpt returns the window around focus in the file at path, or the reason
// there is none.
func (x *SourceExcerpts) Excerpt(path string, focus int) (*graphfrag.ExportExcerpt, string) {
	if path == "" {
		return nil, graphfrag.ExcerptNoSource
	}
	file := x.File(path)
	if file.unavailable != "" {
		return nil, file.unavailable
	}
	if focus < 1 || focus > len(file.lineStarts) {
		return nil, graphfrag.ExcerptOutOfRange
	}
	first := max(1, focus-graphfrag.ExcerptContextLines)
	last := min(len(file.lineStarts), focus+graphfrag.ExcerptContextLines)
	out := &graphfrag.ExportExcerpt{StartLine: first, FocusLine: focus, Lines: make([]string, 0, last-first+1)}
	for line := first; line <= last; line++ {
		text, cut := capLine(file.Line(line))
		out.Lines = append(out.Lines, text)
		out.Truncated = out.Truncated || cut
	}
	return out, ""
}

// File returns the file at path, read once while it fits the cache.
func (x *SourceExcerpts) File(path string) *SourceFile {
	if file, ok := x.files[path]; ok {
		return file
	}
	file := x.load(path)
	x.files[path] = file
	x.order = append(x.order, path)
	x.bytes += len(file.content)
	for x.bytes > excerptCacheBytes && len(x.order) > 1 {
		oldest := x.order[0]
		x.order = x.order[1:]
		x.bytes -= len(x.files[oldest].content)
		delete(x.files, oldest)
	}
	return file
}

func (x *SourceExcerpts) load(path string) *SourceFile {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !x.allowed(resolved) {
		return &SourceFile{unavailable: graphfrag.ExcerptNoSource}
	}
	content, err := x.readFile(resolved)
	if err != nil {
		return &SourceFile{unavailable: graphfrag.ExcerptUnreadable}
	}
	return &SourceFile{content: content, lineStarts: lineStarts(content)}
}

func (x *SourceExcerpts) allowed(path string) bool {
	for _, root := range x.roots {
		if _, ok := RelativeToRoot(root, path); ok {
			return true
		}
	}
	return false
}

// lineStarts returns the offset of each line. A final newline ends the last
// line rather than starting an empty one.
func lineStarts(content []byte) []int {
	if len(content) == 0 {
		return nil
	}
	starts := []int{0}
	for i, b := range content {
		if b == '\n' && i+1 < len(content) {
			starts = append(starts, i+1)
		}
	}
	return starts
}

// Unavailable is why the file has no text, or "" when it has.
func (f *SourceFile) Unavailable() string { return f.unavailable }

// Lines is the number of lines of the file.
func (f *SourceFile) Lines() int { return len(f.lineStarts) }

// Line returns the 1-based line n without its line ending.
func (f *SourceFile) Line(n int) []byte {
	end := len(f.content)
	if n < len(f.lineStarts) {
		end = f.lineStarts[n]
	}
	text := f.content[f.lineStarts[n-1]:end]
	text = bytes.TrimSuffix(text, []byte("\n"))
	return bytes.TrimSuffix(text, []byte("\r"))
}

// capLine keeps the first ExcerptLineMaxRunes runes of a line and reports
// whether it cut any.
func capLine(text []byte) (string, bool) {
	offset := 0
	for runes := 0; offset < len(text); runes++ {
		if runes == graphfrag.ExcerptLineMaxRunes {
			return string(text[:offset]), true
		}
		_, size := utf8.DecodeRune(text[offset:])
		offset += size
	}
	return string(text), false
}
