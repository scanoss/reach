// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"maps"
	"os"
	"strings"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"

	"github.com/scanoss/reach/cpreproc"
)

// fragmentCallEndLine is the end line a fragment edge carries for call: the
// line its expression ends on when that is after line, else 0.
func fragmentCallEndLine(call *callgraph.FunctionCall, line int) int {
	if call == nil || call.EndLine <= line {
		return 0
	}
	return call.EndLine
}

// FragmentSourceLines collects the lines the exported call sites of the
// scanned source cover and reads their text for the fragment's
// source_lines. A call in a dependency's source is left out: its file path is
// relative to that dependency, not to the scanned tree.
type FragmentSourceLines struct {
	ctx   *Context
	lines map[string]map[int]bool // actual path -> lines
	paths map[string]string       // actual path -> exported path
}

// NewFragmentSourceLines returns an empty record of the source lines a fragment quotes.
func NewFragmentSourceLines(ctx *Context) *FragmentSourceLines {
	return &FragmentSourceLines{ctx: ctx, lines: make(map[string]map[int]bool), paths: make(map[string]string)}
}

// Add records the lines line..endLine of a call site in callerKey's file.
func (s *FragmentSourceLines) Add(callerKey string, line, endLine int) {
	if line <= 0 || s.ctx == nil || s.ctx.Graph == nil {
		return
	}
	decl := s.ctx.Graph.Functions[callerKey]
	if decl == nil || decl.FilePath == "" {
		return
	}
	s.addFile(decl.FilePath, line, endLine)
}

// addFile records the lines line..endLine of the source file at path.
func (s *FragmentSourceLines) addFile(path string, line, endLine int) {
	lines := s.lines[path]
	if lines == nil {
		location := NormalizeExportPath(s.ctx, path)
		if location.DependencyInfo != nil || location.FilePath == "" {
			return
		}
		s.paths[path] = location.FilePath
		lines = make(map[int]bool)
		s.lines[path] = lines
	}
	for n := line; n <= max(line, endLine); n++ {
		lines[n] = true
	}
}

// AddIncludes records the line of each #include directive and the lines of
// each string literal of a C or C++ graph, so a reader can quote a directive
// or a literal it matches.
func (s *FragmentSourceLines) AddIncludes() {
	if s.ctx == nil || s.ctx.Graph == nil {
		return
	}
	for path, includes := range s.ctx.Graph.CIncludes {
		for _, inc := range includes {
			if inc.Line > 0 {
				s.addFile(path, inc.Line, inc.Line)
			}
		}
	}
	for path, literals := range s.ctx.Graph.CStrings {
		for _, l := range literals {
			if l.Line > 0 {
				s.addFile(path, l.Line, l.EndLine)
			}
		}
	}
}

// AddInternal records the source lines of an internal edge's call site.
func (s *FragmentSourceLines) AddInternal(edge graphfrag.GraphFragmentEdge) {
	s.Add(edge.CallerKey, edge.Line, edge.EndLine)
}

// AddExternal records the source lines of an external call's site.
func (s *FragmentSourceLines) AddExternal(call *graphfrag.GraphFragmentExternal) {
	s.Add(call.CallerKey, call.Line, call.EndLine)
}

// Text reads the recorded lines from the source files, keyed by exported
// path. A file that cannot be read contributes nothing.
func (s *FragmentSourceLines) Text() map[string]map[int]string {
	if len(s.lines) == 0 {
		return nil
	}
	out := make(map[string]map[int]string, len(s.lines))
	for actual, wanted := range s.lines {
		data, err := os.ReadFile(actual) // #nosec G304 -- a source file the call graph parsed.
		if err != nil {
			continue
		}
		fileLines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
		text := make(map[int]string, len(wanted))
		for n := range wanted {
			if n >= 1 && n <= len(fileLines) {
				text[n] = fileLines[n-1]
			}
		}
		if cpreproc.IsCFile(actual) {
			// The conditionals of the file's #if 0 blocks, so a reader can
			// tell the code they disable.
			maps.Copy(text, cpreproc.RegionDirectives(fileLines))
		}
		if len(text) > 0 {
			out[s.paths[actual]] = text
		}
	}
	return out
}

// GraphFragmentSourceLines is the source_lines of a fragment built in memory:
// the lines of its call sites, constant references, declarations, casts,
// attribute stores, #include directives and C or C++ string literals, plus the
// conditionals of a C file's statically false regions.
func GraphFragmentSourceLines(ctx *Context, out *graphfrag.GraphFragmentExport) map[string]map[int]string {
	lines := NewFragmentSourceLines(ctx)
	lines.AddIncludes()
	for i := range out.InternalEdges {
		lines.AddInternal(out.InternalEdges[i])
	}
	for i := range out.ExternalCalls {
		lines.AddExternal(&out.ExternalCalls[i])
	}
	add := func(function, line, endLine int) { lines.Add(out.Functions[function].Key, line, endLine) }
	for _, r := range out.ConstantRefs {
		add(r.Function, r.Line, r.EndLine)
	}
	for _, d := range out.Declarations {
		add(d.Function, d.Line, d.EndLine)
	}
	for _, c := range out.Casts {
		add(c.Function, c.Line, c.EndLine)
	}
	for _, st := range out.AttributeStores {
		add(st.Function, st.Line, st.EndLine)
	}
	return lines.Text()
}
