// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// nodeObjectLiteralsOf builds a project of the given files and returns the
// object literals the graph holds for name.
func nodeObjectLiteralsOf(t *testing.T, files map[string]string, name string) []NodeObjectLiteral {
	t.Helper()
	graph := buildNodeFiles(t, files)
	for path, literals := range graph.NodeObjectLiterals {
		if filepath.Base(path) == name {
			return literals
		}
	}
	return nil
}

func nodeLiteralTexts(literals []NodeObjectLiteral) []string {
	texts := make([]string, len(literals))
	for i, lit := range literals {
		texts[i] = lit.Text
	}
	return texts
}

func assertNodeLiteralTexts(t *testing.T, got []NodeObjectLiteral, want ...string) {
	t.Helper()
	texts := nodeLiteralTexts(got)
	if strings.Join(texts, "\n---\n") != strings.Join(want, "\n---\n") {
		t.Errorf("object literals:\n got  %q\n want %q", texts, want)
	}
}

func moduleKeyOf(modulePath string) string {
	return FunctionID{Package: modulePath, Name: moduleInitMethodName}.String()
}

func TestNodeObjectLiteralsCallArgumentWithExactSpan(t *testing.T) {
	t.Parallel()

	src := "import zork from 'zork-lib';\n" +
		"zork.seal(payload, secret, { mode: 'quux', rounds: 3 });\n"
	got := nodeObjectLiteralsOf(t, map[string]string{"mod.js": src}, "mod.js")
	if len(got) != 1 {
		t.Fatalf("object literals = %+v, want one", got)
	}
	lit := got[0]
	// Line 2 is `zork.seal(payload, secret, { mode: 'quux', rounds: 3 });`:
	// the brace is the 28th character and the closing brace the 54th, so the
	// exclusive end column is 55.
	line := strings.Split(src, "\n")[1]
	start := strings.Index(line, "{") + 1
	end := strings.LastIndex(line, "}") + 2
	want := NodeObjectLiteral{
		Line: 2, StartCol: 28, EndLine: 2, EndCol: 55,
		Text:      "{ mode: 'quux', rounds: 3 }",
		CallerKey: moduleKeyOf("app/mod"),
	}
	if start != want.StartCol || end != want.EndCol {
		t.Fatalf("test arithmetic: columns from source %d..%d, want %d..%d", start, end, want.StartCol, want.EndCol)
	}
	if lit != want {
		t.Errorf("literal:\n got  %+v\n want %+v", lit, want)
	}
	if line[lit.StartCol-1:lit.EndCol-1] != lit.Text {
		t.Errorf("source[%d:%d] = %q, want the text %q", lit.StartCol, lit.EndCol, line[lit.StartCol-1:lit.EndCol-1], lit.Text)
	}
}

func TestNodeObjectLiteralsInitializerCallerKeys(t *testing.T) {
	t.Parallel()

	src := `const head = { alg: 'frob-256' };
function build() {
  const opts = { level: 9 };
  return opts;
}
`
	got := nodeObjectLiteralsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeLiteralTexts(t, got, "{ alg: 'frob-256' }", "{ level: 9 }")
	if len(got) != 2 {
		return
	}
	if got[0].CallerKey != moduleKeyOf("app/mod") {
		t.Errorf("module-level caller key = %q, want %q", got[0].CallerKey, moduleKeyOf("app/mod"))
	}
	if want := (FunctionID{Package: "app/mod", Name: "build"}).String(); got[1].CallerKey != want {
		t.Errorf("function caller key = %q, want %q", got[1].CallerKey, want)
	}
}

func TestNodeObjectLiteralsNestedObjectOnlyOuter(t *testing.T) {
	t.Parallel()

	src := `const cfg = {
  outer: 1,
  inner: { deep: 'plugh' },
};
`
	got := nodeObjectLiteralsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeLiteralTexts(t, got, "{\n  outer: 1,\n  inner: { deep: 'plugh' },\n}")
	if len(got) == 1 && (got[0].Line != 1 || got[0].EndLine != 4 || got[0].StartCol != 13 || got[0].EndCol != 2) {
		t.Errorf("span = %d:%d..%d:%d, want 1:13..4:2", got[0].Line, got[0].StartCol, got[0].EndLine, got[0].EndCol)
	}
}

func TestNodeObjectLiteralsInsideArrayInsideCall(t *testing.T) {
	t.Parallel()

	src := `import xyzzy from 'xyzzy-lib';
export function run() {
  xyzzy.batch([{ id: 1 }, { id: 2 }]);
}
`
	got := nodeObjectLiteralsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeLiteralTexts(t, got, "{ id: 1 }", "{ id: 2 }")
	want := FunctionID{Package: "app/mod", Name: "run"}.String()
	for _, lit := range got {
		if lit.CallerKey != want {
			t.Errorf("%s caller key = %q, want %q", lit.Text, lit.CallerKey, want)
		}
	}
}

func TestNodeObjectLiteralsMethodBodyObjectIsInOuterText(t *testing.T) {
	t.Parallel()

	src := `module.exports = {
  make() {
    return { kind: 'grault' };
  },
};
`
	got := nodeObjectLiteralsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeLiteralTexts(t, got, "{\n  make() {\n    return { kind: 'grault' };\n  },\n}")
}

func TestNodeObjectLiteralsCallbackGetsItsOwnKey(t *testing.T) {
	t.Parallel()

	src := `import garply from 'garply-lib';
garply.on('ready', () => garply.emit({ state: 'up' }));
`
	got := nodeObjectLiteralsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeLiteralTexts(t, got, "{ state: 'up' }")
	if want := (FunctionID{Package: "app/mod", Name: "<anonymous>@2:20"}).String(); len(got) == 1 && got[0].CallerKey != want {
		t.Errorf("caller key = %q, want %q", got[0].CallerKey, want)
	}
}

func TestNodeObjectLiteralsSkipsPatternsAndEmptyObjects(t *testing.T) {
	t.Parallel()

	src := `const { waldo, fred: f } = load();
const blank = {};
const commented = { /* nothing */ };
function take({ a, b }) { return a + b; }
`
	got := nodeObjectLiteralsOf(t, map[string]string{"mod.js": src}, "mod.js")
	assertNodeLiteralTexts(t, got)
}

func TestNodeObjectLiteralsTypeScriptTypesAreNotObjects(t *testing.T) {
	t.Parallel()

	src := `interface Shape { side: number }
type Opts = { mode: string; size: number };
function make(opts: { mode: string }): Opts {
  return { mode: opts.mode, size: 4 };
}
`
	got := nodeObjectLiteralsOf(t, map[string]string{"mod.ts": src}, "mod.ts")
	assertNodeLiteralTexts(t, got, "{ mode: opts.mode, size: 4 }")
	if want := (FunctionID{Package: "app/mod", Name: "make"}).String(); len(got) == 1 && got[0].CallerKey != want {
		t.Errorf("caller key = %q, want %q", got[0].CallerKey, want)
	}
}

// An outermost object bound to a variable carries it, as a call's assigned
// variable: a const, let or var declarator, or an assignment to a plain name,
// with the column the name starts at, and its line when the declarator starts
// on another line. An argument, a nested object and a member target carry
// none.
func TestNodeObjectLiteralsAssignedVar(t *testing.T) {
	t.Parallel()

	src := `const head = { alg: 'frob-256' };
let opts = { mode: 'quux' };
var legacy = { rounds: 3 };
current = { level: 9 };
zork.seal(payload, { mode: 'quux' });
const outer = { inner: { deep: 1 } };
const spread =
  { wide: true };
cfg.value = { tag: 1 };
const wrapped = ({ paren: 1 });
`
	got := nodeObjectLiteralsOf(t, map[string]string{"mod.js": src}, "mod.js")
	type assigned struct {
		Line           int
		AssignedVar    string
		AssignStartCol int
		AssignLine     int
	}
	var have []assigned
	for _, lit := range got {
		have = append(have, assigned{lit.Line, lit.AssignedVar, lit.AssignStartCol, lit.AssignLine})
	}
	want := []assigned{
		{1, "head", 7, 0},
		{2, "opts", 5, 0},
		{3, "legacy", 5, 0},
		{4, "current", 1, 0},
		{5, "", 0, 0},
		{6, "outer", 7, 0},
		{8, "spread", 7, 7},
		{9, "", 0, 0},
		{10, "wrapped", 7, 0},
	}
	if fmt.Sprint(have) != fmt.Sprint(want) {
		t.Errorf("assigned variables:\n got  %+v\n want %+v", have, want)
	}
}
