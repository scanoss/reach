// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// cCallLines builds a project of one C file and returns, by function name,
// the lines of the calls the graph lists for it, and the file's includes.
func cCallLines(t *testing.T, src string) (map[string][]int, []CInclude) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem("c", NewParserForEcosystem("c")).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	out := map[string][]int{}
	for _, fn := range graph.Functions {
		for _, call := range fn.Calls {
			out[fn.ID.Name] = append(out[fn.ID.Name], call.Line)
		}
		sort.Ints(out[fn.ID.Name])
	}
	var includes []CInclude
	for _, list := range graph.CIncludes {
		includes = append(includes, list...)
	}
	return out, includes
}

// A conditional that splits an `else if` chain, or an #if/#else pair whose
// branches each open the same block, is not C to tree-sitter. The function
// keeps every call after it, at the file's own lines, and the includes keep
// their conditional flag. Where only one branch can be read (two branches
// each opening a block), the #else branch is lost: narrow() at line 22.
func TestCConditionalSplittingAStatementKeepsTheFunction(t *testing.T) {
	t.Parallel()
	src := `#include <stdio.h>
#ifdef USE_ACME
# include <acme/acme.h>
#endif

int run(int argc, char **argv)
{
    while (argc-- > 0) {
        if (argv[0][0] == 'a')
            alpha();
# ifndef NO_BETA
        else if (argv[0][0] == 'b') {
            beta();
        }
# endif
        else
            gamma();
    }
#if defined(WIDE)
    if (wide()) {
#else
    if (narrow()) {
#endif
        acme_init(1);
    }
    acme_done();
    return 0;
}

int after(void) { return tail(); }
`
	calls, includes := cCallLines(t, src)
	want := map[string][]int{"run": {10, 13, 17, 20, 24, 26}, "after": {30}}
	for name, lines := range want {
		got := calls[name]
		if len(got) != len(lines) {
			t.Fatalf("%s calls at %v, want %v (all: %v)", name, got, lines, calls)
		}
		for i := range lines {
			if got[i] != lines[i] {
				t.Fatalf("%s calls at %v, want %v", name, got, lines)
			}
		}
	}
	if len(includes) != 2 || includes[0].Header != "stdio.h" || includes[0].Conditional ||
		includes[1].Header != "acme/acme.h" || !includes[1].Conditional || includes[1].Line != 3 {
		t.Fatalf("includes = %+v", includes)
	}
}

// Blanking keeps every offset: directive lines and continuation lines become
// spaces, other lines are untouched; with dropElse, #else branches go too.
func TestCBlankConditionals(t *testing.T) {
	t.Parallel()
	src := "a();\n#if X \\\n  && Y\nb();\n#else\nc();\n#endif\nd();\n"
	keep := string(cBlankConditionals([]byte(src), false))
	if want := "a();\n" + "       \n" + "      \n" + "b();\n" + "     \n" + "c();\n" + "      \n" + "d();\n"; keep != want {
		t.Fatalf("keep = %q, want %q", keep, want)
	}
	drop := string(cBlankConditionals([]byte(src), true))
	if want := "a();\n" + "       \n" + "      \n" + "b();\n" + "     \n" + "    \n" + "      \n" + "d();\n"; drop != want {
		t.Fatalf("drop = %q, want %q", drop, want)
	}
	if cBlankConditionals([]byte("a();\n#define X 1\n"), false) != nil {
		t.Fatal("a file without conditionals has nothing to blank")
	}
}

// A function a macro declares keeps its calls: one argument
// (`PHP_FUNCTION(name)`, read as a parenthesized declarator) is named by the
// argument, more (`ZEND_METHOD(Cls, name)`, read as a call statement and a
// block) after the macro and its identifier arguments.
func TestCMacroDeclaredFunctions(t *testing.T) {
	t.Parallel()
	src := `PHP_FUNCTION(acme_hash)
{
    acme_init();
}

ZEND_METHOD(Acme, sign)
{
    acme_sign(1);
}

static int plain(void) { return acme_done(); }
`
	calls, _ := cCallLines(t, src)
	for name, lines := range map[string][]int{"acme_hash": {3}, "ZEND_METHOD_Acme_sign": {8}, "plain": {11}} {
		if got := calls[name]; len(got) != len(lines) || got[0] != lines[0] {
			t.Fatalf("%s calls at %v, want %v (all: %v)", name, got, lines, calls)
		}
	}
}

// A file whose backends define the same function in #if/#elif branches,
// each complete, keeps every branch's body when another function of the file
// is cut short: the reparse (which blanks #elif branches) only fills the
// broken range.
func TestCConditionalReparseKeepsWholeBranches(t *testing.T) {
	t.Parallel()
	src := `#if defined(USE_A)
int digest(void) { return a_digest(); }
#elif defined(USE_B)
int digest(void) { return b_digest(); }
#endif

int run(int k)
{
    if (k == 1)
        one();
#ifdef HAVE_TWO
    else if (k == 2)
        two();
#endif
    else
        three();
    return 0;
}
`
	calls, _ := cCallLines(t, src)
	lines := []int{}
	for _, l := range calls {
		lines = append(lines, l...)
	}
	sort.Ints(lines)
	if want := []int{2, 4, 10, 13, 16}; len(lines) != len(want) || lines[0] != 2 || lines[1] != 4 || lines[4] != 16 {
		t.Fatalf("call lines %v, want %v (by function: %v)", lines, want, calls)
	}
}

// A broken function both trees read keeps the calls of both: the own tree's
// #else branch the reparse blanked, and the reparse's calls past the error.
func TestCMergeFunctionsUnionsBrokenBodies(t *testing.T) {
	t.Parallel()
	own := []FunctionDecl{
		{StartLine: 1, EndLine: 3, Calls: []FunctionCall{{Line: 2, StartCol: 5}}},
		{StartLine: 5, EndLine: 9, Calls: []FunctionCall{{Line: 6, StartCol: 5}, {Line: 7, StartCol: 5}}},
	}
	alt := []FunctionDecl{
		{StartLine: 1, EndLine: 3},
		{StartLine: 5, EndLine: 20, Calls: []FunctionCall{{Line: 6, StartCol: 5}, {Line: 15, StartCol: 5}}},
	}
	got := cMergeFunctions(own, [][2]int{{5, 12}}, alt)
	if len(got) != 2 || len(got[0].Calls) != 1 {
		t.Fatalf("merged = %+v", got)
	}
	var lines []int
	for _, c := range got[1].Calls {
		lines = append(lines, c.Line)
	}
	if got[1].EndLine != 20 || len(lines) != 3 || lines[0] != 6 || lines[1] != 7 || lines[2] != 15 {
		t.Fatalf("broken function = %d-%d calls at %v, want 5-20 at [6 7 15]", got[1].StartLine, got[1].EndLine, lines)
	}
}
