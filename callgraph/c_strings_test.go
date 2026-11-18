// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// cStringsOf builds a project of one file in ecosystem (c or cpp) and
// returns the string literals the graph lists for it.
func cStringsOf(t *testing.T, ecosystem, name, src string) []CString {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem(ecosystem, NewParserForEcosystem(ecosystem)).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	for path, literals := range graph.CStrings {
		if filepath.Base(path) == name {
			return literals
		}
	}
	return nil
}

// Every string literal of a file is listed as written, in source order: in
// a global table, a call, a comparison, a return, each piece of a
// concatenation; not an #include path, a #define body, a comment or a
// literal over the size cap.
func TestCStringsListEveryLiteral(t *testing.T) {
	t.Parallel()
	long := `"` + strings.Repeat("x", cStringMaxBytes) + `"`
	src := "#include \"zork.h\"\n" +
		"#define ZORK_NAME \"zork-define\"\n" +
		"static const struct alg algs[] = { { .name = \"zork-128\" } };\n" +
		"int f(const char *x) {\n" +
		"    /* \"zork-comment\" */\n" +
		"    if (strcmp(x, \"zork-256\") == 0) return 1;\n" +
		"    puts(\"zork-\" L\"wide\");\n" +
		"    puts(" + long + ");\n" +
		"    return g(\"a\\\n" +
		"b\");\n" +
		"}\n"
	want := []CString{
		{Line: 3, StartCol: 46, EndCol: 56, Text: `"zork-128"`},
		{Line: 6, StartCol: 19, EndCol: 29, Text: `"zork-256"`},
		{Line: 7, StartCol: 10, EndCol: 17, Text: `"zork-"`},
		{Line: 7, StartCol: 18, EndCol: 25, Text: `L"wide"`},
		{Line: 9, StartCol: 14, EndCol: 3, EndLine: 10, Text: "\"a\\\nb\""},
	}
	for _, tc := range []struct{ ecosystem, name string }{{ecosystemC, "main.c"}, {ecosystemCPP, "main.cpp"}} {
		if got := cStringsOf(t, tc.ecosystem, tc.name, src); !reflect.DeepEqual(got, want) {
			t.Errorf("%s literals:\n got  %+v\n want %+v", tc.ecosystem, got, want)
		}
	}
}

// A file without a literal has no entry.
func TestCStringsNoneWithoutLiterals(t *testing.T) {
	t.Parallel()
	if got := cStringsOf(t, ecosystemC, "main.c", "int f(void) { return 1; }\n"); got != nil {
		t.Errorf("literals = %+v, want none", got)
	}
}
