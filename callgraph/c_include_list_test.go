// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// cIncludesOf builds a project of the given files in ecosystem (c or cpp) and
// returns the include list the graph holds for name.
func cIncludesOf(t *testing.T, ecosystem string, files map[string]string, name string) []CInclude {
	t.Helper()
	dir := t.TempDir()
	for file, src := range files {
		if err := os.WriteFile(filepath.Join(dir, file), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilderForEcosystem(ecosystem, NewParserForEcosystem(ecosystem)).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	for path, includes := range graph.CIncludes {
		if filepath.Base(path) == name {
			return includes
		}
	}
	t.Fatalf("no includes for %s in %v", name, graph.CIncludes)
	return nil
}

func TestCIncludesListEveryDirective(t *testing.T) {
	t.Parallel()

	src := "#include <zork/cipher.h>\n" +
		"#include \"plugh.h\"\n" +
		"  #include   <stdio.h>\r\n" +
		"#ifdef HAVE_XYZZY\n" +
		"#include <xyzzy/kdf.h>\n" +
		"#else\n" +
		"#include \"frob.h\"\n" +
		"#endif\n" +
		"#include ZORK_HEADER\n" +
		"int main(void) { return zork_encrypt(1); }\n"
	want := []CInclude{
		{Line: 1, StartCol: 1, EndCol: 25, Header: "zork/cipher.h", System: true, Text: "#include <zork/cipher.h>"},
		{Line: 2, StartCol: 1, EndCol: 19, Header: "plugh.h", Text: "#include \"plugh.h\""},
		{Line: 3, StartCol: 3, EndCol: 23, Header: "stdio.h", System: true, Text: "#include   <stdio.h>"},
		{Line: 5, StartCol: 1, EndCol: 23, Header: "xyzzy/kdf.h", System: true, Text: "#include <xyzzy/kdf.h>", Conditional: true},
		{Line: 7, StartCol: 1, EndCol: 18, Header: "frob.h", Text: "#include \"frob.h\"", Conditional: true},
	}
	for _, ecosystem := range []string{ecosystemC, ecosystemCPP} {
		name := "main.c"
		if ecosystem == ecosystemCPP {
			name = "main.cpp"
		}
		got := cIncludesOf(t, ecosystem, map[string]string{name: src}, name)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s includes:\n got  %+v\n want %+v", ecosystem, got, want)
		}
	}
}

// A file with no #include has no entry, and the include list leaves the
// legacy Imports set as it was.
func TestCIncludesKeepImportsSet(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.c"), []byte("#include <zork/cipher.h>\nint f(void) { return 1; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.c"), []byte("int g(void) { return 2; }\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range analyses {
		switch filepath.Base(a.FilePath) {
		case "a.c":
			if a.Imports["zork/cipher.h"] != "zork/cipher.h" || len(a.CIncludes) != 1 {
				t.Errorf("a.c: imports %v, includes %+v", a.Imports, a.CIncludes)
			}
		case "b.c":
			if len(a.CIncludes) != 0 {
				t.Errorf("b.c: includes %+v, want none", a.CIncludes)
			}
		}
	}
}
