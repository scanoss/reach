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

func TestGoParser_Basics(t *testing.T) {
	p := NewGoParser()

	if got := p.PackageSeparator(); got != "/" {
		t.Fatalf("PackageSeparator() = %q, want /", got)
	}
	if !p.SkipsDirNamed("testdata") || !p.SkipsDirNamed("_asm") {
		t.Fatalf("SkipsDirNamed testdata/_ prefix = %v/%v", p.SkipsDirNamed("testdata"), p.SkipsDirNamed("_asm"))
	}
	if p.SkipsDirNamed("vendor") {
		t.Fatal("vendor is a global skip, not a Go shape skip")
	}
	if got := p.SubPackagePath("example.com/root", "sub"); got != "example.com/root/sub" {
		t.Fatalf("SubPackagePath() = %q", got)
	}
}

func TestGoParser_ParseDirectorySelectedReadsOnlyKeptFiles(t *testing.T) {
	var parser SelectiveParser = NewGoParser()
	dir := t.TempDir()
	for _, name := range []string{"a.go", "b.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("package p\n\nfunc F() {}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	kept := filepath.Join(dir, "a.go")
	analyses, err := parser.ParseDirectorySelected(dir, "example.com/p", func(path string) bool { return path == kept })
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 1 || analyses[0].FilePath != kept {
		t.Fatalf("analyses = %+v, want only %s", analyses, kept)
	}
}

func TestGoParser_ParseDirectoryAndFile(t *testing.T) {
	p := NewGoParser()
	dir := t.TempDir()

	src := `package mypkg

import (
	"fmt"
	alias "crypto/aes"
	"crypto/cipher"
)

func helper() {
	fmt.Println("ok")
}

func TestGoParser_ParseDirectoryIncludesTestsWhenConfigured(t *testing.T) {
	p := NewGoParser(WithIncludeTests(true))
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "crypto_test.go"), []byte("package mypkg\nfunc TestX(){}"), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "example.com/project/mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis (test file included), got %d", len(analyses))
	}
}

type S struct{}

func (s *S) Encrypt(data []byte) {
	_, _ = alias.NewCipher(data)
	var b cipher.Block
	_ = b
	helper()
	s.internal()
}

func (s *S) internal() {}
`
	if err := os.WriteFile(filepath.Join(dir, "crypto.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "crypto_test.go"), []byte("package mypkg\nfunc TestX(){}"), 0o644); err != nil {
		t.Fatal(err)
	}

	analyses, err := p.ParseDirectory(dir, "example.com/project/mypkg")
	if err != nil {
		t.Fatalf("ParseDirectory error: %v", err)
	}
	if len(analyses) != 1 {
		t.Fatalf("expected 1 analysis (non-test file), got %d", len(analyses))
	}

	analysis := analyses[0]
	if analysis.PackageName != "mypkg" {
		t.Fatalf("PackageName = %q, want mypkg", analysis.PackageName)
	}
	if analysis.Imports["fmt"] != "fmt" {
		t.Fatalf("fmt import not resolved correctly: %#v", analysis.Imports)
	}
	if analysis.Imports["alias"] != "crypto/aes" {
		t.Fatalf("alias import not resolved correctly: %#v", analysis.Imports)
	}
	if analysis.Imports["cipher"] != "crypto/cipher" {
		t.Fatalf("cipher import not resolved correctly: %#v", analysis.Imports)
	}

	if len(analysis.Functions) < 3 {
		t.Fatalf("expected at least 3 functions, got %d", len(analysis.Functions))
	}

	foundMethod := false
	foundHelperCall := false
	foundAliasCall := false
	for _, fn := range analysis.Functions {
		if fn.ID.Name == "Encrypt" {
			foundMethod = true
			for _, c := range fn.Calls {
				if c.Callee.Package == "example.com/project/mypkg" && c.Callee.Name == "helper" {
					foundHelperCall = true
				}
				if c.Callee.Package == "crypto/aes" && c.Callee.Name == "NewCipher" {
					foundAliasCall = true
				}
			}
		}
	}
	if !foundMethod {
		t.Fatal("expected method declaration for (*S).Encrypt")
	}
	if !foundHelperCall {
		t.Fatal("expected helper() call resolution in method")
	}
	if !foundAliasCall {
		t.Fatal("expected alias.NewCipher() call resolution in method")
	}

	_, err = p.ParseFile(filepath.Join(dir, "missing.go"), "example.com/project/mypkg")
	if err == nil {
		t.Fatal("expected ParseFile error for missing file")
	}
}

func TestGoParser_ParseDirectoryErrors(t *testing.T) {
	p := NewGoParser()
	_, err := p.ParseDirectory(filepath.Join(t.TempDir(), "missing"), "pkg")
	if err == nil {
		t.Fatal("expected ParseDirectory error for missing directory")
	}
}

func TestGoParser_ReturnSources(t *testing.T) {
	p := NewGoParser()
	dir := t.TempDir()

	src := `package mypkg

import (
	alias "crypto/aes"
	"crypto/cipher"
)

func direct(value cipher.Block) cipher.Block {
	return value
}

func factory(key []byte) (cipher.Block, error) {
	return alias.NewCipher(key)
}

func unknown() any {
	return nil
}

func bare() {
	return
}

func withClosure(value cipher.Block, wrong cipher.Block) cipher.Block {
	closure := func() cipher.Block { return wrong }
	_ = closure
	return value
}
`
	path := filepath.Join(dir, "returns.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	analysis, err := p.ParseFile(path, "example.com/project/mypkg")
	if err != nil {
		t.Fatalf("ParseFile error: %v", err)
	}

	direct := findGoFunction(t, analysis, "direct")
	if len(direct.ReturnSources) != 1 {
		t.Fatalf("direct ReturnSources len = %d, want 1", len(direct.ReturnSources))
	}
	if got := direct.ReturnSources[0]; got.Type != "VARIABLE" || got.Name != "value" {
		t.Fatalf("direct ReturnSources[0] = %+v, want VARIABLE value", got)
	}

	factory := findGoFunction(t, analysis, "factory")
	if len(factory.ReturnSources) != 1 {
		t.Fatalf("factory ReturnSources len = %d, want 1", len(factory.ReturnSources))
	}
	callTarget := factory.ReturnSources[0].CallTarget
	if factory.ReturnSources[0].Type != "CALL_RESULT" || callTarget == nil {
		t.Fatalf("factory ReturnSources[0] = %+v, want CALL_RESULT", factory.ReturnSources[0])
	}
	if callTarget.Package != "crypto/aes" || callTarget.Name != "NewCipher" {
		t.Fatalf("factory call target = %+v, want crypto/aes.NewCipher", *callTarget)
	}

	unknown := findGoFunction(t, analysis, "unknown")
	if len(unknown.ReturnSources) != 1 {
		t.Fatalf("unknown ReturnSources len = %d, want 1", len(unknown.ReturnSources))
	}
	if got := unknown.ReturnSources[0]; got.Type != "VALUE" || got.Value != "nil" {
		t.Fatalf("unknown ReturnSources[0] = %+v, want VALUE nil", got)
	}

	bare := findGoFunction(t, analysis, "bare")
	if len(bare.ReturnSources) != 0 {
		t.Fatalf("bare ReturnSources len = %d, want 0", len(bare.ReturnSources))
	}

	withClosure := findGoFunction(t, analysis, "withClosure")
	if len(withClosure.ReturnSources) != 1 || withClosure.ReturnSources[0].Name != "value" {
		t.Fatalf("withClosure ReturnSources = %#v, want only value", withClosure.ReturnSources)
	}
}

func findGoFunction(t *testing.T, analysis *FileAnalysis, name string) *FunctionDecl {
	t.Helper()
	for i := range analysis.Functions {
		if analysis.Functions[i].ID.Name == name {
			return &analysis.Functions[i]
		}
	}
	t.Fatalf("missing function %q", name)
	return nil
}

func TestGoParser_CallColumnsAreOneBasedExclusive(t *testing.T) {
	dir := t.TempDir()
	const source = "package p\nfunc run() { helper() }\nfunc helper() {}\n"
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}

	analysis, err := NewGoParser().ParseFile(path, "example.com/p")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	for _, fn := range analysis.Functions {
		for _, call := range fn.Calls {
			if call.Callee.Name != "helper" {
				continue
			}
			if call.StartCol != 14 || call.EndCol != 22 {
				t.Fatalf("helper() columns = %d:%d, want 14:22 (1-based, end-exclusive)", call.StartCol, call.EndCol)
			}
			return
		}
	}
	t.Fatal("helper() call not found")
}

// TestGoParser_VersionDirectoryImportName: an unaliased /vN import binds the
// module-rule name and also vN, for modules that declare `package vN`; an
// import claiming vN keeps it, and two /vN paths offering it leave it unbound.
func TestGoParser_VersionDirectoryImportName(t *testing.T) {
	cases := []struct {
		name, imports string
		want          map[string]string // call text -> callee package ("" unresolved)
	}{
		{
			name:    "package named vN",
			imports: `import "example.com/lib/sub/v2"`,
			want:    map[string]string{"v2.Open": "example.com/lib/sub/v2", "sub.Close": "example.com/lib/sub/v2"},
		},
		{
			name:    "explicit alias keeps vN",
			imports: "import (\n\t\"example.com/lib/sub/v2\"\n\tv2 \"example.com/other\"\n)",
			want:    map[string]string{"v2.Open": "example.com/other", "sub.Close": "example.com/lib/sub/v2"},
		},
		{
			name:    "two vN paths are ambiguous",
			imports: "import (\n\t\"example.com/a/v2\"\n\t\"example.com/sub/v2\"\n)",
			want:    map[string]string{"v2.Open": "", "sub.Close": "example.com/sub/v2"},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			source := "package p\n" + c.imports + "\nfunc run() {\n\tv2.Open()\n\tsub.Close()\n}\n"
			path := filepath.Join(dir, "main.go")
			if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
				t.Fatal(err)
			}
			analysis, err := NewGoParser().ParseFile(path, "example.com/p")
			if err != nil {
				t.Fatalf("ParseFile: %v", err)
			}
			got := map[string]string{}
			for _, fn := range analysis.Functions {
				for _, call := range fn.Calls {
					got[call.Raw] = call.Callee.Package
				}
			}
			for raw, want := range c.want {
				if pkg, ok := got[raw]; !ok {
					t.Errorf("call %s not found (calls: %v)", raw, got)
				} else if pkg != want {
					t.Errorf("call %s resolves to %q, want %q", raw, pkg, want)
				}
			}
		})
	}
}

// TestGoParser_ConstructedReceiverTyped: a method called on a value the
// expression constructs is typed with that type, as on a typed local.
func TestGoParser_ConstructedReceiverTyped(t *testing.T) {
	dir := t.TempDir()
	const source = "package p\nimport \"example.com/dep\"\ntype T struct{}\nfunc (T) M() {}\n" +
		"func run() {\n\tT{}.M()\n\t(&T{}).M()\n\tnew(T).M()\n\tdep.C{}.N()\n\tf().M()\n}\n"
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := NewGoParser().ParseFile(path, "example.com/p")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	want := map[string]FunctionID{
		"T{}.M":     {Package: "example.com/p", Type: "T", Name: "M"},
		"(&T{}).M":  {Package: "example.com/p", Type: "*T", Name: "M"},
		"new(T).M":  {Package: "example.com/p", Type: "*T", Name: "M"},
		"dep.C{}.N": {Package: "example.com/dep", Type: "C", Name: "N"},
		"f().M":     {Name: "M"},
	}
	got := map[string]FunctionID{}
	for _, fn := range analysis.Functions {
		for _, call := range fn.Calls {
			got[call.Raw] = call.Callee
		}
	}
	for raw, w := range want {
		if g, ok := got[raw]; !ok {
			t.Errorf("call %s not found (calls: %v)", raw, got)
		} else if g != w {
			t.Errorf("call %s callee %+v, want %+v", raw, g, w)
		}
	}
}

// TestGoParser_ArgumentsFromTheSyntaxTree: a shift or a comparison inside an
// argument does not split or merge arguments.
func TestGoParser_ArgumentsFromTheSyntaxTree(t *testing.T) {
	dir := t.TempDir()
	const source = "package p\nimport \"example.com/kdf\"\nfunc run(p, s []byte, n int) {\n\tkdf.Key(p, s, 1<<15, 8, n > 1, 32)\n\tkdf.Key(p, s /* salt */, []int{1, 2}...)\n}\n"
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := NewGoParser().ParseFile(path, "example.com/p")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	var got [][]string
	for _, fn := range analysis.Functions {
		for _, c := range fn.Calls {
			got = append(got, c.Arguments)
		}
	}
	want := [][]string{{"p", "s", "1<<15", "8", "n > 1", "32"}, {"p", "s", "[]int{1, 2}..."}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("arguments %q, want %q", got, want)
	}
}

// TestGoBuilder_PrunesBuiltinsWithoutAnImportPath: a builtin call is pruned
// whether the package has an import path or not, unless the package declares
// a function of that name.
func TestGoBuilder_PrunesBuiltinsWithoutAnImportPath(t *testing.T) {
	for _, importPath := range []string{"example.com/p", ""} {
		dir := t.TempDir()
		const source = "package p\nfunc run(n int) []byte {\n\tb := make([]byte, n)\n\t_ = len(b)\n\treturn append(b, 1)\n}\n"
		if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
		graph, err := NewBuilderForEcosystem("go", NewGoParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: importPath}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		for key, fn := range graph.Functions {
			for _, c := range fn.Calls {
				t.Errorf("import path %q: %s keeps builtin call %s", importPath, key, c.Raw)
			}
		}
	}
}

// TestGoBuilder_KeepsMethodsNamedLikeBuiltins: only a bare call is pruned; a
// method named like a builtin, called through a field, a chain or an index,
// stays a call.
func TestGoBuilder_KeepsMethodsNamedLikeBuiltins(t *testing.T) {
	for _, importPath := range []string{"example.com/p", ""} {
		dir := t.TempDir()
		const source = `package p
type conn struct{}
func (c *conn) close() {}
func (c *conn) len() int { return 0 }
func mk() *conn { return &conn{} }
type S struct{ c *conn; cs []*conn }
func (s *S) Run() {
	s.c.close()
	mk().close()
	_ = s.cs[0].len()
	_ = len(s.cs)
}
`
		if err := os.WriteFile(filepath.Join(dir, "p.go"), []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
		graph, err := NewBuilderForEcosystem("go", NewGoParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: importPath}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		var raws []string
		for key, fn := range graph.Functions {
			if strings.HasSuffix(key, "Run") {
				for _, c := range fn.Calls {
					raws = append(raws, c.Raw)
				}
			}
		}
		if len(raws) != 4 {
			t.Errorf("import path %q: Run keeps %q, want mk and the three method calls, not len", importPath, raws)
		}
	}
}
