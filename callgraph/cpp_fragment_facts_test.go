// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// parseCPPFile parses one C++ source file and returns its analysis.
func parseCPPFile(t *testing.T, src string) *FileAnalysis {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCPPParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1", len(analyses))
	}
	return analyses[0]
}

func cppFunction(t *testing.T, analysis *FileAnalysis, id FunctionID) *FunctionDecl {
	t.Helper()
	for i := range analysis.Functions {
		if analysis.Functions[i].ID.Type == id.Type && analysis.Functions[i].ID.Name == id.Name {
			return &analysis.Functions[i]
		}
	}
	var got []string
	for i := range analysis.Functions {
		got = append(got, analysis.Functions[i].ID.String())
	}
	t.Fatalf("no function %s.%s among %v", id.Type, id.Name, got)
	return nil
}

// Using directives and declarations are listed with the includes, as
// written, with their span and whether a function body holds them; one in a
// class body is not.
func TestCPPParser_UsingsListedAsIncludes(t *testing.T) {
	t.Parallel()

	analysis := parseCPPFile(t, `#include <memory>
using namespace Acme::Crypto;
using  Acme::Hash::Digest;
namespace app { using namespace std; }
class Derived : public Base {
    using Base::Base;
    void m() { using namespace Inner; }
};
void f() {
    using namespace Acme::Local;
    run();
}
`)
	type entry struct {
		text            string
		line, col, end  int
		using, function bool
	}
	want := []entry{
		{"#include <memory>", 1, 1, 18, false, false},
		{"using namespace Acme::Crypto;", 2, 1, 30, true, false},
		{"using Acme::Hash::Digest;", 3, 1, 27, true, false},
		{"using namespace std;", 4, 17, 37, true, false},
		{"using namespace Inner;", 7, 16, 38, true, true},
		{"using namespace Acme::Local;", 10, 5, 33, true, true},
	}
	var got []entry
	for _, inc := range analysis.CIncludes {
		got = append(got, entry{inc.Text, inc.Line, inc.StartCol, inc.EndCol, inc.Using, inc.InFunction})
		if inc.Using && (inc.Header != "" || inc.System) {
			t.Errorf("using %q has header %q system %v, want none", inc.Text, inc.Header, inc.System)
		}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("includes = %+v\nwant %+v", got, want)
	}
}

// A function returning a reference or a pointer, in a class body or out of
// line, and an operator function are recorded with their own name and type.
func TestCPPParser_ReferenceAndOperatorFunctions(t *testing.T) {
	t.Parallel()

	src := `namespace acme {
class Keyset {
public:
    const Key& primary() const { return keys_[0]; }
    Key&& take() { return std::move(k_); }
    Key* raw() { return &k_; }
    std::string operator()(const std::string& in) { return hash(in); }
    bool operator ==(const Keyset& o) const { return same(o); }
    const Info& info() const;
};
const Info& Keyset::info() const { return load(); }
}
template <typename T> T& Box<T>::get() { return fetch(); }
auto last() -> Key& { return pick(); }
std::string Digest::operator()(const void* data, size_t n) { return run(data, n); }
`
	analysis := parseCPPFile(t, src)
	for _, w := range []struct {
		typ, name string
		line      int
		call      string
	}{
		{"acme::Keyset", "primary", 4, ""},
		{"acme::Keyset", "take", 5, "std::move"},
		{"acme::Keyset", "raw", 6, ""},
		{"acme::Keyset", "operator()", 7, "hash"},
		{"acme::Keyset", "operator==", 8, "same"},
		{"acme::Keyset", "info", 11, "load"},
		{"Box<T>", "get", 13, "fetch"},
		{"", "last", 14, "pick"},
		{"Digest", "operator()", 15, "run"},
	} {
		fn := cppFunction(t, analysis, FunctionID{Type: w.typ, Name: w.name})
		if fn.StartLine != w.line || fn.EndLine != w.line {
			t.Errorf("%s.%s span lines %d-%d, want %d", w.typ, w.name, fn.StartLine, fn.EndLine, w.line)
		}
		if w.call != "" && (len(fn.Calls) != 1 || fn.Calls[0].Raw != w.call) {
			t.Errorf("%s.%s calls = %#v, want one call of %s", w.typ, w.name, fn.Calls, w.call)
		}
	}
}

// A call of a call's result is a site of its own: the call operator of the
// type the inner callee names, spanning the whole expression.
func TestCPPParser_CallOfCall(t *testing.T) {
	t.Parallel()

	src := `class Local { public: int operator()(int v) { return v; } };
void f(const std::string& x) {
    std::string h = SHA256()(x);
    auto k = crypto::Keccak<256>()(x, 3);
    Local()(1);
    obj.get()(x);
}
`
	calls := parseCPPCalls(t, src)["f"]
	type site struct {
		raw, typ, name, text string
		args                 []string
		internal             bool
	}
	var got []site
	for i := range calls {
		c := &calls[i]
		if c.Callee.Name != cppCallOperator {
			continue
		}
		if c.ASTKind != cNodeCallExpression {
			t.Errorf("site %q anchor kind %q, want call_expression", c.Raw, c.ASTKind)
		}
		got = append(got, site{c.Raw, c.Callee.Type, c.Callee.Name, spanText(src, c), c.Arguments, c.Callee.Linkage == LinkageInternal})
	}
	want := []site{
		{"SHA256()", "SHA256", "operator()", "SHA256()(x)", []string{"x"}, false},
		{"crypto::Keccak<256>()", "crypto::Keccak<256>", "operator()", "crypto::Keccak<256>()(x, 3)", []string{"x", "3"}, false},
		{"Local()", "Local", "operator()", "Local()(1)", []string{"1"}, true},
	}
	if len(got) != len(want) {
		t.Fatalf("call operator sites = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i].raw != want[i].raw || got[i].typ != want[i].typ || got[i].text != want[i].text || !slices.Equal(got[i].args, want[i].args) || got[i].internal != want[i].internal {
			t.Errorf("site %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	if _, ok := findCPPCall(calls, "SHA256"); !ok {
		t.Errorf("the inner call SHA256() is no longer a site: %#v", calls)
	}
}

// Each parameter is listed as written: its type text without the name and
// default value, its name and the span of its declaration.
func TestCPPParser_WrittenParameters(t *testing.T) {
	t.Parallel()

	src := `void f(const seal::KeyGenerator &keygen, int n, std::vector<int> *v, Foo, int (*cb)(int), unsigned char buf[], const std::string& label = "x", Args&&... rest) { use(n); }
void g(void) { }
void h(
    helib::PtxtArray
        &p) { }
`
	analysis := parseCPPFile(t, src)
	got := cppFunction(t, analysis, FunctionID{Name: "f"}).WrittenParameters
	want := []WrittenParameter{
		{Type: "const seal::KeyGenerator &", Name: "keygen", Line: 1, StartCol: 8, EndCol: 40},
		{Type: "int", Name: "n", Line: 1, StartCol: 42, EndCol: 47},
		{Type: "std::vector<int> *", Name: "v", Line: 1, StartCol: 49, EndCol: 68},
		{Type: "Foo", Line: 1, StartCol: 70, EndCol: 73},
		{Type: "int (*)(int)", Name: "cb", Line: 1, StartCol: 75, EndCol: 89},
		{Type: "unsigned char []", Name: "buf", Line: 1, StartCol: 91, EndCol: 110},
		{Type: "const std::string&", Name: "label", Line: 1, StartCol: 112, EndCol: 142},
		{Type: "Args&&...", Name: "rest", Line: 1, StartCol: 144, EndCol: 158},
	}
	if !slices.Equal(got, want) {
		t.Errorf("written parameters =\n%+v\nwant\n%+v", got, want)
	}
	if got := cppFunction(t, analysis, FunctionID{Name: "g"}).WrittenParameters; got != nil {
		t.Errorf("g(void) written parameters = %+v, want none", got)
	}
	wantH := []WrittenParameter{{Type: "helib::PtxtArray &", Name: "p", Line: 4, StartCol: 5, EndCol: 11, EndLine: 5}}
	if got := cppFunction(t, analysis, FunctionID{Name: "h"}).WrittenParameters; !slices.Equal(got, wantH) {
		t.Errorf("h written parameters = %+v, want %+v", got, wantH)
	}
}

// The local declarations of a function body are listed as C's are, with the
// pointer and reference declarators and C++'s initializers.
func TestCPPParser_Declarations(t *testing.T) {
	t.Parallel()

	src := `void f(Source e) {
    CryptoPP::SHA256 copy = e;
    CryptoPP::SHA256 *p = &copy, &r = copy;
    const auto& ref = make();
    auto v = e;
    Foo&& moved = take();
    static const Foo* const q = nullptr;
    QSslKey key(data, QSsl::Rsa);
    Botan::AutoSeeded_RNG rng;
    Botan::Hash h{"SHA-256"};
    int n{3};
    auto* heap = new Foo(1);
    Foo vexing();
    for (int i = 0; i < n; i++) { std::string s = "x"; }
}
`
	analysis := parseCPPFile(t, src)
	got := cppFunction(t, analysis, FunctionID{Name: "f"}).Declarations
	decl := func(typ, name, init string, line, start, end int) VarDecl {
		return VarDecl{Type: typ, Name: name, Init: init, Line: line, StartCol: start, EndCol: end}
	}
	want := []VarDecl{
		decl("CryptoPP::SHA256", "copy", VarInitOther, 2, 5, 31),
		decl("CryptoPP::SHA256*", "p", VarInitOther, 3, 5, 44),
		decl("CryptoPP::SHA256&", "r", VarInitOther, 3, 5, 44),
		decl("const auto&", "ref", VarInitCall, 4, 5, 30),
		decl("auto", "v", VarInitOther, 5, 5, 16),
		decl("Foo&&", "moved", VarInitCall, 6, 5, 26),
		decl("const Foo*", "q", VarInitNull, 7, 5, 41),
		decl("QSslKey", "key", VarInitCall, 8, 5, 34),
		decl("Botan::AutoSeeded_RNG", "rng", "", 9, 5, 31),
		decl("Botan::Hash", "h", VarInitCall, 10, 5, 30),
		decl("int", "n", VarInitOther, 11, 5, 14),
		decl("auto*", "heap", VarInitCall, 12, 5, 29),
		decl("int", "i", VarInitLiteral, 14, 10, 20),
		decl("std::string", "s", VarInitLiteral, 14, 35, 55),
	}
	if !slices.Equal(got, want) {
		t.Errorf("declarations =\n%+v\nwant\n%+v", got, want)
	}
}

func TestCPPOperatorName(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{
		"operator()":     "operator()",
		"operator ()":    "operator()",
		"operator ==":    "operator==",
		"operator new":   "operator new",
		"operator new[]": "operator new[]",
		"operatorFoo":    "operatorFoo",
		"process":        "process",
	} {
		if got := cppOperatorName(in); got != want {
			t.Errorf("cppOperatorName(%q) = %q, want %q", in, got, want)
		}
	}
}

// A call of a project type's call operator through a temporary is an edge to
// the operator the type defines, and a function returning a reference is a
// node its callers reach.
func TestCPPParser_CallOperatorAndReferenceFunctionEdges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `class Digest {
public:
    std::string operator()(const std::string& in) { return run(in); }
};

const Config& settings() { return load(); }

void use(const std::string& x) {
    std::string h = Digest()(x);
    settings();
}
`
	if err := os.WriteFile(filepath.Join(dir, "app.cpp"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem(ecosystemCPP, NewCPPParser()).BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	use := FunctionID{Package: "app", Name: "use"}.String()
	for _, callee := range []FunctionID{{Package: "app", Type: "Digest", Name: "operator()"}, {Package: "app", Name: "settings"}} {
		if _, ok := graph.Functions[callee.String()]; !ok {
			t.Fatalf("no function %s in graph", callee.String())
		}
		if !slices.Contains(graph.Callers[callee.String()], use) {
			t.Errorf("callers[%s] = %v, want %s", callee.String(), graph.Callers[callee.String()], use)
		}
	}
}
