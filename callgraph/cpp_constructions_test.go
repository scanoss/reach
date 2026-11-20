// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// spanText is the source text a call's span covers.
func spanText(src string, call *FunctionCall) string {
	lines := strings.Split(src, "\n")
	if call.Line == call.EndLine {
		return lines[call.Line-1][call.StartCol-1 : call.EndCol-1]
	}
	parts := []string{lines[call.Line-1][call.StartCol-1:]}
	parts = append(parts, lines[call.Line:call.EndLine-1]...)
	return strings.Join(append(parts, lines[call.EndLine-1][:call.EndCol-1]), "\n")
}

// Each way C++ constructs an object without a call_expression is a call of
// the type's constructor, keyed (T).T, whose span reads back as the construct
// and whose anchor names the node that writes it.
func TestCPPParser_ConstructionSites(t *testing.T) {
	t.Parallel()

	src := `void f(int ctx, int n) {
    seal::KeyGenerator keygen(ctx);
    QSslKey key(data, QSsl::Rsa, QSsl::Pem);
    Poco::Crypto::CipherKey aes("aes-256-cbc", pwd);
    Botan::AutoSeeded_RNG rng{};
    static Poco::SHA2Engine sha;
    const lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> params;
    std::vector<uint8_t> buf(32), other{1, 2};
    auto p = new Botan::AES_256(n);
    Foo* q = new Foo;
    q = new ns::Bar<int>{n};
    auto alg = jwt::algorithm::hs256{"secret"};
    QSslKey multi(data,
                  QSsl::Rsa);
    Botan::SHA_256 vexing();
}
`
	calls := parseCPPCalls(t, src)["f"]

	type site struct {
		kind, typ, name, raw, text, assigned string
		args                                 []string
	}
	want := []site{
		{"function_declarator", "seal::KeyGenerator", "KeyGenerator", "seal::KeyGenerator", "seal::KeyGenerator keygen(ctx)", "keygen", []string{"ctx"}},
		{"function_declarator", "QSslKey", "QSslKey", "QSslKey", "QSslKey key(data, QSsl::Rsa, QSsl::Pem)", "key", []string{"data", "QSsl::Rsa", "QSsl::Pem"}},
		{"init_declarator", "Poco::Crypto::CipherKey", "CipherKey", "Poco::Crypto::CipherKey", `Poco::Crypto::CipherKey aes("aes-256-cbc", pwd)`, "aes", []string{`"aes-256-cbc"`, "pwd"}},
		{"init_declarator", "Botan::AutoSeeded_RNG", "AutoSeeded_RNG", "Botan::AutoSeeded_RNG", "Botan::AutoSeeded_RNG rng{}", "rng", nil},
		{"identifier", "Poco::SHA2Engine", "SHA2Engine", "Poco::SHA2Engine", "Poco::SHA2Engine sha", "sha", nil},
		{"identifier", "lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS>", "CCParams", "lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS>", "lbcrypto::CCParams<lbcrypto::CryptoContextBFVRNS> params", "params", nil},
		{"init_declarator", "std::vector<uint8_t>", "vector", "std::vector<uint8_t>", "std::vector<uint8_t> buf(32)", "buf", []string{"32"}},
		{"init_declarator", "std::vector<uint8_t>", "vector", "std::vector<uint8_t>", "std::vector<uint8_t> buf(32), other{1, 2}", "other", []string{"1", "2"}},
		{"new_expression", "Botan::AES_256", "AES_256", "Botan::AES_256", "new Botan::AES_256(n)", "p", []string{"n"}},
		{"new_expression", "Foo", "Foo", "Foo", "new Foo", "q", nil},
		{"new_expression", "ns::Bar<int>", "Bar", "ns::Bar<int>", "new ns::Bar<int>{n}", "q", []string{"n"}},
		{"compound_literal_expression", "jwt::algorithm::hs256", "hs256", "jwt::algorithm::hs256", `jwt::algorithm::hs256{"secret"}`, "alg", []string{`"secret"`}},
		{"function_declarator", "QSslKey", "QSslKey", "QSslKey", "QSslKey multi(data,\n                  QSsl::Rsa)", "multi", []string{"data", "QSsl::Rsa"}},
		{"function_declarator", "Botan::SHA_256", "SHA_256", "Botan::SHA_256", "Botan::SHA_256 vexing()", "vexing", nil},
	}
	if len(calls) != len(want) {
		t.Fatalf("calls = %d, want %d: %#v", len(calls), len(want), calls)
	}
	for i, w := range want {
		call := calls[i]
		if call.ASTKind != w.kind || call.Callee != (FunctionID{Package: "app", Type: w.typ, Name: w.name}) || call.Raw != w.raw || call.AssignedVar != w.assigned || !slices.Equal(call.Arguments, w.args) {
			t.Errorf("site %d = kind %q callee %#v raw %q assigned %q args %q, want %+v", i, call.ASTKind, call.Callee, call.Raw, call.AssignedVar, call.Arguments, w)
		}
		if got := spanText(src, &call); got != w.text {
			t.Errorf("site %d span text = %q, want %q", i, got, w.text)
		}
		if last := call.NamedASTPath[strings.LastIndex(call.NamedASTPath, "/")+1:]; !strings.HasPrefix(last, w.kind+"[") {
			t.Errorf("site %d anchor path %q does not end at a %s", i, call.NamedASTPath, w.kind)
		}
	}
}

// What constructs no object of a nameable class, or constructs it by copy, is
// no construction site.
func TestCPPParser_NoConstructionSite(t *testing.T) {
	t.Parallel()

	calls := parseCPPCalls(t, `void f(int n) {
    int x(5);
    unsigned long y{2};
    auto a = n;
    Foo* p;
    Foo& r = other;
    Foo arr[4];
    extern Foo shared;
    Foo copy = other;
    Foo list = {1, 2};
    Foo named(Bar b);
    Foo typed(const Bar&);
    Foo pointer(Bar*);
    Foo vexing(Bar());
    void helper(int);
    Foo* many = new Foo[n];
    int* raw = new int(3);
    struct sockaddr_in addr;
}
`)["f"]
	if len(calls) != 0 {
		t.Fatalf("calls = %#v, want none", calls)
	}
}

// A temporary written T(args) stays the call_expression it parses as.
func TestCPPParser_TemporaryStaysCall(t *testing.T) {
	t.Parallel()

	calls := parseCPPCalls(t, `void f() {
    const QSslKey k = QSslKey(data);
}
`)["f"]
	if len(calls) != 1 || calls[0].ASTKind != cNodeCallExpression || calls[0].Callee != (FunctionID{Package: "app", Name: "QSslKey"}) || calls[0].AssignedVar != "k" {
		t.Fatalf("calls = %#v, want the call_expression QSslKey(data) alone", calls)
	}
}

// A construction of a project type is an edge to the constructor the project
// defines, in the class or out of line.
func TestCPPParser_ConstructionReachesProjectConstructor(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	src := `class Cipher {
public:
    Cipher(int bits) { setup(bits); }
};

class Hasher {
public:
    Hasher();
};

Hasher::Hasher() { init(); }

void use(int n) {
    Cipher c(n);
    Hasher h;
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
	for _, ctor := range []FunctionID{{Package: "app", Type: "Cipher", Name: "Cipher"}, {Package: "app", Type: "Hasher", Name: "Hasher"}} {
		if _, ok := graph.Functions[ctor.String()]; !ok {
			t.Fatalf("no function %s in graph", ctor.String())
		}
		if !slices.Contains(graph.Callers[ctor.String()], use) {
			t.Errorf("callers[%s] = %v, want %s", ctor.String(), graph.Callers[ctor.String()], use)
		}
	}
}
