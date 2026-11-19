// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// parseOneCSharp parses one C# source file and returns its analysis.
func parseOneCSharp(t *testing.T, body string) *FileAnalysis {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.cs"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewCSharpParser().ParseDirectory(dir, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1", len(analyses))
	}
	return analyses[0]
}

// csharpCallsOf returns the calls of the single declared method named name.
func csharpCallsOf(t *testing.T, a *FileAnalysis, name string) []FunctionCall {
	t.Helper()
	for i := range a.Functions {
		if BaseFunctionName(a.Functions[i].ID.Name) == name {
			return a.Functions[i].Calls
		}
	}
	t.Fatalf("no method %q in %+v", name, a.Functions)
	return nil
}

// A file's declared namespace keys its types, not the directory it sits in.
func TestCSharpParserNamespaceKeysTypes(t *testing.T) {
	a := parseOneCSharp(t, `
namespace Acme.Crypto
{
    class Hasher
    {
        public void Run() { }
    }
}`)
	if a.PackagePath != "Acme.Crypto" {
		t.Errorf("package = %q, want Acme.Crypto", a.PackagePath)
	}
	if len(a.Functions) != 1 {
		t.Fatalf("functions = %d, want 1", len(a.Functions))
	}
	if got := a.Functions[0].ID; got.Package != "Acme.Crypto" || got.Type != "Hasher" || got.Name != "Run#0" {
		t.Errorf("id = %+v, want Acme.Crypto.(Hasher).Run#0", got)
	}
}

// A file-scoped namespace keys its types the same way a block-scoped one does.
func TestCSharpParserFileScopedNamespace(t *testing.T) {
	a := parseOneCSharp(t, "namespace Acme.Crypto;\nclass H { void Run() { } }\n")
	if a.PackagePath != "Acme.Crypto" {
		t.Errorf("package = %q, want Acme.Crypto", a.PackagePath)
	}
	if got := a.Functions[0].ID; got.Package != "Acme.Crypto" || got.Type != "H" {
		t.Errorf("id = %+v, want it keyed by the file-scoped namespace", got)
	}
}

// A plain using imports every type of a namespace, the shape C# uses where
// Java writes a type import; an alias stands for a path and a static using
// opens a type's statics.
func TestCSharpParserUsingDirectives(t *testing.T) {
	a := parseOneCSharp(t, `
using System.Security.Cryptography;
using BC = Org.BouncyCastle.Crypto.Engines;
using static System.Math;
class C { }`)
	if len(a.WildcardImports) != 1 || a.WildcardImports[0] != "System.Security.Cryptography" {
		t.Errorf("wildcard imports = %q", a.WildcardImports)
	}
	if a.ImportAliases["BC"] != "Org.BouncyCastle.Crypto.Engines" {
		t.Errorf("aliases = %v", a.ImportAliases)
	}
	if len(a.StaticWildcardImports) != 1 || a.StaticWildcardImports[0] != "System.Math" {
		t.Errorf("static imports = %q", a.StaticWildcardImports)
	}
}

// A static call through a type name is keyed by the type, binds statically and
// carries the arity its site writes.
func TestCSharpParserStaticCall(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
using System.Security.Cryptography;
class H { void Run() { SHA256.Create(); } }`), "Run")
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	if got := calls[0].Callee; got.Type != "SHA256" || got.Name != "Create#0" {
		t.Errorf("callee = %+v, want (SHA256).Create#0", got)
	}
	if !calls[0].StaticReceiver {
		t.Error("a type-name receiver binds statically")
	}
}

// A fully qualified receiver keeps its namespace in the callee's package, so a
// rule anchored on the written path matches it.
func TestCSharpParserQualifiedReceiver(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
class H { void Run() { System.Security.Cryptography.SHA256.Create(); } }`), "Run")
	if got := calls[0].Callee; got.Package != "System.Security.Cryptography" || got.Type != "SHA256" {
		t.Errorf("callee = %+v, want System.Security.Cryptography.(SHA256)", got)
	}
}

// `new T(..)` is a call of the type's constructor, with the arity it writes.
func TestCSharpParserObjectCreation(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
using Org.BouncyCastle.Crypto.Engines;
class H { void Run() { var e = new SM4Engine(); } }`), "Run")
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1: %+v", len(calls), calls)
	}
	if got := calls[0].Callee; got.Type != "SM4Engine" || got.Name != "<init>#0" {
		t.Errorf("callee = %+v, want (SM4Engine).<init>#0", got)
	}
	if calls[0].AssignedVar != "e" {
		t.Errorf("assigned var = %q, want e", calls[0].AssignedVar)
	}
}

// A local typed by its declaration, and one a `var` takes from its
// constructor, both type the calls made on them: the shape every engine rule
// of the ruleset anchors on.
func TestCSharpParserTypedLocalReceiver(t *testing.T) {
	for _, declaration := range []string{"SM4Engine e = new SM4Engine();", "var e = new SM4Engine();"} {
		calls := csharpCallsOf(t, parseOneCSharp(t, `
using Org.BouncyCastle.Crypto.Engines;
class H { void Run(KeyParameter k) { `+declaration+` e.Init(true, k); } }`), "Run")
		var init *FunctionCall
		for i := range calls {
			if BaseFunctionName(calls[i].Callee.Name) == "Init" {
				init = &calls[i]
			}
		}
		if init == nil {
			t.Fatalf("%s: no Init call in %+v", declaration, calls)
		}
		if init.Callee.Type != "SM4Engine" || init.Callee.Name != "Init#2" {
			t.Errorf("%s: callee = %+v, want (SM4Engine).Init#2", declaration, init.Callee)
		}
		if init.ReceiverVar != "e" {
			t.Errorf("%s: receiver var = %q, want e", declaration, init.ReceiverVar)
		}
		if len(init.Arguments) != 2 || init.Arguments[0] != "true" {
			t.Errorf("%s: arguments = %q", declaration, init.Arguments)
		}
	}
}

// An unqualified owner is keyed on the file's own namespace and carries every
// namespace an on-demand using could declare it in, so the graph can settle it.
func TestCSharpParserOwnerAlternatives(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
using System.Security.Cryptography;
namespace Acme.App;
class H { void Run() { SHA256.Create(); } }`), "Run")
	want := []string{"Acme.App.SHA256", "System.Security.Cryptography.SHA256"}
	got := calls[0].OwnerAlternatives
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("alternatives = %q, want %q", got, want)
	}
}

// A type the file declares is certain: it names no alternative.
func TestCSharpParserDeclaredTypeHasNoAlternatives(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
using System.Security.Cryptography;
namespace Acme.App;
class Helper { public static void Go() { } }
class H { void Run() { Helper.Go(); } }`), "Run")
	if len(calls[0].OwnerAlternatives) != 0 {
		t.Errorf("alternatives = %q, want none for a declared type", calls[0].OwnerAlternatives)
	}
}

// A constructor is a declaration under the key a `new` call writes.
func TestCSharpParserConstructorDeclaration(t *testing.T) {
	a := parseOneCSharp(t, "namespace Acme;\nclass H { public H(int n) { } }\n")
	if len(a.Functions) != 1 {
		t.Fatalf("functions = %d, want 1", len(a.Functions))
	}
	if got := a.Functions[0].ID; got.Name != "<init>#1" || got.Type != "H" {
		t.Errorf("id = %+v, want Acme.(H).<init>#1", got)
	}
}

// A nested type keys its methods under the path the source nests them in.
func TestCSharpParserNestedType(t *testing.T) {
	a := parseOneCSharp(t, "namespace Acme;\nclass Outer { class Inner { void Run() { } } }\n")
	if got := a.Functions[0].ID; got.Type != "Outer.Inner" {
		t.Errorf("type = %q, want Outer.Inner", got.Type)
	}
}

// A base list is the type's supertypes, each qualified with the namespace it
// is written in and with every namespace a using brings in.
func TestCSharpParserBaseList(t *testing.T) {
	a := parseOneCSharp(t, "using Org.BouncyCastle.Crypto;\nnamespace Acme;\nclass E : IBlockCipher, Base { }\n")
	want := []string{"Acme.IBlockCipher", "Org.BouncyCastle.Crypto.IBlockCipher", "Acme.Base", "Org.BouncyCastle.Crypto.Base"}
	if got := a.Supertypes["Acme.E"]; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("supertypes = %q, want %q", got, want)
	}
	if got := a.ClassBases["E"]; len(got) != 2 || got[0] != "IBlockCipher" {
		t.Errorf("class bases = %q, want the names as written", got)
	}
}

// A string constant a type declares is recorded under the name a use spells.
func TestCSharpParserNamedValues(t *testing.T) {
	a := parseOneCSharp(t, `
namespace Acme;
class Algorithms { public const string Name = "SHA-256"; }`)
	if got := a.NamedValues["Acme.Algorithms.Name"]; got.Value != "SHA-256" {
		t.Errorf("named values = %+v", a.NamedValues)
	}
}

// Every link of a fluent chain shares the chain's id.
func TestCSharpParserFluentChain(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
class H { void Run() { ECDsa.Create().SignData(d, h); } }`), "Run")
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2: %+v", len(calls), calls)
	}
	if calls[0].ChainID == "" || calls[0].ChainID != calls[1].ChainID {
		t.Errorf("chain ids = %q and %q, want one shared id", calls[0].ChainID, calls[1].ChainID)
	}
}

// An expression-bodied member holds its calls in the arrow clause.
func TestCSharpParserExpressionBodiedMember(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, "class H { byte[] Run(byte[] d) => SHA256.HashData(d); }"), "Run")
	if len(calls) != 1 || BaseFunctionName(calls[0].Callee.Name) != "HashData" {
		t.Fatalf("calls = %+v, want one HashData call", calls)
	}
}

// A test file is skipped unless the parser is asked for tests.
func TestCSharpParserSkipsTestFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.cs", "b.test.cs"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("class C { void R() { } }"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	analyses, err := NewCSharpParser().ParseDirectory(dir, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1 (tests skipped)", len(analyses))
	}
	// A .NET test project names its files without a suffix the scanner can
	// read, so a `FooTests.cs` is ordinary source.
	if err := os.WriteFile(filepath.Join(dir, "CryptoTests.cs"), []byte("class C { void R() { } }"), 0o600); err != nil {
		t.Fatal(err)
	}
	if analyses, err := NewCSharpParser().ParseDirectory(dir, "Acme"); err != nil || len(analyses) != 2 {
		t.Fatalf("analyses = %d, %v; want a FooTests.cs read as source", len(analyses), err)
	}
	withTests, err := NewCSharpParser(WithIncludeTests(true)).ParseDirectory(dir, "Acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(withTests) != 3 {
		t.Fatalf("analyses with tests = %d, want 3", len(withTests))
	}
}

// The registry gives the C# parser and its contract type resolver.
func TestCSharpRegistry(t *testing.T) {
	for _, name := range []string{"csharp", "c#"} {
		if _, ok := NewParserForEcosystem(name).(*CSharpParser); !ok {
			t.Errorf("%s: parser = %T, want *CSharpParser", name, NewParserForEcosystem(name))
		}
	}
}

// A field initializer is a call of the type, made outside any method body.
func TestCSharpParserClassInitializer(t *testing.T) {
	a := parseOneCSharp(t, `
using System.Security.Cryptography;
namespace Acme;
class H { private static readonly SHA256 Hash = SHA256.Create(); }`)
	calls := csharpCallsOf(t, a, "<clinit>")
	if len(calls) != 1 || calls[0].Callee.Type != "SHA256" || calls[0].Callee.Name != "Create#0" {
		t.Fatalf("class initializer calls = %+v, want one (SHA256).Create#0", calls)
	}
}

// A property's accessors and its arrow clause hold calls like a method body.
func TestCSharpParserPropertyCalls(t *testing.T) {
	a := parseOneCSharp(t, `
using System.Security.Cryptography;
namespace Acme;
class H
{
    public byte[] Key { get { return SHA256.HashData(d); } }
    public string Name => MD5.Create().ToString();
}`)
	if got := csharpCallsOf(t, a, "Key"); len(got) != 1 || BaseFunctionName(got[0].Callee.Name) != "HashData" {
		t.Errorf("accessor calls = %+v, want one HashData call", got)
	}
	if got := csharpCallsOf(t, a, "Name"); len(got) != 2 {
		t.Errorf("arrow-bodied property calls = %+v, want the chain's two links", got)
	}
}

// A using alias stands for the namespace it names at every use of it.
func TestCSharpParserUsingAlias(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
using BC = Org.BouncyCastle.Crypto.Engines;
namespace Acme;
class H { void Run() { var e = new BC.SM4Engine(); } }`), "Run")
	if got := calls[0].Callee; got.Package != "Org.BouncyCastle.Crypto.Engines" || got.Type != "SM4Engine" {
		t.Errorf("callee = %+v, want the alias expanded to its namespace", got)
	}
}

// The file's using directives are scope facts of the graph, with the span
// each directive is written at.
func TestCSharpParserUsingsAreScopeFacts(t *testing.T) {
	a := parseOneCSharp(t, `using System.Security.Cryptography;
using BC = Org.BouncyCastle.Crypto.Engines;
using static System.Math;
global using System.Text;
class C { }`)
	if len(a.CSharpUsings) != 4 {
		t.Fatalf("usings = %+v, want 4", a.CSharpUsings)
	}
	want := []CSharpUsing{
		{Namespace: "System.Security.Cryptography", Kind: "using", Line: 1},
		{Namespace: "Org.BouncyCastle.Crypto.Engines", Alias: "BC", Kind: "alias", Line: 2},
		{Namespace: "System.Math", Kind: "static", Line: 3},
		{Namespace: "System.Text", Kind: "using", Global: true, Line: 4},
	}
	for i, w := range want {
		got := a.CSharpUsings[i]
		if got.Namespace != w.Namespace || got.Alias != w.Alias || got.Kind != w.Kind || got.Global != w.Global || got.Line != w.Line {
			t.Errorf("using %d = %+v, want %+v", i, got, w)
		}
		if got.StartCol != 1 || got.EndCol <= got.StartCol || got.Text == "" {
			t.Errorf("using %d span = %d..%d %q", i, got.StartCol, got.EndCol, got.Text)
		}
	}
}

// A graph of C# sources carries each file's usings.
func TestCSharpGraphCarriesUsings(t *testing.T) {
	graph := buildCSharpGraph(t, map[string]string{
		"app.cs": "using System.Security.Cryptography;\nnamespace Acme;\nclass A { void R() { SHA256.Create(); } }\n",
	})
	if len(graph.CSharpUsings) != 1 {
		t.Fatalf("graph usings = %+v, want one file", graph.CSharpUsings)
	}
	for _, usings := range graph.CSharpUsings {
		if len(usings) != 1 || usings[0].Namespace != "System.Security.Cryptography" {
			t.Errorf("usings = %+v", usings)
		}
	}
}

// A constant the caller passes by name is traced to its value: a local
// assigned a literal once, and a field of the enclosing type.
func TestCSharpParserArgumentValueSources(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
namespace Acme;
class H
{
    const string Mode = "SM4/CTR/NoPadding";
    void Run()
    {
        string local = "SEED/GCM/NoPadding";
        Cipher.Get(Mode);
        Cipher.Get(local);
    }
}`), "Run")
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	for i, want := range []struct{ kind, name, value string }{
		{sourceNodeField, "Mode", `"SM4/CTR/NoPadding"`},
		{sourceNodeVariable, "local", `"SEED/GCM/NoPadding"`},
	} {
		sources := calls[i].ArgumentSources
		if len(sources) != 1 || len(sources[0]) != 1 {
			t.Fatalf("call %d sources = %+v", i, sources)
		}
		got := sources[0][0]
		if got.Type != want.kind || got.Name != want.name {
			t.Errorf("call %d source = %+v, want a %s named %s", i, got, want.kind, want.name)
		}
		if len(got.SourceNodes) != 1 || got.SourceNodes[0].Value != want.value {
			t.Errorf("call %d value = %+v, want %s", i, got.SourceNodes, want.value)
		}
	}
}

// A local written twice holds no single constant: its type is still known,
// its value is not.
func TestCSharpParserReboundLocalHasNoValue(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
namespace Acme;
class H { void Run() { string a = "x"; a = "y"; Cipher.Get(a); } }`), "Run")
	for _, call := range calls {
		for _, sources := range call.ArgumentSources {
			for _, source := range sources {
				if len(source.SourceNodes) != 0 {
					t.Errorf("rebound local traced to %+v", source.SourceNodes)
				}
				if source.DeclaredType != "string" {
					t.Errorf("declared type = %q, want string", source.DeclaredType)
				}
			}
		}
	}
}

// A parameter and a field carry the type they are declared with, the
// evidence a rule that selects an overload by argument type reads.
func TestCSharpParserArgumentDeclaredTypes(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
namespace Acme;
class H
{
    private int _size = 2048;
    void Run(int bits) { RSA.Create(bits); RSA.Create(_size); }
}`), "Run")
	if len(calls) != 2 {
		t.Fatalf("calls = %d, want 2", len(calls))
	}
	for i, want := range []struct{ kind, name string }{{sourceNodeVariable, "bits"}, {sourceNodeField, "_size"}} {
		sources := calls[i].ArgumentSources
		if len(sources) != 1 || len(sources[0]) != 1 {
			t.Fatalf("call %d sources = %+v", i, sources)
		}
		if got := sources[0][0]; got.Type != want.kind || got.Name != want.name || got.DeclaredType != "int" {
			t.Errorf("call %d source = %+v, want a %s named %s declared int", i, got, want.kind, want.name)
		}
	}
}

// A property write is an attribute store: the shape a rule reads when the
// caller configures an object before the call that uses it.
func TestCSharpParserAttributeStores(t *testing.T) {
	a := parseOneCSharp(t, `
namespace Acme;
class H { void Run() { var aes = Aes.Create(); aes.KeySize = 256; aes.GenerateKey(); } }`)
	var stores []AttributeStore
	for i := range a.Functions {
		if BaseFunctionName(a.Functions[i].ID.Name) == "Run" {
			stores = a.Functions[i].AttributeStores
		}
	}
	if len(stores) != 1 {
		t.Fatalf("stores = %+v, want 1", stores)
	}
	got := stores[0]
	if got.Receiver != "aes" || got.Attribute != "KeySize" || got.Operator != "=" || got.Value.Text != "256" {
		t.Errorf("store = %+v, want aes.KeySize = 256", got)
	}
	if got.Line != 3 || got.StartCol <= 0 || got.EndCol <= got.StartCol {
		t.Errorf("store span = line %d, %d..%d", got.Line, got.StartCol, got.EndCol)
	}
}

// A property declared with an initializer holds its calls in the value, not
// in an accessor.
func TestCSharpParserPropertyInitializer(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
using System.Security.Cryptography;
namespace Acme;
class H { public byte[] Key { get; } = RandomNumberGenerator.GetBytes(16); }`), "Key")
	if len(calls) != 1 || BaseFunctionName(calls[0].Callee.Name) != "GetBytes" {
		t.Fatalf("calls = %+v, want the initializer's one call", calls)
	}
}

// The resource of a `using (T v = f())` statement types v, as a declaration
// does, so a call on it is keyed by the type.
func TestCSharpParserUsingStatementResource(t *testing.T) {
	calls := csharpCallsOf(t, parseOneCSharp(t, `
using System.Security.Cryptography;
namespace Acme;
class H { void Run(byte[] d) { using (HashAlgorithm h = SHA256.Create()) { h.ComputeHash(d); } } }`), "Run")
	var compute *FunctionCall
	for i := range calls {
		if BaseFunctionName(calls[i].Callee.Name) == "ComputeHash" {
			compute = &calls[i]
		}
	}
	if compute == nil || compute.Callee.Type != "HashAlgorithm" {
		t.Fatalf("ComputeHash call = %+v, want it typed by the using resource", compute)
	}
}

// Two overloads share one key, which is keyed by name and arity: their calls
// are unioned rather than one body replacing the other.
func TestCSharpOverloadsKeepBothBodies(t *testing.T) {
	graph := buildCSharpGraph(t, map[string]string{
		"h.cs": `using System.Security.Cryptography;
namespace Acme;
class Helpers
{
    public static byte[] Hash(byte[] data) { return SHA256.Create().ComputeHash(data); }
    public static byte[] Hash(string data) { return MD5.Create().ComputeHash(null); }
}`,
	})
	calls := callsOf(t, graph, "Acme.(Helpers).Hash#1")
	var sha, md5 bool
	for _, c := range calls {
		sha = sha || strings.Contains(c, "(SHA256).Create")
		md5 = md5 || strings.Contains(c, "(MD5).Create")
	}
	if !sha || !md5 {
		t.Errorf("calls = %q, want both overloads' bodies", calls)
	}
}

// A call on an interface reaches the types that implement it, and a call on
// an abstract member the types that override it: C# writes an abstract class
// where Java reaches the same overrides through an interface.
func TestCSharpDispatchesToImplementations(t *testing.T) {
	graph := buildCSharpGraph(t, map[string]string{
		"app.cs": `namespace Acme;
interface IDigest { byte[] Compute(byte[] d); }
class Sha : IDigest { public byte[] Compute(byte[] d) { return Hashes.Sha256(d); } }
abstract class Hasher { public abstract byte[] Hash(byte[] d); }
class Sm3 : Hasher { public override byte[] Hash(byte[] d) { return Hashes.Sm3(d); } }
static class Hashes { public static byte[] Sha256(byte[] d) { return null; } public static byte[] Sm3(byte[] d) { return null; } }
class App
{
    void Run(byte[] d) { IDigest i = new Sha(); i.Compute(d); Hasher h = new Sm3(); h.Hash(d); }
}`,
	})
	for _, want := range []string{"Acme.(Sha).Compute#1", "Acme.(Sm3).Hash#1"} {
		if len(graph.Callers[want]) == 0 {
			t.Errorf("%s has no caller: the call on its interface or abstract member did not dispatch", want)
		}
	}
}

// An instance field's initializer runs in the constructor, so a type that
// declares none gets the one C# generates; a static field's runs at class
// load.
func TestCSharpFieldInitializersRunWhereTheyDo(t *testing.T) {
	a := parseOneCSharp(t, `
using System.Security.Cryptography;
namespace Acme;
class Vault
{
    private static readonly SHA256 Shared = SHA256.Create();
    private readonly Aes _cipher = Aes.Create();
}`)
	calls := func(name string) []FunctionCall {
		for i := range a.Functions {
			if a.Functions[i].ID.Name == name {
				return a.Functions[i].Calls
			}
		}
		return nil
	}
	if got := calls("<clinit>#0"); len(got) != 1 || got[0].Callee.Type != "SHA256" {
		t.Errorf("class initializer calls = %+v, want the static field's", got)
	}
	if got := calls("<init>#0"); len(got) != 1 || got[0].Callee.Type != "Aes" {
		t.Errorf("generated constructor calls = %+v, want the instance field's", got)
	}
}

// A type that declares a constructor runs its instance field initializers in
// it, rather than in one C# would have generated.
func TestCSharpDeclaredConstructorRunsTheFieldInitializers(t *testing.T) {
	a := parseOneCSharp(t, `
using System.Security.Cryptography;
namespace Acme;
class Vault
{
    private readonly Aes _cipher = Aes.Create();
    public Vault(int n) { _cipher.GenerateIV(); }
}`)
	var ctor *FunctionDecl
	for i := range a.Functions {
		if a.Functions[i].ID.Name == "<init>#1" {
			ctor = &a.Functions[i]
		}
		if a.Functions[i].ID.Name == "<init>#0" {
			t.Error("a type that declares a constructor needs no generated one")
		}
	}
	if ctor == nil {
		t.Fatal("no declared constructor")
	}
	var created bool
	for _, c := range ctor.Calls {
		created = created || c.Callee.Type == "Aes" && BaseFunctionName(c.Callee.Name) == "Create"
	}
	if !created {
		t.Errorf("declared constructor calls = %+v, want the field initializer's call", ctor.Calls)
	}
}

// A file written as top-level statements is the program's entry point: C#
// compiles the statements into a `Main` it generates, and without it every
// call of such a file is invisible.
func TestCSharpTopLevelProgram(t *testing.T) {
	a := parseOneCSharp(t, `using System.Security.Cryptography;

if (args.Length > 0)
{
    var h = SHA256.HashData(File.ReadAllBytes(args[0]));
}

static string Hash(string v) => Convert.ToHexString(MD5.HashData(null));
`)
	var main, local *FunctionDecl
	for i := range a.Functions {
		switch a.Functions[i].ID.Name {
		case "Main#1":
			main = &a.Functions[i]
		case "Hash#1":
			local = &a.Functions[i]
		}
	}
	if main == nil {
		t.Fatalf("no generated Main: %+v", a.Functions)
	}
	if main.EntryKind != RootKindMain || !main.Static {
		t.Errorf("generated Main = %+v, want a static entry point", main.ID)
	}
	var sha bool
	for _, c := range main.Calls {
		sha = sha || c.Callee.Type == "SHA256"
	}
	if !sha {
		t.Errorf("Main calls = %+v, want the statements' call", main.Calls)
	}
	if local == nil {
		t.Fatal("a local function among the statements owns its own body")
	}
	for _, c := range main.Calls {
		if c.Callee.Type == "MD5" {
			t.Error("the local function's call belongs to it, not to Main")
		}
	}
}

// An explicit `static Main` is the entry point under its own name: C# spells
// it with a capital, which the shared main detection does not read.
func TestCSharpExplicitMainIsAnEntryPoint(t *testing.T) {
	a := parseOneCSharp(t, "namespace Acme;\nclass Program { static void Main(string[] args) { } void Run() { } }\n")
	for i := range a.Functions {
		switch BaseFunctionName(a.Functions[i].ID.Name) {
		case "Main":
			if a.Functions[i].EntryKind != RootKindMain {
				t.Errorf("Main entry kind = %q, want main", a.Functions[i].EntryKind)
			}
		case "Run":
			if a.Functions[i].EntryKind != "" {
				t.Errorf("Run entry kind = %q, want none", a.Functions[i].EntryKind)
			}
		}
	}
}
