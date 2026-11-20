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

// buildCPPProject writes files (path relative to the project root -> source)
// and builds the C++ graph of the project, rooted at import path "proj".
func buildCPPProject(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	return buildCPPProjectWith(t, NewBuilderForEcosystem(ecosystemCPP, NewCPPParser()), files)
}

func buildCPPProjectWith(t *testing.T, b *Builder, files map[string]string) *CallGraph {
	t.Helper()
	root := t.TempDir()
	for name, src := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := b.BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: "proj"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

// wantCPPEdges checks that each callee has the caller, with the edge kind.
func wantCPPEdges(t *testing.T, graph *CallGraph, edges [][3]string) {
	t.Helper()
	for _, e := range edges {
		callee, caller, kind := e[0], e[1], EdgeKind(e[2])
		if graph.Functions[callee] == nil {
			t.Errorf("no function %s", callee)
		}
		if !slices.Contains(graph.Callers[callee], caller) {
			t.Errorf("callers[%s] = %v, want %s", callee, graph.Callers[callee], caller)
			continue
		}
		if got := cppEdgeKind(graph, caller, callee); got != kind {
			t.Errorf("%s -> %s: kind %q, want %q", caller, callee, got, kind)
		}
	}
}

func wantNoCPPEdges(t *testing.T, graph *CallGraph, edges [][2]string) {
	t.Helper()
	for _, e := range edges {
		if slices.Contains(graph.Callers[e[0]], e[1]) {
			t.Errorf("callers[%s] = %v, want no %s", e[0], graph.Callers[e[0]], e[1])
		}
	}
}

// cppEdgeKind is the most certain kind recorded for a caller->callee edge.
func cppEdgeKind(graph *CallGraph, caller, callee string) EdgeKind {
	best := EdgeKind("")
	for key, res := range graph.EdgeResolutions {
		from, to, ok := EdgeResolutionEndpoints(key, res)
		if !ok || from != caller || to != callee {
			continue
		}
		if best == "" || edgeKindRank(res.Kind) > edgeKindRank(best) {
			best = res.Kind
		}
	}
	return best
}

func cppCallOf(t *testing.T, graph *CallGraph, caller, raw string) FunctionCall {
	t.Helper()
	fn := graph.Functions[caller]
	if fn == nil {
		t.Fatalf("no function %s", caller)
	}
	for _, call := range fn.Calls {
		if call.Raw == raw {
			return call
		}
	}
	t.Fatalf("%s has no call %q: %#v", caller, raw, fn.Calls)
	return FunctionCall{}
}

const cppExact = string(EdgeKindExact)

// A: the receiver of a member call is typed from a data member's declared
// type, declared in a header of another directory: a raw pointer, a
// std::unique_ptr / std::shared_ptr through `->`, a member held by value,
// and `this->member`.
func TestResolveCPPCalls_MemberReceivers(t *testing.T) {
	t.Parallel()

	graph := buildCPPProject(t, map[string]string{
		"include/handshake.h": `#include <memory>
class Exchange { public: void nonce(int n); void reset(); };
class Session {
 public:
  void open();
 private:
  std::unique_ptr<Exchange> owned_;
  std::shared_ptr<Exchange> shared_;
  Exchange* raw_;
  Exchange held_;
};
`,
		"src/exchange.cc": `#include "handshake.h"
void Exchange::nonce(int n) { fill(n); }
void Exchange::reset() { clear(); }
`,
		"src/session.cc": `#include "handshake.h"
void Session::open() {
  owned_->nonce(1);
  shared_->nonce(2);
  raw_->reset();
  held_.reset();
  this->held_.nonce(3);
  owned_.reset();
}
`,
	})
	open := "proj/src.(Session).open"
	wantCPPEdges(t, graph, [][3]string{
		{"proj/src.(Exchange).nonce", open, cppExact},
		{"proj/src.(Exchange).reset", open, cppExact},
	})
	// `owned_.reset()` is std::unique_ptr's own reset, not Exchange's.
	if call := cppCallOf(t, graph, open, "owned_.reset"); call.Callee.Type != "" {
		t.Errorf("owned_.reset callee = %#v, want it left untyped", call.Callee)
	}
	for _, raw := range []string{"owned_->nonce", "shared_->nonce", "raw_->reset", "held_.reset", "this->held_.nonce"} {
		if call := cppCallOf(t, graph, open, raw); call.Callee.String() != "proj/src.(Exchange)."+call.Callee.Name {
			t.Errorf("%s callee = %s", raw, call.Callee.String())
		}
	}
}

// A: the receiver is the result of a call: a static factory returning a
// smart pointer by reference, an `auto` local bound to it, and a member
// function whose return type is deduced from the member it returns.
func TestResolveCPPCalls_CallResultReceivers(t *testing.T) {
	t.Parallel()

	graph := buildCPPProject(t, map[string]string{
		"rng.h": `#include <memory>
namespace app {
class Rng {
 public:
  static const std::unique_ptr<Rng>& instance();
  void bytes(unsigned char* p, int n);
};
class Pair { public: bool derive(int n); };
class Box {
 public:
  const auto& pair() { return pair_; }
  Rng* rng() const;
 private:
  std::unique_ptr<Pair> pair_;
};
}
`,
		"rng.cc": `#include "rng.h"
namespace app {
const std::unique_ptr<Rng>& Rng::instance() { static std::unique_ptr<Rng> r; return r; }
void Rng::bytes(unsigned char* p, int n) { RAND_bytes(p, n); }
bool Pair::derive(int n) { return DH_compute_key(n); }
Rng* Box::rng() const { return nullptr; }

void direct(unsigned char* p) { Rng::instance()->bytes(p, 4); }
void bound(unsigned char* p) {
  const auto& r = Rng::instance();
  r->bytes(p, 8);
}
void chained(Box& box, unsigned char* p) {
  box.pair()->derive(2);
  box.rng()->bytes(p, 1);
}
}
`,
	})
	bytes, derive := "proj.(app::Rng).bytes", "proj.(app::Pair).derive"
	wantCPPEdges(t, graph, [][3]string{
		{bytes, "proj.(app).direct", cppExact},
		{bytes, "proj.(app).bound", cppExact},
		{bytes, "proj.(app).chained", cppExact},
		{derive, "proj.(app).chained", cppExact},
		{"proj.(app::Box).pair", "proj.(app).chained", cppExact},
	})
}

// B: a type, a scope and a function written unqualified inside a namespace
// name what that namespace (or an enclosing one, or one a using-directive
// names) declares.
func TestResolveCPPCalls_NamespaceRelativeNames(t *testing.T) {
	t.Parallel()

	graph := buildCPPProject(t, map[string]string{
		"lib/digest.h": `namespace outer { namespace inner {
class Digest { public: void init(); static Digest make(); };
void salt(int n);
} }
namespace util { class Clock { public: long now(); }; }
`,
		"lib/digest.cc": `#include "digest.h"
namespace outer { namespace inner {
void Digest::init() { EVP_DigestInit(0, 0); }
Digest Digest::make() { return Digest(); }
void salt(int n) { Digest d; d.init(); }
} }
long util::Clock::now() { return 0; }
`,
		"app/use.cc": `#include "../lib/digest.h"
using namespace util;
namespace outer {
namespace inner {
void local() { Digest d; d.init(); salt(1); }
}
void nested() { inner::Digest::make(); inner::salt(2); }
}
void viaUsing() { Clock c; c.now(); }
`,
	})
	init := "proj/lib.(outer::inner::Digest).init"
	wantCPPEdges(t, graph, [][3]string{
		{init, "proj/lib.(outer::inner).salt", cppExact},
		{init, "proj/app.(outer::inner).local", cppExact},
		{"proj/lib.(outer::inner).salt", "proj/app.(outer::inner).local", cppExact},
		{"proj/lib.(outer::inner::Digest).make", "proj/app.(outer).nested", cppExact},
		{"proj/lib.(outer::inner).salt", "proj/app.(outer).nested", cppExact},
		{"proj/lib.(util::Clock).now", "proj/app.viaUsing", cppExact},
	})
}

// C: a call on a base class's pointer, reference or smart pointer reaches
// every override in a class derived from it, transitively; a call on an
// object held by value binds statically.
func TestResolveCPPCalls_ClassHierarchyDispatch(t *testing.T) {
	t.Parallel()

	graph := buildCPPProject(t, map[string]string{
		"crypto.h": `#include <memory>
class Impl {
 public:
  virtual ~Impl() = default;
  virtual void hash_init() = 0;
  virtual void seed(int n);
};
class Native : public Impl { public: void hash_init() override; };
class Ossl : public Native { public: void hash_init() override; void seed(int n) override; };
class Unrelated { public: void hash_init(); };
class Hasher {
 public:
  void start();
 private:
  std::shared_ptr<Impl> crypto;
};
`,
		"crypto.cc": `#include "crypto.h"
void Impl::seed(int n) { mix(n); }
void Native::hash_init() { native_md5(); }
void Ossl::hash_init() { EVP_md5(); }
void Ossl::seed(int n) { RAND_seed(n); }
void Unrelated::hash_init() { other(); }
void Hasher::start() { crypto->hash_init(); }
void local() {
  Impl* c = new Ossl;
  c->hash_init();
  c->seed(1);
}
void param(Impl& impl) { impl.seed(2); }
void byValue() { Native n; n.hash_init(); }
`,
	})
	dispatch := string(EdgeKindInterfaceDispatch)
	wantCPPEdges(t, graph, [][3]string{
		{"proj.(Native).hash_init", "proj.(Hasher).start", dispatch},
		{"proj.(Ossl).hash_init", "proj.(Hasher).start", dispatch},
		{"proj.(Native).hash_init", "proj.local", dispatch},
		{"proj.(Ossl).hash_init", "proj.local", dispatch},
		{"proj.(Impl).seed", "proj.local", cppExact},
		{"proj.(Ossl).seed", "proj.local", dispatch},
		{"proj.(Ossl).seed", "proj.param", dispatch},
		{"proj.(Native).hash_init", "proj.byValue", cppExact},
	})
	wantNoCPPEdges(t, graph, [][2]string{
		{"proj.(Unrelated).hash_init", "proj.(Hasher).start"},
		{"proj.(Unrelated).hash_init", "proj.local"},
		{"proj.(Ossl).hash_init", "proj.byValue"},
	})
	// The abstract method is the call's own callee.
	if call := cppCallOf(t, graph, "proj.(Hasher).start", "crypto->hash_init"); call.Callee.Type != "Impl" {
		t.Errorf("crypto->hash_init callee = %#v, want type Impl", call.Callee)
	}
}

// D: std::make_unique<T> and std::make_shared<T>, qualified or not, are
// constructions of T beside the call of the factory.
func TestResolveCPPCalls_MakeUniqueConstructs(t *testing.T) {
	t.Parallel()

	graph := buildCPPProject(t, map[string]string{
		"src/dh.h": `namespace net { class Dh { public: Dh(const unsigned char* p, int n); bool secret(int n); }; }
`,
		"src/dh.cc": `#include "dh.h"
namespace net { Dh::Dh(const unsigned char* p, int n) { DH_generate_key(0); } bool Dh::secret(int n) { return true; } }
`,
		"proto/enc.cc": `#include <memory>
#include "../src/dh.h"
using std::make_shared;
namespace net {
void start(const unsigned char* p) {
  auto dh = std::make_unique<Dh>(p, 96);
  dh->secret(1);
}
void shared(const unsigned char* p) { auto s = make_shared<Dh>(p, 4); s->secret(2); }
}
`,
	})
	ctor := "proj/src.(net::Dh).Dh"
	wantCPPEdges(t, graph, [][3]string{
		{ctor, "proj/proto.(net).start", cppExact},
		{ctor, "proj/proto.(net).shared", cppExact},
		{"proj/src.(net::Dh).secret", "proj/proto.(net).start", cppExact},
		{"proj/src.(net::Dh).secret", "proj/proto.(net).shared", cppExact},
	})
	// The factory call stays a call site of its own.
	start := graph.Functions["proj/proto.(net).start"]
	var raws []string
	for _, call := range start.Calls {
		raws = append(raws, call.Raw)
	}
	if !slices.Contains(raws, "std::make_unique<Dh>") || !slices.Contains(raws, "Dh") {
		t.Errorf("start calls = %v, want the make_unique call and the Dh construction", raws)
	}
}

// E: a qualified call of a static function of a named namespace resolves to
// the definition of its own file, and never to another file's.
func TestResolveCPPCalls_StaticNamespaceFunction(t *testing.T) {
	t.Parallel()

	graph := buildCPPProject(t, map[string]string{
		"ocb.cc": `namespace aes {
static void set_key(const unsigned char* k, int bits) { EVP_EncryptInit_ex(0, 0, 0, k, 0); }
}
int init_ctx(const unsigned char* k) { aes::set_key(k, 128); return 0; }
`,
		"other.cc": `namespace aes { void set_key(const unsigned char* k, int bits); }
void elsewhere(const unsigned char* k) { aes::set_key(k, 256); }
`,
	})
	static := "proj/ocb.cc.(aes).set_key"
	wantCPPEdges(t, graph, [][3]string{{static, "proj.init_ctx", cppExact}})
	wantNoCPPEdges(t, graph, [][2]string{{static, "proj.elsewhere"}})
}

// G: a constructor's member initializer list is the constructor's: the
// calls in it, the construction of a class-typed member, and of a base.
func TestResolveCPPCalls_MemberInitializerList(t *testing.T) {
	t.Parallel()

	graph := buildCPPProject(t, map[string]string{
		"key.h": `namespace k {
class Ctx { public: Ctx(int bits); };
class Base { public: Base(int n); };
class Key : public Base {
 public:
  Key();
 private:
  void* m_dh;
  Ctx m_ctx;
  int m_size;
};
}
`,
		"key.cc": `#include "key.h"
namespace k {
Ctx::Ctx(int bits) { setup(bits); }
Base::Base(int n) { prepare(n); }
Key::Key() : Base(1), m_dh(DH_new()), m_ctx(2048), m_size(0) { finish(); }
}
`,
	})
	key := "proj.(k::Key).Key"
	wantCPPEdges(t, graph, [][3]string{
		{"proj.(k::Ctx).Ctx", key, cppExact},
		{"proj.(k::Base).Base", key, cppExact},
	})
	var callees []string
	for _, call := range graph.Functions[key].Calls {
		callees = append(callees, call.Callee.String())
	}
	if !slices.Contains(callees, "proj.DH_new") || !slices.Contains(callees, "proj.finish") {
		t.Errorf("Key calls = %v, want DH_new from the initializer list and finish from the body", callees)
	}
	for _, callee := range callees {
		if strings.Contains(callee, "m_dh") || strings.Contains(callee, "m_size") {
			t.Errorf("Key calls = %v: a pointer or primitive member's initializer is not a call", callees)
		}
	}
}

// A member function's unqualified call of another member is an implicit
// `this->` call: the member, the inherited one, and the overrides.
func TestResolveCPPCalls_ImplicitThis(t *testing.T) {
	t.Parallel()

	graph := buildCPPProject(t, map[string]string{
		"rand.cc": `namespace r {
class Source {
 public:
  virtual void fill(unsigned char* p, int n);
  long next() { long v; fill(reinterpret_cast<unsigned char*>(&v), 8); return v; }
};
class Strong : public Source { public: void fill(unsigned char* p, int n) override; void top(); };
void Source::fill(unsigned char* p, int n) { weak(p, n); }
void Strong::fill(unsigned char* p, int n) { RAND_bytes(p, n); }
void Strong::top() { next(); }
}
`,
	})
	wantCPPEdges(t, graph, [][3]string{
		{"proj.(r::Source).fill", "proj.(r::Source).next", cppExact},
		{"proj.(r::Strong).fill", "proj.(r::Source).next", string(EdgeKindInterfaceDispatch)},
		{"proj.(r::Source).next", "proj.(r::Strong).top", cppExact},
	})
}

// A call that resolves to no project definition is left as the parser keyed
// it, and an `auto` local bound to a call the contract KB types is left to
// the KB pass, even when the project defines the producer.
func TestResolveCPPCalls_LeavesContractTypingAlone(t *testing.T) {
	t.Parallel()

	b := NewBuilderForEcosystem(ecosystemCPP, NewCPPParser())
	b.kb = botanShapedKB(t)
	graph := buildCPPProjectWith(t, b, map[string]string{
		"botan.cc": `#include <memory>
namespace Botan {
class HashFunction {
 public:
  static std::unique_ptr<HashFunction> create(const char* name);
  void update(int n);
};
std::unique_ptr<HashFunction> HashFunction::create(const char* name) { return nullptr; }
void HashFunction::update(int n) { compress(n); }
}
void digest(int n) {
  auto h = Botan::HashFunction::create("SHA-256");
  h->update(n);
}
void library(Botan::MessageAuthenticationCode& mac) { mac.set_key(1); }
`,
	})
	if call := cppCallOf(t, graph, "proj.digest", "h->update"); call.Callee.Type != "std::unique_ptr<Botan::HashFunction>" {
		t.Errorf("h->update callee = %#v, want the KB's std::unique_ptr<Botan::HashFunction>", call.Callee)
	}
	if call := cppCallOf(t, graph, "proj.library", "mac.set_key"); call.Callee.String() != "proj.(Botan::MessageAuthenticationCode).set_key" {
		t.Errorf("mac.set_key callee = %s, want it as the parser keyed it", call.Callee.String())
	}
}

// A class written with an export macro (`class LIB_API Name { ... }`) is a
// class: tree-sitter reads the macro as the name and the rest as a function,
// so the parser blanks the macro and reads the file again.
func TestResolveCPPCalls_ExportMacroClass(t *testing.T) {
	t.Parallel()

	graph := buildCPPProject(t, map[string]string{
		"api.h": `#define LIB_API
class LIB_API Provider
{
  public:
    virtual ~Provider() = default;
    virtual void random(unsigned char* p, int n) = 0;
};
class LIB_API System : public Provider { public: void random(unsigned char* p, int n) override; };
`,
		"api.cc": `#include "api.h"
#include <memory>
void System::random(unsigned char* p, int n) { RAND_bytes(p, n); }
std::shared_ptr<Provider> provider();
void fill(Provider* p, unsigned char* out) { p->random(out, 16); }
`,
	})
	wantCPPEdges(t, graph, [][3]string{{"proj.(System).random", "proj.fill", string(EdgeKindInterfaceDispatch)}})
	if graph.Functions["proj.Provider"] != nil || graph.Functions["proj.System"] != nil {
		t.Errorf("an export-macro class was read as a function")
	}
	for _, typ := range []string{"Provider", "System"} {
		if !graph.ProjectDeclaredTypes[typ] {
			t.Errorf("%s is not a project-declared type", typ)
		}
	}
}
