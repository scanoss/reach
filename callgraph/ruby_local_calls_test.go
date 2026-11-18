// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"testing"
)

// buildRubyGraph builds a graph over a directory of named Ruby sources, as a
// gem's own build does.
func buildRubyGraph(t *testing.T, files map[string]string) *CallGraph {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	graph, err := NewBuilderForEcosystem(ecosystemRuby, NewRubyParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "lib"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

// callsOf is the targets the named function calls.
func callsOf(t *testing.T, graph *CallGraph, key string) []string {
	t.Helper()
	fn := graph.Functions[key]
	if fn == nil {
		var have []string
		for k := range graph.Functions {
			have = append(have, k)
		}
		t.Fatalf("no function %q; have %q", key, have)
	}
	out := make([]string, 0, len(fn.Calls))
	for _, c := range fn.Calls {
		out = append(out, c.Callee.String())
	}
	return out
}

// hasCall reports whether want is among the function's targets.
func hasCall(t *testing.T, graph *CallGraph, key, want string) bool {
	t.Helper()
	for _, got := range callsOf(t, graph, key) {
		if got == want {
			return true
		}
	}
	return false
}

// A relative constant names the class the enclosing namespace holds, in
// whichever file of the gem it is declared.
func TestRubyLocalCallsRelativeConstant(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"jwt.rb": "module JWT\n  def self.encode(payload)\n    Encode.new(payload).segments\n  end\nend\n",
		"jwt/encode.rb": "module JWT\n  class Encode\n    def initialize(payload)\n      @payload = payload\n    end\n" +
			"    def segments\n      'x'\n    end\n  end\nend\n",
	})
	// An instantiation runs the class's `initialize` and stays a site of its
	// own: the card matcher reads a site from the component's external
	// calls, and binding the call would take it out of them.
	if !hasCall(t, graph, "lib.(JWT).encode#1", "lib::jwt.(JWT::Encode).initialize#1") {
		t.Errorf("`Encode.new` does not reach JWT::Encode#initialize; calls = %q",
			callsOf(t, graph, "lib.(JWT).encode#1"))
	}
	if !hasCall(t, graph, "lib.(JWT).encode#1", "lib.(Encode).new#1") {
		t.Errorf("the instantiation must also stay external for the matcher; calls = %q",
			callsOf(t, graph, "lib.(JWT).encode#1"))
	}
	// `Encode.new(..).segments` runs a method of the class the chain head
	// instantiates.
	if !hasCall(t, graph, "lib.(JWT).encode#1", "lib::jwt.(JWT::Encode).segments#0") {
		t.Errorf("the constructor chain does not reach #segments; calls = %q",
			callsOf(t, graph, "lib.(JWT).encode#1"))
	}
}

// A class may declare one name on both sides; the receiver says which one a
// call runs.
func TestRubyLocalCallsClassAndInstanceSide(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"client.rb": "module RC\n  def self.get(url)\n    Request.execute(url)\n  end\nend\n",
		"rc/request.rb": "module RC\n  class Request\n    def self.execute(url)\n      new(url).execute\n    end\n" +
			"    def initialize(url)\n      @url = url\n    end\n    def execute\n      @url\n    end\n  end\nend\n",
	})
	if !hasCall(t, graph, "lib.(RC).get#1", "lib::rc.(RC::Request).execute#1") {
		t.Errorf("`Request.execute` must run the class-side method, not the instance one; calls = %q",
			callsOf(t, graph, "lib.(RC).get#1"))
	}
	if !hasCall(t, graph, "lib::rc.(RC::Request).execute#1", "lib::rc.(RC::Request).execute#0") {
		t.Errorf("`new(url).execute` must run the instance method; calls = %q",
			callsOf(t, graph, "lib::rc.(RC::Request).execute#1"))
	}
}

// A bare word is a call where the class declares the method, and nothing
// where it does not: a local read, or a method of a base the gem does not
// declare.
func TestRubyLocalCallsBareSelfCall(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"enc.rb": "class Enc\n  def segments\n    header = 'h'\n    combine(header, signature)\n  end\n" +
			"  def signature\n    'sig'\n  end\n  def combine(a, b)\n    a + b\n  end\nend\n",
	})
	calls := callsOf(t, graph, "lib.(Enc).segments#0")
	var signature, local int
	for _, c := range calls {
		switch c {
		case "lib.(Enc).signature#0":
			signature++
		case "lib.header#0":
			local++
		}
	}
	if signature != 1 {
		t.Errorf("the bare `signature` must be one call on self; calls = %q", calls)
	}
	if local != 0 {
		t.Errorf("`header` is a local the body binds, not a call; calls = %q", calls)
	}
}

// A component publishes each method under the constant path a dependent
// spells it by, without a package and without an arity.
func TestResolveRubyExportsPublicPath(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"jwt.rb": "module JWT\n  def self.encode(a, b)\n    'x'\n  end\nend\n",
	})
	if got := graph.RubyExports["(JWT).encode"]; got != "lib.(JWT).encode#2" {
		t.Errorf("exports[\"(JWT).encode\"] = %q, want lib.(JWT).encode#2 (exports = %v)", got, graph.RubyExports)
	}
}

// Every file of a directory owns its top-level statements: a Ruby package is
// a directory, so one `<module>` key per package would keep a single file's.
func TestRubyModuleInitIsPerFile(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"a.rb": "Digest::MD5.hexdigest(\"x\")\n",
		"b.rb": "Digest::SHA256.hexdigest(\"y\")\n",
	})
	var files []string
	for key, fn := range graph.Functions {
		if BaseFunctionName(fn.ID.Name) == moduleInitMethodName {
			files = append(files, key+" "+fn.FilePath)
		}
	}
	if len(files) != 2 {
		t.Errorf("module inits = %q, want one per file", files)
	}
}

// Ruby writes an attribute with a setter call; the rules read it as the
// attribute store it is.
func TestRubyAttributeStores(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"a.rb": "ctx = OpenSSL::SSL::SSLContext.new\nctx.verify_mode = OpenSSL::SSL::VERIFY_NONE\n" +
			"def tune(c)\n  c.timeout ||= 5\nend\n",
	})
	var got []string
	for _, fn := range graph.Functions {
		for _, st := range fn.AttributeStores {
			got = append(got, st.Receiver+"."+st.Attribute+st.Operator+st.Value.Text)
		}
	}
	sort.Strings(got)
	want := []string{"c.timeout||=5", "ctx.verify_mode=OpenSSL::SSL::VERIFY_NONE"}
	if !slices.Equal(got, want) {
		t.Errorf("stores = %q, want %q", got, want)
	}
}

// A call on a receiver nothing types may run any method of that name the
// component declares; each candidate is a guess, so each is name-only.
func TestRubyDynamicDispatchCandidates(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"enc.rb": "class Enc\n  def signature\n    @algorithm.sign(data: 1)\n  end\nend\n",
		"a.rb":   "class Hmac\n  def sign(data:)\n    data\n  end\nend\n",
		"b.rb":   "class Ecdsa\n  def sign(data:)\n    data\n  end\nend\n",
	})
	// The unresolved call stays beside the candidates: it is the site the
	// card matcher reads, and it resolves to no declaration of its own.
	got := callsOf(t, graph, "lib.(Enc).signature#0")
	sort.Strings(got)
	want := []string{"lib.(Ecdsa).sign#1", "lib.(Hmac).sign#1", "lib.sign#1"}
	if !slices.Equal(got, want) {
		t.Errorf("calls = %q, want %q", got, want)
	}
}

// An instance variable belongs to the class, so the constructor one method
// runs types the calls every other method makes on it.
func TestRubyInstanceVariableTypedByItsConstructor(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"up.rb": "class Uploader\n  def initialize\n    @signer = Aws::Sigv4::Signer.new(service: 's3')\n  end\n" +
			"  def headers(url)\n    @signer.sign_request(url: url)\n  end\nend\n",
	})
	if !hasCall(t, graph, "lib.(Uploader).headers#1", "lib.(Aws::Sigv4::Signer).sign_request#1") {
		t.Errorf("`@signer.sign_request` names no owner; calls = %q",
			callsOf(t, graph, "lib.(Uploader).headers#1"))
	}
}

// An instance variable two constructors bind is two types, which is no type.
func TestRubyInstanceVariableBoundTwiceIsUntyped(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"up.rb": "class Uploader\n  def initialize\n    @c = OpenSSL::Cipher.new('aes')\n  end\n" +
			"  def swap\n    @c = OpenSSL::Digest.new('sha256')\n  end\n" +
			"  def run\n    @c.update('x')\n  end\nend\n",
	})
	for _, c := range callsOf(t, graph, "lib.(Uploader).run#0") {
		if c != "lib.update#1" {
			t.Errorf("a rebound instance variable was typed: %q", c)
		}
	}
}

// Loading a file runs every statement outside a method in it, so a require
// is a call on the module init of the file it loads.
func TestRubyRequireRunsTheModuleInit(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"app.rb":        "require 'signer'\nrequire_relative 'app/helper'\n",
		"signer.rb":     "module Signer\nend\n",
		"app/helper.rb": "module Helper\nend\n",
	})
	calls := callsOf(t, graph, "lib::app.<module>")
	sort.Strings(calls)
	want := []string{"lib.require#1", "lib.require_relative#1", "lib::app::helper.<module>", "lib::signer.<module>"}
	if !slices.Equal(calls, want) {
		t.Errorf("calls = %q, want %q", calls, want)
	}
}

// A require whose path the source does not state names no file.
func TestRubyRequireOfAnInterpolatedPathIsNotAnEdge(t *testing.T) {
	graph := buildRubyGraph(t, map[string]string{
		"app.rb": "require \"signer/#{name}\"\n",
	})
	for _, c := range callsOf(t, graph, "lib::app.<module>") {
		if c != "lib.require#1" {
			t.Errorf("an interpolated require became the edge %q", c)
		}
	}
}
