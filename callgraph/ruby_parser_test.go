// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// parseRuby writes one Ruby file and parses it.
func parseRuby(t *testing.T, name, src string) *FileAnalysis {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analysis, err := NewRubyParser().ParseFile(path, "acme")
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	return analysis
}

// callsOf is the calls of the named function, in source order.
func callsOf(a *FileAnalysis, name string) []FunctionCall {
	for _, f := range a.Functions {
		if f.ID.Name == name {
			return f.Calls
		}
	}
	return nil
}

// A `require` names a gem or the standard library, a `require_relative` a file
// beside this one. The grammar writes both as calls, so a parser that did not
// read them would report them as crypto calls and lose the imports.
func TestRubyRequiresAreImportsNotCalls(t *testing.T) {
	a := parseRuby(t, "app.rb", `require 'openssl'
require 'digest/sha2'
require_relative 'lib/helper'
OpenSSL::Cipher.new('aes-256-gcm')
`)
	for _, c := range []struct{ key, want string }{
		{"openssl", "openssl"},
		{"sha2", "digest/sha2"},
		{"helper", "lib/helper"},
	} {
		if got := a.Imports[c.key]; got != c.want {
			t.Errorf("import %q = %q, want %q", c.key, got, c.want)
		}
	}
	calls := callsOf(a, rubyTopLevel)
	if len(calls) != 1 || calls[0].Callee.Name != "new" {
		t.Fatalf("top-level calls = %+v, want only the Cipher.new", calls)
	}
}

// Ruby runs a file's body, so a call written outside any method is real. A
// graph that dropped it would miss the cipher a script configures at its top.
func TestRubyFileBodyIsAFunction(t *testing.T) {
	a := parseRuby(t, "script.rb", `cipher = OpenSSL::Cipher.new('aes-256-gcm')
cipher.encrypt
`)
	calls := callsOf(a, rubyTopLevel)
	if len(calls) != 2 {
		t.Fatalf("top-level calls = %d, want 2", len(calls))
	}
	if calls[0].Callee.Type != "OpenSSL::Cipher" || calls[0].Callee.Name != "new" {
		t.Errorf("first call = %q.%q, want OpenSSL::Cipher.new", calls[0].Callee.Type, calls[0].Callee.Name)
	}
	if calls[0].AssignedVar != "cipher" {
		t.Errorf("the constructor binds %q, want cipher", calls[0].AssignedVar)
	}
	if calls[1].ReceiverVar != "cipher" || calls[1].Callee.Type != "" {
		t.Errorf("second call receiver = %q type %q; a local receiver stays caller-local",
			calls[1].ReceiverVar, calls[1].Callee.Type)
	}
}

// A method's owner is the module and class nesting around it, and `def self.x`
// is static on that owner.
func TestRubyMethodsCarryTheirNamespace(t *testing.T) {
	a := parseRuby(t, "signer.rb", `module Acme
  module Crypto
    class Signer
      def sign(data)
        OpenSSL::HMAC.hexdigest(@digest, @key, data)
      end

      def self.weak
        Digest::MD5.hexdigest("x")
      end
    end
  end
end
`)
	want := map[string]struct {
		owner  string
		static bool
	}{
		"sign": {"Acme::Crypto::Signer", false},
		"weak": {"Acme::Crypto::Signer", true},
	}
	if len(a.Functions) != len(want) {
		t.Fatalf("functions = %d, want %d (a body with no calls is not one)", len(a.Functions), len(want))
	}
	for _, f := range a.Functions {
		w, ok := want[f.ID.Name]
		if !ok {
			t.Errorf("unexpected function %q", f.ID.Name)
			continue
		}
		if f.ID.Type != w.owner || f.OwnerType != w.owner {
			t.Errorf("%s owner = %q/%q, want %q", f.ID.Name, f.ID.Type, f.OwnerType, w.owner)
		}
		if f.Static != w.static {
			t.Errorf("%s static = %v, want %v", f.ID.Name, f.Static, w.static)
		}
	}
}

// Positions are 1-based and cover the call as written, which is what a card
// compares against an OpenGrep match.
func TestRubyCallPositions(t *testing.T) {
	a := parseRuby(t, "pos.rb", `def go
  OpenSSL::HMAC.hexdigest(a, b, c)
end
`)
	calls := callsOf(a, "go")
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	c := calls[0]
	if c.Line != 2 || c.EndLine != 2 {
		t.Errorf("lines = %d..%d, want 2..2", c.Line, c.EndLine)
	}
	if c.StartCol != 3 {
		t.Errorf("start column = %d, want 3 (1-based)", c.StartCol)
	}
	if c.Raw != "OpenSSL::HMAC.hexdigest(a, b, c)" {
		t.Errorf("raw = %q", c.Raw)
	}
}

// A directory parse reads the project's own Ruby, and skips the trees a
// project keeps dependencies in and, unless asked, its tests.
func TestRubyDirectorySkips(t *testing.T) {
	p := NewRubyParser()
	for _, dir := range []string{"vendor", ".bundle", "spec", "test", "node_modules"} {
		if !p.SkipsDirNamed(dir) {
			t.Errorf("%s is not skipped", dir)
		}
	}
	if p.SkipsDirNamed("lib") {
		t.Error("lib is skipped")
	}
	if NewRubyParser(WithIncludeTests(true)).SkipsDirNamed("spec") {
		t.Error("spec is skipped with tests included")
	}

	dir := t.TempDir()
	for name, src := range map[string]string{
		"a.rb":      "OpenSSL::Cipher.new('aes')\n",
		"a_spec.rb": "OpenSSL::Cipher.new('aes')\n",
		"notes.txt": "not ruby\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	got, err := p.ParseDirectory(dir, "acme")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || filepath.Base(got[0].FilePath) != "a.rb" {
		t.Fatalf("parsed %d files, want only a.rb", len(got))
	}
}

// The parser is registered for the ecosystem, which is how a scan reaches it.
func TestRubyParserIsRegistered(t *testing.T) {
	if NewParserForEcosystem("ruby") == nil {
		t.Fatal("no parser for ruby")
	}
	if got := NewRubyParser().PackageSeparator(); got != "::" {
		t.Errorf("package separator = %q, want ::", got)
	}
}
