// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRuby writes one Ruby source file into a fresh directory.
func writeRuby(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.rb"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// parseOne parses the single file of a directory and returns its analysis.
func parseOneRuby(t *testing.T, body string) *FileAnalysis {
	t.Helper()
	analyses, err := NewRubyParser().ParseDirectory(writeRuby(t, body), "gem")
	if err != nil {
		t.Fatal(err)
	}
	if len(analyses) != 1 {
		t.Fatalf("analyses = %d, want 1", len(analyses))
	}
	return analyses[0]
}

// moduleCalls returns the calls of the file's module init, which owns every
// top-level statement.
func moduleCalls(t *testing.T, a *FileAnalysis) []FunctionCall {
	t.Helper()
	for _, fn := range a.Functions {
		if fn.ID.Name == moduleInitMethodName {
			return fn.Calls
		}
	}
	t.Fatal("no module init")
	return nil
}

// A qualified constant receiver types the call, which is what the rules select on.
func TestRubyParserQualifiedReceiver(t *testing.T) {
	calls := moduleCalls(t, parseOneRuby(t, `Digest::MD5.hexdigest("x")`))
	if len(calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(calls))
	}
	if got := calls[0].Callee; got.Type != "Digest::MD5" || got.Name != "hexdigest#1" {
		t.Errorf("callee = %+v, want Digest::MD5.hexdigest#1 (the arity suffix every key carries)", got)
	}
	if !calls[0].StaticReceiver {
		t.Error("a constant receiver binds statically")
	}
	if len(calls[0].Arguments) != 1 || calls[0].Arguments[0] != `"x"` {
		t.Errorf("arguments = %q", calls[0].Arguments)
	}
}

// A local bound once to a constant stands for it at every call on that local.
func TestRubyParserConstantAlias(t *testing.T) {
	calls := moduleCalls(t, parseOneRuby(t, "m = Digest::MD5\nm.bubblebabble(\"m\")\n"))
	var typed int
	for _, c := range calls {
		if c.Callee.Type == "Digest::MD5" && rubyBareName(c.Callee.Name) == "bubblebabble" {
			typed++
		}
	}
	if typed != 1 {
		t.Fatalf("calls typed through the alias = %d, want 1; got %+v", typed, calls)
	}
}

// A local bound twice names no single constant, so it types nothing.
func TestRubyParserAliasReboundIsUntyped(t *testing.T) {
	calls := moduleCalls(t, parseOneRuby(t, "m = Digest::MD5\nm = Digest::SHA1\nm.hexdigest(\"x\")\n"))
	for _, c := range calls {
		if rubyBareName(c.Callee.Name) == "hexdigest" && c.Callee.Type != "" {
			t.Errorf("rebound local typed the call as %q", c.Callee.Type)
		}
	}
}

// `Digest(:MD5)` is a method whose name is spelled as a constant: it owns no type.
func TestRubyParserConstantStyleMethod(t *testing.T) {
	calls := moduleCalls(t, parseOneRuby(t, "Digest(:MD5).new\n"))
	var found bool
	for _, c := range calls {
		if rubyBareName(c.Callee.Name) == "Digest" {
			found = true
			if c.Callee.Type != "" {
				t.Errorf("type = %q, want empty", c.Callee.Type)
			}
			if len(c.Arguments) != 1 || c.Arguments[0] != ":MD5" {
				t.Errorf("arguments = %q, want [:MD5]", c.Arguments)
			}
		}
	}
	if !found {
		t.Errorf("no Digest call in %+v", calls)
	}
}

// A require names the library the file calls into.
func TestRubyParserRequires(t *testing.T) {
	a := parseOneRuby(t, "require 'openssl'\nrequire_relative 'lib/helper'\n")
	if got := a.Imports["openssl"]; got != "openssl" {
		t.Errorf("imports[openssl] = %q", got)
	}
	if got := a.Imports["helper"]; got != "lib/helper" {
		t.Errorf("imports[helper] = %q, want lib/helper", got)
	}
}

// A method declared in a module is owned by the nesting, and its calls are its own.
func TestRubyParserMethodNesting(t *testing.T) {
	a := parseOneRuby(t, "module Outer\n  class Inner\n    def run\n      Digest::SHA256.digest(\"x\")\n    end\n  end\nend\n")
	var decl *FunctionDecl
	for i := range a.Functions {
		if rubyBareName(a.Functions[i].ID.Name) == "run" {
			decl = &a.Functions[i]
		}
	}
	if decl == nil {
		t.Fatalf("no run method in %+v", a.Functions)
	}
	if decl.ID.Type != "Outer::Inner" {
		t.Errorf("owner = %q, want Outer::Inner", decl.ID.Type)
	}
	if len(decl.Calls) != 1 || decl.Calls[0].Callee.Type != "Digest::SHA256" {
		t.Errorf("calls = %+v", decl.Calls)
	}
}

// The registry hands Ruby its parser.
func TestRubyParserRegistered(t *testing.T) {
	if p := NewParserForEcosystem("ruby"); p == nil {
		t.Fatal("no parser for ruby")
	} else if p.PackageSeparator() != "::" {
		t.Errorf("separator = %q, want ::", p.PackageSeparator())
	}
}

// A call inside a nested def belongs to that def alone.
func TestRubyParserNestedDefDoesNotDuplicate(t *testing.T) {
	a := parseOneRuby(t, "def outer\n  def inner\n    Digest::MD5.hexdigest(\"x\")\n  end\nend\n")
	var total int
	for _, fn := range a.Functions {
		for _, c := range fn.Calls {
			if rubyBareName(c.Callee.Name) == "hexdigest" {
				total++
				if rubyBareName(fn.ID.Name) != "inner" {
					t.Errorf("hexdigest recorded in %q, want inner", fn.ID.Name)
				}
			}
		}
	}
	if total != 1 {
		t.Errorf("hexdigest recorded %d times, want 1", total)
	}
}

// A constant bound in one method does not type a same-named local elsewhere.
func TestRubyParserAliasesAreScoped(t *testing.T) {
	a := parseOneRuby(t, "def a\n  m = Digest::MD5\n  m.hexdigest(\"x\")\nend\ndef b(m)\n  m.hexdigest(\"y\")\nend\n")
	for _, fn := range a.Functions {
		for _, c := range fn.Calls {
			switch rubyBareName(fn.ID.Name) {
			case "a":
				if c.Callee.Type != "Digest::MD5" {
					t.Errorf("a: type = %q, want Digest::MD5", c.Callee.Type)
				}
			case "b":
				if c.Callee.Type != "" {
					t.Errorf("b: an unrelated local was typed as %q", c.Callee.Type)
				}
			}
		}
	}
}

// An operator assignment rebinds the local, so it names no single constant.
func TestRubyParserOperatorAssignmentUntypes(t *testing.T) {
	calls := moduleCalls(t, parseOneRuby(t, "m = Digest::MD5\nm ||= Digest::SHA1\nm.hexdigest(\"x\")\n"))
	for _, c := range calls {
		if rubyBareName(c.Callee.Name) == "hexdigest" && c.Callee.Type != "" {
			t.Errorf("type = %q, want empty after an operator assignment", c.Callee.Type)
		}
	}
}

// A root-qualified constant denotes the same type as the plain one.
func TestRubyParserRootQualifiedConstant(t *testing.T) {
	calls := moduleCalls(t, parseOneRuby(t, "::OpenSSL::Cipher.new(\"aes-256-gcm\")\n"))
	if len(calls) != 1 || calls[0].Callee.Type != "OpenSSL::Cipher" {
		t.Fatalf("callee = %+v, want OpenSSL::Cipher", calls)
	}
}

// Top-level statements go to the module init, a method's to the method.
func TestRubyParserModuleAndMethodSplit(t *testing.T) {
	a := parseOneRuby(t, "Digest::MD5.hexdigest(\"top\")\ndef run\n  Digest::SHA1.hexdigest(\"in\")\nend\n")
	got := map[string]string{}
	for _, fn := range a.Functions {
		for _, c := range fn.Calls {
			got[rubyBareName(fn.ID.Name)] = c.Callee.Type
		}
	}
	if got[moduleInitMethodName] != "Digest::MD5" || got["run"] != "Digest::SHA1" {
		t.Errorf("split = %v", got)
	}
}

// The anchor path stops at the method the call sits in.
func TestRubyParserASTPathStopsAtMethod(t *testing.T) {
	a := parseOneRuby(t, "module M\n  def run\n    Digest::MD5.hexdigest(\"x\")\n  end\nend\n")
	for _, fn := range a.Functions {
		for _, c := range fn.Calls {
			if strings.Contains(c.NamedASTPath, "method") {
				t.Errorf("path crosses the method boundary: %q", c.NamedASTPath)
			}
		}
	}
}

// rubyBareName is a callee name without its arity suffix, so a test can name
// the method it means.
func rubyBareName(name string) string {
	if i := strings.Index(name, "#"); i > 0 {
		return name[:i]
	}
	return name
}
