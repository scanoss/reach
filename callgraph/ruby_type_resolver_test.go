// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"testing"

	"github.com/scanoss/reach/callgraph/contracts"
	"github.com/scanoss/reach/javaruntime"
)

// rubyGraph is a graph of one function holding the given calls.
func rubyGraph(calls ...FunctionCall) (*CallGraph, *FunctionDecl) {
	fn := &FunctionDecl{ID: FunctionID{Package: "acme", Name: "go"}, Calls: calls}
	return &CallGraph{Functions: map[string]*FunctionDecl{fn.ID.String(): fn}}, fn
}

// rubyCall is a call of a constant-qualified method.
func rubyCall(owner, name, assigned, receiver string) FunctionCall {
	return FunctionCall{
		Callee:      FunctionID{Type: owner, Name: name},
		AssignedVar: assigned,
		ReceiverVar: receiver,
	}
}

// Ruby declares no types, so a call through a local is only resolvable from
// what created the local. A constructor types its local even with no contract:
// OpenSSL::Cipher.new returns an OpenSSL::Cipher, the shape most Ruby crypto
// rules match.
func TestRubyResolverTypesALocalFromItsConstructor(t *testing.T) {
	graph, fn := rubyGraph(
		rubyCall("OpenSSL::Cipher", "new", "cipher", ""),
		rubyCall("", "encrypt", "", "cipher"),
	)
	r := NewRubyContractTypeResolver(&contracts.KnowledgeBase{Contracts: map[string][]contracts.Contract{"x": nil}})
	if err := r.ResolveTypes(graph, nil); err != nil {
		t.Fatal(err)
	}
	got := fn.Calls[1]
	if got.ResolvedReceiverType != "OpenSSL::Cipher" || !got.ReceiverBoundOnce {
		t.Errorf("receiver type = %q (bound once %v), want OpenSSL::Cipher", got.ResolvedReceiverType, got.ReceiverBoundOnce)
	}
}

// A local two calls bind has no one type, so it is left alone: a wrong type is
// worse than none.
func TestRubyResolverLeavesARebooundLocalAlone(t *testing.T) {
	graph, fn := rubyGraph(
		rubyCall("OpenSSL::Cipher", "new", "c", ""),
		rubyCall("OpenSSL::Digest", "new", "c", ""),
		rubyCall("", "update", "", "c"),
	)
	r := NewRubyContractTypeResolver(&contracts.KnowledgeBase{Contracts: map[string][]contracts.Contract{"x": nil}})
	if err := r.ResolveTypes(graph, nil); err != nil {
		t.Fatal(err)
	}
	if got := fn.Calls[2]; got.ResolvedReceiverType != "" {
		t.Errorf("a rebound local was typed %q", got.ResolvedReceiverType)
	}
}

// A knowledge base that does not load leaves the graph as it was, rather than
// failing the build: a graph without contract types is poorer, never wrong.
func TestRubyResolverWithoutAKBIsANoOp(t *testing.T) {
	graph, fn := rubyGraph(rubyCall("OpenSSL::Cipher", "new", "cipher", ""), rubyCall("", "encrypt", "", "cipher"))
	if err := NewRubyContractTypeResolver(nil).ResolveTypes(graph, nil); err != nil {
		t.Fatal(err)
	}
	if fn.Calls[1].ResolvedReceiverType != "" {
		t.Error("a nil KB resolved a type")
	}
}

// The resolver is registered for the ecosystem, which is how a build reaches it.
func TestRubyResolverIsRegistered(t *testing.T) {
	if NewTypeResolverForEcosystem("ruby", javaruntime.Config{}) == nil {
		t.Fatal("no type resolver for ruby")
	}
}
