// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "github.com/scanoss/reach/callgraph/contracts"

// RubyContractTypeResolver applies return types from the Ruby contracts KB.
//
// Ruby declares no types, so a call through a local receiver
// (`cipher.encrypt`) can only be resolved from what created the local. The
// parser records that pair -- the constructor's AssignedVar and the call's
// ReceiverVar -- and this resolver supplies the missing half: the type a
// contract says a call returns, so the builder can bind the receiver to it.
type RubyContractTypeResolver struct {
	kb *contracts.KnowledgeBase
}

// NewRubyContractTypeResolver creates a resolver backed by the supplied KB.
func NewRubyContractTypeResolver(kb *contracts.KnowledgeBase) *RubyContractTypeResolver {
	return &RubyContractTypeResolver{kb: kb}
}

// NewRubyContractTypeResolverFromSource loads the installed Ruby KB
// (contracts.ForEcosystem). A KB that does not load degrades to a no-op
// resolver, as the other ecosystems do: a graph without contract types is
// poorer, never wrong.
func NewRubyContractTypeResolverFromSource() *RubyContractTypeResolver {
	kb, err := contracts.ForEcosystem("ruby")
	if err != nil {
		return NewRubyContractTypeResolver(nil)
	}
	return NewRubyContractTypeResolver(kb)
}

// ResolveTypes fills missing declaration return types from unconditional
// contracts, and the resolved receiver type of a call whose receiver is a
// local bound once to a call a contract types.
func (r *RubyContractTypeResolver) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	if r.kb == nil || len(r.kb.Contracts) == 0 {
		return nil
	}
	for _, fn := range graph.Functions {
		if fn.ReturnType == "" {
			r.fillReturnType(fn)
		}
		r.bindLocalReceivers(fn)
	}
	return nil
}

// fillReturnType takes the return type of the first unconditional contract of
// the declaration.
func (r *RubyContractTypeResolver) fillReturnType(fn *FunctionDecl) {
	matches := r.kb.ContractsForTolerant(fn.ID.String(), len(fn.Parameters))
	for i := range matches {
		contract := &matches[i]
		if contract.When == nil && contract.Return.Type != "" {
			fn.ReturnType = contract.Return.Type
			return
		}
	}
}

// bindLocalReceivers types a call made through a local that one call in the
// same function bound, when a contract says what that call returns. A local
// bound more than once is left alone: two types are no type.
func (r *RubyContractTypeResolver) bindLocalReceivers(fn *FunctionDecl) {
	producers := map[string]string{} // local -> the type its producer returns
	bound := map[string]int{}        // local -> how many calls bind it
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.AssignedVar == "" {
			continue
		}
		bound[call.AssignedVar]++
		if t := r.returnTypeOf(call); t != "" {
			producers[call.AssignedVar] = t
		}
	}
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.ReceiverVar == "" || call.ResolvedReceiverType != "" {
			continue
		}
		if bound[call.ReceiverVar] != 1 {
			continue
		}
		if t := producers[call.ReceiverVar]; t != "" {
			call.ResolvedReceiverType = t
			call.ReceiverBoundOnce = true
		}
	}
}

// returnTypeOf is what an unconditional contract says a call returns. A
// constructor with no contract still types its local: `OpenSSL::Cipher.new`
// returns an OpenSSL::Cipher, which is the shape most Ruby crypto rules match.
func (r *RubyContractTypeResolver) returnTypeOf(call *FunctionCall) string {
	matches := r.kb.ContractsForTolerant(call.Callee.String(), 0)
	for i := range matches {
		contract := &matches[i]
		if contract.When == nil && contract.Return.Type != "" {
			return contract.Return.Type
		}
	}
	if call.Callee.Name == "new" && call.Callee.Type != "" {
		return call.Callee.Type
	}
	return ""
}
