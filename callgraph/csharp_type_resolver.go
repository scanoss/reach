// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "github.com/scanoss/reach/callgraph/contracts"

// CSharpContractTypeResolver applies return types from the C# contracts KB.
//
// C# declares types, but `var` hides them and a fluent link
// (`ECDsa.Create().SignData(..)`) has no declaration at all. The parser
// records what each call binds and what each receiver reads, and this
// resolver supplies the missing half: the type a contract says a call
// returns.
type CSharpContractTypeResolver struct {
	kb *contracts.KnowledgeBase
}

// NewCSharpContractTypeResolver creates a resolver backed by the supplied KB.
func NewCSharpContractTypeResolver(kb *contracts.KnowledgeBase) *CSharpContractTypeResolver {
	return &CSharpContractTypeResolver{kb: kb}
}

// NewCSharpContractTypeResolverFromSource loads the installed C# KB
// (contracts.ForEcosystem). A KB that does not load degrades to a no-op
// resolver, as the other ecosystems do.
func NewCSharpContractTypeResolverFromSource() *CSharpContractTypeResolver {
	kb, err := contracts.ForEcosystem(ecosystemCSharp)
	if err != nil {
		return NewCSharpContractTypeResolver(nil)
	}
	return NewCSharpContractTypeResolver(kb)
}

// ResolveTypes fills missing declaration return types from unconditional
// contracts, and the receiver type of a call through a local bound once to a
// call a contract types.
func (r *CSharpContractTypeResolver) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	contracted := r.kb != nil && len(r.kb.Contracts) > 0
	for _, fn := range graph.Functions {
		if contracted && fn.ReturnType == "" {
			r.fillReturnType(fn)
		}
		r.bindLocalReceivers(fn)
	}
	return nil
}

func (r *CSharpContractTypeResolver) fillReturnType(fn *FunctionDecl) {
	matches := r.kb.ContractsForTolerant(fn.ID.String(), len(fn.Parameters))
	for i := range matches {
		if contract := &matches[i]; contract.When == nil && contract.Return.Type != "" {
			fn.ReturnType = contract.Return.Type
			return
		}
	}
}

// bindLocalReceivers types a call made through a local that one call in the
// same body bound. A local bound more than once is left alone: two types are
// no type.
func (r *CSharpContractTypeResolver) bindLocalReceivers(fn *FunctionDecl) {
	producers := map[string]string{}
	bound := map[string]int{}
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
// constructor types its local with no contract at all: `new SM4Engine()`
// returns an SM4Engine.
func (r *CSharpContractTypeResolver) returnTypeOf(call *FunctionCall) string {
	if r.kb != nil {
		for i, matches := 0, r.kb.ContractsForTolerant(call.Callee.String(), 0); i < len(matches); i++ {
			if contract := &matches[i]; contract.When == nil && contract.Return.Type != "" {
				return contract.Return.Type
			}
		}
	}
	if BaseFunctionName(call.Callee.Name) == constructorMethodName && call.Callee.Type != "" {
		return csharpJoin(call.Callee.Package, call.Callee.Type)
	}
	return ""
}
