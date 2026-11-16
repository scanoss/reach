// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "github.com/scanoss/reach/callgraph/contracts"

// CPPContractTypeResolver applies return types from the C++ contracts KB.
type CPPContractTypeResolver struct {
	kb *contracts.KnowledgeBase
}

// NewCPPContractTypeResolver creates a resolver backed by the supplied KB.
func NewCPPContractTypeResolver(kb *contracts.KnowledgeBase) *CPPContractTypeResolver {
	return &CPPContractTypeResolver{kb: kb}
}

// NewCPPContractTypeResolverFromSource loads the installed C++ KB (contracts.ForEcosystem).
func NewCPPContractTypeResolverFromSource() *CPPContractTypeResolver {
	kb, err := contracts.ForEcosystem("cpp")
	if err != nil {
		return NewCPPContractTypeResolver(nil)
	}
	return NewCPPContractTypeResolver(kb)
}

// ResolveTypes fills missing declaration return types from unconditional contracts.
func (r *CPPContractTypeResolver) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	if r.kb == nil || len(r.kb.Contracts) == 0 {
		return nil
	}
	for _, fn := range graph.Functions {
		if fn.ReturnType != "" {
			continue
		}
		method, _ := splitMethodArity(&fn.ID)
		matches := r.kb.ContractsFor(method, len(fn.Parameters))
		for i := range matches {
			contract := &matches[i]
			if contract.When == nil && contract.Return.Type != "" {
				fn.ReturnType = contract.Return.Type
				break
			}
		}
	}
	return nil
}
