// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "github.com/scanoss/reach/callgraph/contracts"

// CContractTypeResolver applies return types from the C contracts KB.
type CContractTypeResolver struct {
	kb *contracts.KnowledgeBase
}

// NewCContractTypeResolver creates a resolver backed by the supplied KB.
func NewCContractTypeResolver(kb *contracts.KnowledgeBase) *CContractTypeResolver {
	return &CContractTypeResolver{kb: kb}
}

// NewCContractTypeResolverFromSource loads the installed C KB (contracts.ForEcosystem). Missing
// contracts degrade to a no-op resolver.
func NewCContractTypeResolverFromSource() *CContractTypeResolver {
	kb, err := contracts.ForEcosystem("c")
	if err != nil {
		return NewCContractTypeResolver(nil)
	}
	return NewCContractTypeResolver(kb)
}

// ResolveTypes fills missing declaration return types from unconditional contracts.
func (r *CContractTypeResolver) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	if r.kb == nil || len(r.kb.Contracts) == 0 {
		return nil
	}
	for _, fn := range graph.Functions {
		if fn.ReturnType != "" {
			continue
		}
		matches := r.kb.ContractsFor(fn.ID.String(), len(fn.Parameters))
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
