// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "github.com/scanoss/reach/callgraph/contracts"

// RustContractTypeResolver applies return types from the Rust contracts KB.
type RustContractTypeResolver struct {
	kb *contracts.KnowledgeBase
}

// NewRustContractTypeResolver creates a resolver backed by the supplied KB.
func NewRustContractTypeResolver(kb *contracts.KnowledgeBase) *RustContractTypeResolver {
	return &RustContractTypeResolver{kb: kb}
}

// NewRustContractTypeResolverFromSource loads the installed Rust KB (contracts.ForEcosystem). Contract
// load failures degrade to a no-op resolver.
func NewRustContractTypeResolverFromSource() *RustContractTypeResolver {
	kb, err := contracts.ForEcosystem("rust")
	if err != nil {
		return NewRustContractTypeResolver(nil)
	}
	return NewRustContractTypeResolver(kb)
}

// ResolveTypes fills missing declaration return types from unconditional contracts.
func (r *RustContractTypeResolver) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	if r.kb == nil || len(r.kb.Contracts) == 0 {
		return nil
	}
	for _, fn := range graph.Functions {
		if fn.ReturnType != "" {
			continue
		}
		matches := r.kb.ContractsForTolerant(rustFunctionFQN(fn), len(fn.Parameters))
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

func rustFunctionFQN(fn *FunctionDecl) string {
	if fn.ID.Type != "" {
		return fn.ID.Package + "::" + fn.ID.Type + "." + fn.ID.Name
	}
	return fn.ID.Package + "::" + fn.ID.Name
}
