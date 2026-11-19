// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// reanchorGuessedCSharpOwners moves each call whose owner namespace the parser
// guessed onto the alternative the graph declares. C# writes every type
// through an on-demand `using`, so an unqualified owner is keyed on the
// caller's own namespace until the whole graph says which using declares it.
// The caller's own namespace wins when it declares the type; otherwise exactly
// one using must, or the guess stands.
func reanchorGuessedCSharpOwners(graph *CallGraph) {
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if len(call.OwnerAlternatives) == 0 {
				continue
			}
			if _, declared := graph.SourceSupertypes[csharpJoin(call.Callee.Package, call.Callee.Type)]; declared {
				continue
			}
			if owner, ok := declaredCSharpOwnerAlternative(graph, call.OwnerAlternatives); ok {
				call.Callee.Package = strings.TrimSuffix(owner, csharpSeparator+call.Callee.Type)
			}
		}
	}
}

func declaredCSharpOwnerAlternative(graph *CallGraph, alternatives []string) (string, bool) {
	if _, declared := graph.SourceSupertypes[alternatives[0]]; declared {
		return alternatives[0], true
	}
	chosen := ""
	for _, alternative := range alternatives[1:] {
		if _, declared := graph.SourceSupertypes[alternative]; !declared {
			continue
		}
		if chosen != "" && chosen != alternative {
			return "", false
		}
		chosen = alternative
	}
	return chosen, chosen != ""
}
