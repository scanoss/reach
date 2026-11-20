// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "strings"

// csharpOwnerTargets resolves a C# external call whose owner the caller could
// not name. C# writes a type through an on-demand `using`, so a call into a
// dependency is keyed on the caller's own namespace: `Reach.App.(SM4Engine)`
// for a type the dependency declares as
// `Org.BouncyCastle.Crypto.Engines.(SM4Engine)`. The call carries every owner
// it can have (candidate_owners, 1.39); this re-keys it on each and keeps the
// one a dependency declares.
//
// Exactly one owner must resolve: two usings that both declare the type name
// make the call ambiguous, and a wrong edge costs precision, which is the one
// thing reachability must not spend.
func csharpOwnerTargets(
	e callEdge,
	directDeps map[ComponentKey]bool,
	functionsBySignature map[string][]graphNode,
	functionsByCanonicalSignature map[string][]graphNode,
	aliasByKey map[string][]graphNode,
) edgeTargets {
	if len(e.candidateOwners) < 2 {
		return edgeTargets{}
	}
	member, ok := csharpKeyMember(e.target)
	if !ok {
		return edgeTargets{}
	}
	var found edgeTargets
	chosen := ""
	// The first candidate is the caller's own namespace, the guess that
	// already failed to resolve.
	for _, owner := range e.candidateOwners[1:] {
		key, ok := csharpKeyForOwner(owner, member)
		if !ok {
			continue
		}
		targets := externalTargets(key, e.targetCanonicalSignature, directDeps, functionsBySignature, functionsByCanonicalSignature, aliasByKey)
		if len(targets.nodes) == 0 {
			continue
		}
		if chosen != "" && chosen != owner {
			return edgeTargets{}
		}
		chosen, found = owner, targets
	}
	return found
}

// csharpKeyMember is the `).Method#arity` tail of a C# function key, the part
// that survives a change of owner.
func csharpKeyMember(key string) (string, bool) {
	i := strings.LastIndex(key, ").")
	if i < 0 || !strings.Contains(key, ".(") {
		return "", false
	}
	return key[i+1:], true
}

// csharpKeyForOwner re-spells a key on a fully qualified owner type:
// `Org.BouncyCastle.Crypto.Engines.SM4Engine` plus `.Init#2` becomes
// `Org.BouncyCastle.Crypto.Engines.(SM4Engine).Init#2`.
func csharpKeyForOwner(owner, member string) (string, bool) {
	i := strings.LastIndex(owner, ".")
	if i <= 0 || i == len(owner)-1 {
		return "", false
	}
	return owner[:i] + ".(" + owner[i+1:] + ")" + member, true
}
