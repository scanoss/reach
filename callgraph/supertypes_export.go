// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// ExportSupertypes is SourceSupertypes with each wildcard-import clause
// settled against the types this graph knows: the scanned source's, and the
// platform's and dependencies' the bytecode index read. The parser writes a
// supertype named through wildcard imports as its candidates in Java's lookup
// order (`pkg.T|wild1.T|...|java.lang.T`). The same-package type shadows the
// on-demand imports, and two on-demand imports of one name do not compile, so
// the first candidate the graph knows is the type meant. A clause with no
// known candidate keeps all of them, for a stitcher to settle against the
// components it joins. The graph is not modified.
func (g *CallGraph) ExportSupertypes() map[string][]string {
	if g == nil || len(g.SourceSupertypes) == 0 {
		return nil
	}
	known := g.knownTypeNames()
	out := make(map[string][]string, len(g.SourceSupertypes))
	for owner, clauses := range g.SourceSupertypes {
		resolved := make([]string, len(clauses))
		for i, clause := range clauses {
			resolved[i] = settleWildcardSupertype(clause, known)
		}
		out[owner] = resolved
	}
	return out
}

// settleWildcardSupertype returns the first known candidate of a wildcard
// clause, or the clause unchanged. A clause that is not of the wildcard shape
// (it ends with the java.lang candidate) lists same-scope declarations or an
// unresolvable marker, which lookup order does not decide.
func settleWildcardSupertype(clause string, known map[string]bool) string {
	candidates := strings.Split(clause, javaSupertypeAlternatives)
	if len(candidates) < 2 || !strings.HasPrefix(candidates[len(candidates)-1], javaLangPackage+".") {
		return clause
	}
	for _, candidate := range candidates {
		if candidate == javaUnresolvableSupertype {
			return clause
		}
	}
	for _, candidate := range candidates {
		if known[normalizeHierarchyName(candidate)] {
			return candidate
		}
	}
	return clause
}

// knownTypeNames is every type the graph holds a declaration or a bytecode
// record of, in normalizeHierarchyName form.
func (g *CallGraph) knownTypeNames() map[string]bool {
	known := make(map[string]bool, len(g.SourceSupertypes)+len(g.TypeHierarchy))
	for owner := range g.SourceSupertypes {
		known[normalizeHierarchyName(owner)] = true
	}
	for owner, parents := range g.TypeHierarchy {
		known[normalizeHierarchyName(owner)] = true
		for _, parent := range parents {
			known[normalizeHierarchyName(parent)] = true
		}
	}
	for key := range g.ExternalMethodSignatures {
		pkg, rest, ok := strings.Cut(key, "|")
		if !ok {
			continue
		}
		typ, _, _ := strings.Cut(rest, "|")
		if typ != "" {
			known[normalizeHierarchyName(qualifiedJavaTypeName(pkg, typ))] = true
		}
	}
	for _, decl := range g.Functions {
		if decl != nil && decl.ID.Type != "" {
			known[declOwnerFQN(decl.ID)] = true
		}
	}
	return known
}
