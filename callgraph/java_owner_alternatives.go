// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// recordJavaOwnerAlternatives marks each call whose owner type the parser
// guessed. A type imported only on demand (`import com.nimbusds.jwt.*;`) is
// resolved per file, without knowing which package declares it, so the parser
// keys it on the file's own package or on the first on-demand import. Only
// the whole graph knows which of those packages declares the type;
// reanchorGuessedJavaOwners reads the alternatives recorded here.
func recordJavaOwnerAlternatives(analysis *FileAnalysis) {
	if len(analysis.WildcardImports) == 0 {
		return
	}
	for i := range analysis.Functions {
		calls := analysis.Functions[i].Calls
		for j := range calls {
			calls[j].OwnerAlternatives = javaOwnerAlternatives(calls[j].Callee, analysis)
		}
	}
}

func javaOwnerAlternatives(callee FunctionID, analysis *FileAnalysis) []string {
	typ := callee.Type
	if !looksLikeJavaTypeName(typ) || strings.ContainsAny(typ, ".<>[]()") {
		return nil
	}
	if _, imported := analysis.Imports[typ]; imported {
		return nil
	}
	if _, declared := analysis.ClassBases[typ]; declared {
		return nil
	}
	if analysis.TypeNamesAtRisk[typ] {
		return nil
	}
	own := javaAnalysisPackagePath(analysis)
	guessed := callee.Package == own
	alternatives := []string{joinJavaPackage(own, typ)}
	for _, wildcard := range analysis.WildcardImports {
		guessed = guessed || callee.Package == wildcard
		alternatives = append(alternatives, wildcard+"."+typ)
	}
	if !guessed {
		return nil
	}
	return alternatives
}

// reanchorGuessedJavaOwners moves each call whose owner type the parser
// guessed onto the alternative the graph declares. The file's own package
// wins when it declares the type, since a type of the package shadows an
// on-demand import (JLS 6.4.1); otherwise exactly one on-demand import must
// declare it, in an artifact the caller compiles against. A guess the graph
// already declares, or one no alternative settles, is left as it is.
//
// Without it, `ConfigurableJWTProcessor p = ...; p.process(jwt)` in
// oauth2-oidc-sdk, whose file imports com.nimbusds.jwt.proc.* among others,
// named a ConfigurableJWTProcessor in the caller's own package, and the call
// never reached nimbus-jose-jwt.
func reanchorGuessedJavaOwners(graph *CallGraph) {
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if len(call.OwnerAlternatives) == 0 {
				continue
			}
			if _, declared := graph.SourceSupertypes[qualifiedJavaTypeName(call.Callee.Package, call.Callee.Type)]; declared {
				continue
			}
			if owner, ok := declaredJavaOwnerAlternative(graph, fn, call.OwnerAlternatives); ok {
				call.Callee.Package = strings.TrimSuffix(owner, "."+call.Callee.Type)
			}
		}
	}
}

func declaredJavaOwnerAlternative(graph *CallGraph, caller *FunctionDecl, alternatives []string) (string, bool) {
	if _, declared := graph.SourceSupertypes[alternatives[0]]; declared {
		return alternatives[0], true
	}
	chosen := ""
	for _, alternative := range alternatives[1:] {
		if _, declared := graph.SourceSupertypes[alternative]; !declared {
			continue
		}
		if !graph.artifacts.compilesAgainst(declOwnerFQN(caller.ID), alternative) {
			continue
		}
		if chosen != "" && chosen != alternative {
			return "", false
		}
		chosen = alternative
	}
	return chosen, chosen != ""
}

// reanchorGuessedJavaOwnersFromBytecode is reanchorGuessedJavaOwners for a
// type no source in the graph declares but a dependency JAR does (a component
// mined alone, or a client scan, with its dependencies as type-only packages):
// a call whose guessed owner neither source nor bytecode knows moves to the
// single alternative the bytecode index knows. It runs after type resolution,
// which records every indexed class in graph.TypeHierarchy.
func reanchorGuessedJavaOwnersFromBytecode(graph *CallGraph) int {
	if len(graph.TypeHierarchy) == 0 {
		return 0
	}
	known := func(t string) bool {
		if _, ok := graph.SourceSupertypes[t]; ok {
			return true
		}
		_, ok := graph.TypeHierarchy[t]
		return ok
	}
	moved := 0
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if len(call.OwnerAlternatives) == 0 || known(qualifiedJavaTypeName(call.Callee.Package, call.Callee.Type)) {
				continue
			}
			chosen := ""
			for _, alternative := range call.OwnerAlternatives {
				if _, ok := graph.TypeHierarchy[alternative]; !ok {
					continue
				}
				if chosen != "" && chosen != alternative {
					chosen = ""
					break
				}
				chosen = alternative
			}
			if chosen != "" {
				oldCalleeKey := call.Callee.String()
				call.Callee.Package = strings.TrimSuffix(chosen, "."+call.Callee.Type)
				// The caller index was built before type resolution; move the
				// edge there too, as rewriteJavaCallFromIndex does.
				addCaller(graph.Callers, call.Callee.String(), fn.ID.String(), oldCalleeKey)
				moved++
			}
		}
	}
	return moved
}
