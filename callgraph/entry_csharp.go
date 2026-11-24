// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/scanoss/reach/callgraph/entrypoints"
)

// C# entry points from the framework catalog (entrypoints/csharp): the
// actions of a controller and the lifecycle methods of a hosted service,
// which the framework finds through the type's base and calls by reflection.

// isCSharpDeclaration reports a declaration of a C# source file, whose entry
// points come from the C# catalog and never the Java one.
func isCSharpDeclaration(decl *FunctionDecl) bool {
	return strings.EqualFold(filepath.Ext(decl.FilePath), ".cs")
}

// csharpIsAction reports a method a controller exposes as an action: public,
// an instance method, neither a constructor, a property nor a synthetic
// declaration, and not marked [NonAction].
func csharpIsAction(decl *FunctionDecl) bool {
	return decl.Visibility == "public" && !decl.Static && decl.FunctionType == "method" &&
		!implicitRoot(decl) && !slices.Contains(decl.Annotations, "NonAction")
}

// csharpSupertypeEntryMark reports a method the catalog names on a type
// that derives, through application bases, from a catalog type such as
// ControllerBase or BackgroundService. An entry whose names are "*" takes
// the type's actions (csharpIsAction).
func (t *Tracer) csharpSupertypeEntryMark(decl *FunctionDecl, isUserType func(string) bool) (EntryMark, bool) {
	if decl.Static || decl.ID.Type == "" || decl.FunctionType != "method" {
		return EntryMark{}, false
	}
	catalog := entryCatalog()
	name := BaseFunctionName(decl.ID.Name)
	if !catalog.Named(entryLanguageCSharp, entrypoints.ShapeSupertype, name) {
		return EntryMark{}, false
	}
	owner := csharpJoin(decl.ID.Package, decl.ID.Type)
	for _, external := range t.csharpExternalSupertypes(owner, isUserType, map[string]bool{}) {
		dot := strings.LastIndex(external, csharpSeparator)
		if dot < 0 {
			continue
		}
		entry, ok := catalog.Match(entryLanguageCSharp, entrypoints.ShapeSupertype, external[:dot], external[dot+1:], name)
		if ok && (slices.Contains(entry.Names, name) || csharpIsAction(decl)) {
			return catalogEntryMark(&entry), true
		}
	}
	return EntryMark{}, false
}

// csharpExternalSupertypes lists the types outside the application that
// typeName derives from, directly or through application bases. A base is
// recorded under every namespace that could declare it; one the application
// declares shadows the others of its name, as the enclosing namespace
// shadows a using in C#'s lookup.
func (t *Tracer) csharpExternalSupertypes(typeName string, isUserType func(string) bool, seen map[string]bool) []string {
	if seen[typeName] {
		return nil
	}
	seen[typeName] = true
	supertypes := t.graph.SourceSupertypes[typeName]
	supertypes = append(supertypes[:len(supertypes):len(supertypes)], t.graph.TypeHierarchy[typeName]...)
	declared := map[string]bool{}
	for _, candidate := range supertypes {
		if _, ok := t.graph.SourceSupertypes[candidate]; ok {
			declared[candidate[strings.LastIndex(candidate, csharpSeparator)+1:]] = true
		}
	}
	var out []string
	for _, candidate := range supertypes {
		switch {
		case candidate == "":
		case !isUserType(candidate):
			if !declared[candidate[strings.LastIndex(candidate, csharpSeparator)+1:]] {
				out = append(out, candidate)
			}
		default:
			out = append(out, t.csharpExternalSupertypes(candidate, isUserType, seen)...)
		}
	}
	return out
}
