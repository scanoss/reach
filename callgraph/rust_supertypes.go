// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// rust_supertypes.go records a Rust crate's trait hierarchy as supertypes
// (FileAnalysis.Supertypes), in function-key owner form (`aead.AeadInPlace`),
// so a stitch follows a call through a trait as it follows one through a Java
// interface:
//
//   - `impl Trait for Type` makes Trait a supertype of Type: a method Type only
//     gets from the trait's default body (`encrypt_in_place` on
//     ChaChaPoly1305) is found in the trait, and Type's own method implements
//     the trait's declaration.
//   - `trait A: B + C` makes B and C supertypes of A.
//   - a blanket `impl<G: Bound> Trait for G` gives every type that implements
//     Bound the block's methods, which are keyed under the parameter
//     (`aead.(Alg).encrypt` for `impl<Alg: AeadInPlace> Aead for Alg`): the
//     parameter's owner is recorded as a supertype of Bound.
//
// A trait's required methods, declared without a body, are recorded as
// abstract declarations (processRustTraitDefaults), so a call to one
// dispatches to the implementations instead of joining nothing.

// recordRustImplSupertypes records what an impl block adds to the hierarchy.
func (p *RustParser) recordRustImplSupertypes(implScope *FileAnalysis, declPackage, typeName string, traits []string, generics map[string]string, analysis *FileAnalysis) {
	if len(traits) == 0 {
		return
	}
	trait := rustTraitOwner(implScope, traits[0])
	if trait == "" {
		return
	}
	owner := rustTypeOwner(declPackage, typeName)
	if bound, blanket := generics[typeName]; blanket {
		// `impl<G: Bound> Trait for G`: every implementation of Bound has the
		// block's methods.
		for _, b := range rustBoundTraits(bound) {
			if boundOwner := rustTraitOwner(implScope, b); boundOwner != "" && owner != "" {
				addRustSupertype(analysis, boundOwner, owner)
			}
		}
		return
	}
	if owner != "" && owner != trait {
		addRustSupertype(analysis, owner, trait)
	}
}

// recordRustTraitSupertypes records a trait's supertraits.
func (p *RustParser) recordRustTraitSupertypes(node *sitter.Node, src []byte, scope *FileAnalysis, packagePath, traitName string, analysis *FileAnalysis) {
	bounds := node.ChildByFieldName("bounds")
	if bounds == nil || traitName == "" {
		return
	}
	owner := rustTypeOwner(packagePath, traitName)
	for i := 0; i < int(bounds.NamedChildCount()); i++ {
		bound := bounds.NamedChild(i)
		text := stripRustGenericArgs(rustScopedTypeText(bound, src))
		if text == "" || bound.Type() == "lifetime" {
			continue
		}
		if super := rustTraitOwner(scope, text); super != "" && super != owner {
			addRustSupertype(analysis, owner, super)
		}
	}
}

// rustTraitOwner is a trait path's owner form, the package and name the
// trait's own declarations are keyed under: `aead::AeadInPlace` is
// `aead.AeadInPlace`. A path into the standard library is left out: no
// closure holds its source.
func rustTraitOwner(scope *FileAnalysis, path string) string {
	path = strings.TrimSpace(stripRustGenericArgs(path))
	if path == "" || path == rustSelfType {
		return ""
	}
	var facts *rustFileFacts
	if scope != nil {
		facts = scope.rustFacts
	}
	pkg, typ := rustQualifyType(scope, facts, path)
	if pkg == "" || typ == "" || rustStandardCrates[rustCrateRoot(pkg)] || pkg == rustPreludePackage {
		return ""
	}
	return pkg + "." + typ
}

// rustTypeOwner is the owner form of a type the crate declares.
func rustTypeOwner(pkg, typ string) string {
	if pkg == "" || typ == "" {
		return ""
	}
	return pkg + "." + typ
}

// rustBoundTraits splits a generic parameter's bound (`AeadInPlace`,
// `Clone + Encrypt`) into its traits.
func rustBoundTraits(bound string) []string {
	var out []string
	for _, part := range strings.Split(bound, "+") {
		part = strings.TrimSpace(part)
		if part != "" && !strings.HasPrefix(part, "'") && !strings.HasPrefix(part, "?") {
			out = append(out, part)
		}
	}
	return out
}

func addRustSupertype(analysis *FileAnalysis, owner, super string) {
	if analysis == nil || owner == "" || super == "" {
		return
	}
	if analysis.Supertypes == nil {
		analysis.Supertypes = make(map[string][]string)
	}
	for _, s := range analysis.Supertypes[owner] {
		if s == super {
			return
		}
	}
	analysis.Supertypes[owner] = append(analysis.Supertypes[owner], super)
}
