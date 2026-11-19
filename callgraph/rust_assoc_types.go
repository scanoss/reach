// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// rust_assoc_types.go resolves a call through a qualified associated type,
// `<Type as Trait>::Assoc::f(..)`, to f on the type the associated type names:
// first through the crate's own `impl Trait for Type { type Assoc = T; }`
// items, then through the knowledge base's trait_associated_types, which
// catalog a dependency's trait (ml-kem's `KemCore::EncapsulationKey`). A call
// neither resolves keeps the key it had.

// rustAssocType is the type an impl's associated type item names, as written,
// and the module of the impl that wrote it.
type rustAssocType struct {
	text   string
	module string
}

// rustAssocTypeKey keys an associated type item by the impl's self type, its
// trait and the item's name, all bare.
func rustAssocTypeKey(self, trait, name string) string {
	return self + "|" + trait + "|" + name
}

// recordAssocTypes records the associated type items of an `impl Trait for
// Type` block.
func (f *rustFileFacts) recordAssocTypes(node *sitter.Node, src []byte, selfType, modulePath string) {
	traitNode := node.ChildByFieldName("trait")
	body := node.ChildByFieldName("body")
	if traitNode == nil || body == nil || selfType == "" {
		return
	}
	trait := rustTypeHead(stripRustGenericArgs(rustScopedTypeText(traitNode, src)))
	if trait == "" {
		return
	}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		item := body.NamedChild(i)
		if item.Type() != rustNodeTypeItem {
			continue
		}
		name := nodeFieldText(item, "name", src)
		typeNode := item.ChildByFieldName("type")
		if name == "" || typeNode == nil {
			continue
		}
		f.addAssocType(rustAssocTypeKey(selfType, trait, name), rustAssocType{text: typeNode.Content(src), module: modulePath})
	}
}

// addAssocType records one associated type, dropping a key two impls answer
// differently.
func (f *rustFileFacts) addAssocType(key string, value rustAssocType) {
	if f.conflicting["assoc:"+key] {
		return
	}
	if existing, seen := f.assocTypes[key]; seen && existing != value {
		delete(f.assocTypes, key)
		f.conflicting["assoc:"+key] = true
		return
	}
	f.assocTypes[key] = value
}

func (f *rustFileFacts) mergeAssocTypes(other *rustFileFacts) {
	for key, value := range other.assocTypes {
		f.addAssocType(key, value)
	}
}

// qualifyAssocTypes qualifies each associated type: a bare name the file
// declares itself with the module of the impl (an item of the module shadows
// any import), anything else with the imports of the file that declared it.
func (f *rustFileFacts) qualifyAssocTypes(staging *FileAnalysis) {
	for key, value := range f.assocTypes {
		text := value.text
		head := rustTypeHead(text)
		if head != "" && f.localTypes[head] && value.module != "" && !strings.Contains(rustStripLifetimes(text), "::") {
			text = rustReplaceTypeHead(text, head, value.module+"::"+head)
		} else {
			text = rustQualifyFactType(staging, text)
		}
		f.assocTypes[key] = rustAssocType{text: text, module: value.module}
	}
}

// assocType returns the qualified type an associated type item names, from
// the crate index: a file's own facts are not qualified.
func (f *rustFileFacts) assocType(self, trait, name string) (string, bool) {
	if f == nil {
		return "", false
	}
	index := f.fallback
	if index == nil {
		return "", false
	}
	value, ok := index.assocTypes[rustAssocTypeKey(self, trait, name)]
	if !ok || value.text == "" {
		return "", false
	}
	return value.text, true
}

// rustQualifiedAssocPath splits the callee path of `<Type as Trait>::Assoc::f`
// into its type, its trait and Assoc. ok is false for any other shape.
func rustQualifiedAssocPath(funcNode *sitter.Node) (typeNode, traitNode *sitter.Node, assoc *sitter.Node, ok bool) {
	if funcNode == nil || funcNode.Symbol() != rustSyms.scopedIdentifier {
		return nil, nil, nil, false
	}
	path := funcNode.ChildByFieldName("path")
	if path == nil || path.Symbol() != rustSyms.scopedIdentifier {
		return nil, nil, nil, false
	}
	bracketed := path.ChildByFieldName("path")
	assoc = path.ChildByFieldName("name")
	if bracketed == nil || assoc == nil || bracketed.Type() != "bracketed_type" {
		return nil, nil, nil, false
	}
	qualified := rustInnerExpression(bracketed)
	if qualified == nil || qualified.Type() != "qualified_type" {
		return nil, nil, nil, false
	}
	typeNode = qualified.ChildByFieldName("type")
	traitNode = qualified.ChildByFieldName("alias")
	if typeNode == nil || traitNode == nil {
		return nil, nil, nil, false
	}
	return typeNode, traitNode, assoc, true
}

// parseQualifiedAssocCall keys `<Type as Trait>::Assoc::f(..)` as f on the
// type Assoc names for Type: the crate's own impl first, then the knowledge
// base's catalog of the trait. It returns nil when neither names one.
func (p *RustParser) parseQualifiedAssocCall(funcNode *sitter.Node, ctx *rustTypeCtx, filePath string, line int, args []string) *FunctionCall {
	typeNode, traitNode, assocNode, ok := rustQualifiedAssocPath(funcNode)
	if !ok {
		return nil
	}
	src, analysis := ctx.src, ctx.analysis
	name := nodeFieldText(funcNode, "name", src)
	assoc := assocNode.Content(src)
	trait := rustTypeHead(stripRustGenericArgs(rustScopedTypeText(traitNode, src)))
	if name == "" || assoc == "" || trait == "" {
		return nil
	}
	resolved := ""
	if _, self := rustQualifyType(analysis, analysis.rustFacts, ctx.rustSubstituteGeneric(rustScopedTypeText(typeNode, src))); self != "" {
		if text, found := analysis.rustFacts.assocType(rustTypeHead(self), trait, assoc); found {
			resolved = text
		}
	}
	if resolved == "" && p.kb != nil {
		if text, cataloged := p.kb.TraitAssociatedType(trait, assoc); cataloged {
			resolved = text
		}
	}
	if resolved == "" {
		return nil
	}
	pkg, typ := rustQualifyType(analysis, analysis.rustFacts, resolved)
	if pkg == "" || typ == "" {
		return nil
	}
	return &FunctionCall{
		Callee:    FunctionID{Package: pkg, Type: typ, Name: name},
		Raw:       stripRustTypeArguments(funcNode.Content(src)),
		FilePath:  filePath,
		Line:      line,
		Arguments: args,
	}
}
