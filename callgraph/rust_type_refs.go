// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"
	"unicode"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	rustNodeTypeIdentifier       = "type_identifier"
	rustNodeScopedTypeIdentifier = "scoped_type_identifier"
)

// rustTypeRefParents are the positions where a path is a whole type, by
// parent with the field it stands in ("" for any child): a struct, tuple
// struct, union or variant field, a parameter, a return type (of a fn, a
// trait or extern fn, a closure, a fn pointer), a let annotation, a cast's
// target, a type alias, an impl's self type, a const or static item's type,
// a generic argument (turbofish and `Item = T` included), the referent of a
// reference or pointer, a tuple or array element, a `dyn` or `impl` trait,
// and a generic parameter's default. OpenGrep 1.33.1 matches a path pattern
// in each. A generic type's head (`Key<u8>`), a trait bound, an impl's
// trait, the left side of a where predicate, a qualified path, a struct
// pattern and a declared name are not among them, and it matches none.
var rustTypeRefParents = map[string]string{
	"field_declaration":              "type",
	"ordered_field_declaration_list": "type",
	rustNodeFunctionItem:             "return_type",
	"function_signature_item":        "return_type",
	rustNodeClosureExpression:        "return_type",
	"function_type":                  "return_type",
	"parameter":                      "type",
	"parameters":                     "",
	"reference_type":                 "type",
	"pointer_type":                   "type",
	"type_arguments":                 "",
	"type_binding":                   "type",
	rustNodeLetDeclaration:           "type",
	"type_cast_expression":           "type",
	"type_item":                      "type",
	rustNodeImplItem:                 "type",
	rustNodeConstItem:                "type",
	rustNodeStaticItem:               "type",
	"tuple_type":                     "",
	"array_type":                     "element",
	"dynamic_type":                   "trait",
	"abstract_type":                  "trait",
	"bounded_type":                   "",
	"optional_type_parameter":        "default_type",
}

// rustTraitPositions are the ancestors that put a type inside a trait bound
// or a qualified path, where OpenGrep matches no generic argument either:
// `R: Into<SysRng>`, `<X as Tr<SysRng>>::Out`.
var rustTraitPositions = map[string]bool{
	"trait_bounds":              true,
	"where_predicate":           true,
	"qualified_type":            true,
	"bracketed_type":            true,
	"removed_trait_bound":       true,
	"higher_ranked_trait_bound": true,
}

// rustIsTypeRef reports whether a type_identifier or scoped_type_identifier
// is a path written as a whole type in a type position (rustTypeRefParents),
// outside any trait bound or qualified path. A one-segment name is one when
// it starts with an upper-case letter and is neither a std prelude type
// (rustPreludeTypes) nor Self; a longer path when it is a plain path
// (`acme::Key`, not `<X as T>::Out`). A type in an expression macro's
// arguments, which the body walk parses again, is one too, though OpenGrep
// does not parse those arguments.
func rustIsTypeRef(node *sitter.Node, src []byte) bool {
	parent := node.Parent()
	if parent == nil {
		return false
	}
	field, ok := rustTypeRefParents[parent.Type()]
	if !ok || (field != "" && !sameSyntaxNode(parent.ChildByFieldName(field), node)) {
		return false
	}
	name := node.Content(src)
	if node.Type() == rustNodeTypeIdentifier {
		if name == "" || !unicode.IsUpper([]rune(name)[0]) || rustPreludeTypes[name] || name == "Self" {
			return false
		}
	} else if strings.ContainsAny(name, "<>") {
		return false
	}
	for n, p := node, parent; p != nil; n, p = p, p.Parent() {
		if rustTraitPositions[p.Type()] {
			return false
		}
		if p.Type() == rustNodeImplItem {
			return !sameSyntaxNode(p.ChildByFieldName("trait"), n)
		}
		if _, ok := rustTypeRefParents[p.Type()]; !ok && p.Type() != "generic_type" {
			return true
		}
	}
	return true
}

// collectRustItemTypeRefs records the type references written outside
// function bodies (a body's own are the body walk's): a fn's signature (its
// parameters, return type and generic defaults) in that fn's references, and
// every other one (a struct or enum field, a type alias, an impl's self
// type, a const or static item's type, a trait or extern fn's signature) in
// the file's <varinit>, which appendRustVarinit then creates for them. It
// skips what the declaration walk skips: a test-only inline module in a scan
// without tests, macros, attributes and use declarations, and a const or
// static item's initializer, which collectRustItemInit walks.
func (p *RustParser) collectRustItemTypeRefs(root *sitter.Node, src []byte, analysis *FileAnalysis) {
	byStart := make(map[[2]int]int, len(analysis.Functions))
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		byStart[[2]int{fn.StartLine, fn.StartCol}] = i
	}
	var walk func(node *sitter.Node, facts *rustBodyFacts)
	walk = func(node *sitter.Node, facts *rustBodyFacts) {
		switch node.Type() {
		case rustNodeModItem:
			if !p.includeTests && rustModuleIsTestOnly(node, src) {
				return
			}
		case rustNodeUseDeclaration, rustNodeExternCrate, rustNodeAttributeItem, "macro_invocation", "macro_definition":
			return
		case rustNodeConstItem, rustNodeStaticItem:
			if t := node.ChildByFieldName("type"); t != nil {
				walk(t, facts)
			}
			return
		case rustNodeFunctionItem:
			line, col, _, _ := rustSpan(node)
			if i, ok := byStart[[2]int{line, col}]; ok {
				var sig rustBodyFacts
				p.walkRustSignature(node, src, &sig, walk)
				fn := &analysis.Functions[i]
				fn.ConstantRefs = append(fn.ConstantRefs, sig.refs...)
				sortConstantRefs(fn.ConstantRefs)
				return
			}
			p.walkRustSignature(node, src, facts, walk)
			return
		case rustNodeTypeIdentifier, rustNodeScopedTypeIdentifier:
			if rustIsTypeRef(node, src) {
				facts.addRef(node, src, ConstantRefType)
			}
			return
		}
		for i := 0; i < int(node.NamedChildCount()); i++ {
			walk(node.NamedChild(i), facts)
		}
	}
	walk(root, &p.itemInit)
}

// walkRustSignature walks every child of a fn item but its body.
func (p *RustParser) walkRustSignature(node *sitter.Node, src []byte, facts *rustBodyFacts, walk func(*sitter.Node, *rustBodyFacts)) {
	body := node.ChildByFieldName("body")
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if child := node.NamedChild(i); !sameSyntaxNode(child, body) {
			walk(child, facts)
		}
	}
}
