// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// The value sources of a C# call's arguments: where the value an argument
// writes as a name comes from. A rule that selects on an algorithm name
// reads a constant the caller wrote once and passed by name, which the
// reference matcher propagates.

// csharpValues tracks the constant a name holds in one body: a local
// declared or assigned a literal, and the fields of the enclosing type. A
// name written more than once with different values holds none.
type csharpValues struct {
	// locals is the literal each local was last declared or assigned, and
	// writes how many times each was written.
	locals map[string]string
	writes map[string]int
	// types is the type each local and parameter is declared with, the
	// evidence an overload a rule selects on by argument type needs.
	types map[string]string
	// fields holds the literal and the declared type of each field of the
	// enclosing type.
	fields     map[string]string
	fieldTypes map[string]string
}

func newCSharpValues(fields, fieldTypes map[string]string) *csharpValues {
	return &csharpValues{
		locals: map[string]string{}, writes: map[string]int{}, types: map[string]string{},
		fields: fields, fieldTypes: fieldTypes,
	}
}

// clone keeps the facts of an enclosing scope while a nested one adds its own.
func (v *csharpValues) clone() *csharpValues {
	out := newCSharpValues(v.fields, v.fieldTypes)
	for name, value := range v.locals {
		out.locals[name] = value
	}
	for name, count := range v.writes {
		out.writes[name] = count
	}
	for name, typeName := range v.types {
		out.types[name] = typeName
	}
	return out
}

// declare records the type a parameter or a local is declared with.
func (v *csharpValues) declare(name, typeName string) {
	if name != "" && typeName != "" {
		v.types[name] = typeName
	}
}

// typeOf is the type a name is declared with: a local or parameter of the
// body, else a field of the enclosing type.
func (v *csharpValues) typeOf(name string) string {
	if typeName, ok := v.types[name]; ok {
		return typeName
	}
	return v.fieldTypes[name]
}

// countWrites counts, over the whole body, how many times each name is
// declared or assigned: a name written twice holds no single constant, and
// the walk that binds values reaches its second write only later.
func (v *csharpValues) countWrites(body *sitter.Node, src []byte) {
	csharpWalk(body, func(node *sitter.Node) {
		for _, name := range csharpWrittenNames(node, src) {
			v.writes[name]++
		}
	})
}

// csharpWrittenNames are the names a declaration or an assignment writes.
func csharpWrittenNames(node *sitter.Node, src []byte) []string {
	switch node.Type() {
	case csharpNodeLocalDeclaration, csharpNodeUsingStatement:
		declaration := csharpChildByType(node, csharpNodeVariableDeclaration)
		if declaration == nil {
			return nil
		}
		var names []string
		for i := 0; i < int(declaration.NamedChildCount()); i++ {
			declarator := declaration.NamedChild(i)
			if declarator.Type() != csharpNodeVariableDeclarator {
				continue
			}
			if name := declarator.ChildByFieldName("name"); name != nil {
				names = append(names, name.Content(src))
			}
		}
		return names
	case csharpNodeAssignment:
		if left := node.ChildByFieldName("left"); left != nil && left.Type() == csharpNodeIdentifier {
			return []string{left.Content(src)}
		}
	}
	return nil
}

// record reads the literals a declaration or an assignment binds.
func (v *csharpValues) record(node *sitter.Node, src []byte) {
	switch node.Type() {
	case csharpNodeLocalDeclaration, csharpNodeUsingStatement:
		declaration := csharpChildByType(node, csharpNodeVariableDeclaration)
		if declaration == nil {
			return
		}
		declared := ""
		if typeNode := declaration.ChildByFieldName("type"); typeNode != nil && typeNode.Type() != csharpNodeImplicitType {
			declared = csharpTypeName(typeNode, src)
		}
		for i := 0; i < int(declaration.NamedChildCount()); i++ {
			declarator := declaration.NamedChild(i)
			if declarator.Type() != csharpNodeVariableDeclarator {
				continue
			}
			name := declarator.ChildByFieldName("name")
			if name == nil {
				continue
			}
			value, ok := csharpLiteralValue(declarator, src)
			v.write(name.Content(src), value, ok)
			v.declare(name.Content(src), declared)
		}
	case csharpNodeAssignment:
		left, right := node.ChildByFieldName("left"), node.ChildByFieldName("right")
		if left == nil || right == nil || left.Type() != csharpNodeIdentifier {
			return
		}
		value, ok := csharpLiteralText(right, src)
		v.write(left.Content(src), value, ok)
	}
}

func (v *csharpValues) write(name, value string, literal bool) {
	if literal {
		v.locals[name] = value
		return
	}
	delete(v.locals, name)
}

// valueOf is the constant a name holds at a use: a local written once with a
// literal, else a field of the enclosing type. A local written more than once
// holds no single value.
func (v *csharpValues) valueOf(name string) (string, bool) {
	if value, ok := v.locals[name]; ok && v.writes[name] == 1 {
		return value, true
	}
	if _, written := v.writes[name]; written {
		return "", false
	}
	value, ok := v.fields[name]
	return value, ok
}

// csharpLiteralValue is the literal a declarator initializes its name with.
func csharpLiteralValue(declarator *sitter.Node, src []byte) (string, bool) {
	for i := 0; i < int(declarator.NamedChildCount()); i++ {
		child := declarator.NamedChild(i)
		if sameSyntaxNode(child, declarator.ChildByFieldName("name")) {
			continue
		}
		return csharpLiteralText(child, src)
	}
	return "", false
}

// csharpLiteralText is the text of a literal expression, "" for anything else.
func csharpLiteralText(node *sitter.Node, src []byte) (string, bool) {
	switch node.Type() {
	case csharpNodeStringLiteral, csharpNodeVerbatimString, "boolean_literal", "integer_literal", "real_literal", "character_literal":
		return node.Content(src), true
	}
	return "", false
}

// csharpArgumentSources traces each argument of a call to the constant it
// holds: a name the body bound to a literal, or a field of the enclosing type.
// An argument that is already a literal, or whose value nothing settles, has
// no source.
func csharpArgumentSources(arguments []string, values *csharpValues, filePath string, line int) [][]SourceNode {
	if values == nil || len(arguments) == 0 {
		return nil
	}
	sources := make([][]SourceNode, len(arguments))
	any := false
	for i, argument := range arguments {
		name := strings.TrimSpace(argument)
		if name == "" || !csharpIsName(name) {
			continue
		}
		value, valued := values.valueOf(name)
		declared := values.typeOf(name)
		if !valued && declared == "" {
			continue
		}
		kind := sourceNodeVariable
		if _, local := values.writes[name]; !local {
			if _, parameter := values.types[name]; !parameter {
				kind = sourceNodeField
			}
		}
		node := SourceNode{
			Type: kind, Name: name, DeclaredType: declared,
			Location: &SourceLocation{FilePath: filePath, Line: line},
		}
		if valued {
			node.SourceNodes = []SourceNode{{Type: sourceNodeValue, Value: value}}
		}
		sources[i] = []SourceNode{node}
		any = true
	}
	if !any {
		return nil
	}
	return sources
}

// csharpIsName reports a bare identifier, the only argument shape a constant
// is followed through.
func csharpIsName(text string) bool {
	for i, r := range text {
		switch {
		case r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return text != ""
}

// csharpFields holds what a type's fields declare, by the name a method of
// that type writes them with: their literal value and their declared type.
type csharpFields struct {
	values, types map[string]string
}

func (f *csharpFields) literals() map[string]string {
	if f == nil {
		return nil
	}
	return f.values
}

func (f *csharpFields) declaredTypes() map[string]string {
	if f == nil {
		return nil
	}
	return f.types
}

// csharpFieldFacts reads the fields a type declares.
func csharpFieldFacts(node *sitter.Node, src []byte) *csharpFields {
	body := node.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	out := &csharpFields{values: map[string]string{}, types: map[string]string{}}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		field := body.NamedChild(i)
		if field.Type() != csharpNodeFieldDeclaration {
			continue
		}
		declaration := csharpChildByType(field, csharpNodeVariableDeclaration)
		if declaration == nil {
			continue
		}
		declared := ""
		if typeNode := declaration.ChildByFieldName("type"); typeNode != nil && typeNode.Type() != csharpNodeImplicitType {
			declared = csharpTypeName(typeNode, src)
		}
		for j := 0; j < int(declaration.NamedChildCount()); j++ {
			declarator := declaration.NamedChild(j)
			if declarator.Type() != csharpNodeVariableDeclarator {
				continue
			}
			name := declarator.ChildByFieldName("name")
			if name == nil {
				continue
			}
			if value, ok := csharpLiteralValue(declarator, src); ok {
				out.values[name.Content(src)] = value
			}
			if declared != "" {
				out.types[name.Content(src)] = declared
			}
		}
	}
	if len(out.values) == 0 && len(out.types) == 0 {
		return nil
	}
	return out
}
