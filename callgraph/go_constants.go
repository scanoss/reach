// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"math"

	sitter "github.com/smacker/go-tree-sitter"
)

const (
	goNodeConstDeclaration = "const_declaration"
	goNodeConstSpec        = "const_spec"
	goNodeSourceFile       = "source_file"
	goNodeArgumentList     = "argument_list"
	goNodeComment          = "comment"
	goNodeRangeClause      = "range_clause"
	goNodeReceiveStatement = "receive_statement"
	goNodeForClause        = "for_clause"
	goNodeLabeledStatement = "labeled_statement"
	goNodeTypeSwitch       = "type_switch_statement"
	goNodeVariadicParam    = "variadic_parameter_declaration"
	goNodeIntLiteral       = "int_literal"
	goNodeInterpretedStr   = "interpreted_string_literal"
	goNodeRawStr           = "raw_string_literal"
)

// goConstTypes are the declared types a typed const may have and still be read
// as a plain integer or string literal. A float or a named type is not.
var goConstTypes = map[string]bool{
	"int": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"uintptr": true, "byte": true, "rune": true, "string": true,
}

type goDeclKind int

const (
	// goDeclOpaque is a declaration of the name that yields no literal and
	// that the value walk does not follow: a const without a literal
	// initializer, a range or receive binding, a receiver, a named result or
	// a function literal's parameter.
	goDeclOpaque goDeclKind = iota
	goDeclLiteral
	// goDeclVar is a `var` or `:=` binding, which the value walk traces to
	// its initializer (goValueWalk).
	goDeclVar
	// goDeclParam is a parameter of a function or method declaration, which
	// a caller's argument fills.
	goDeclParam
)

// goDecl is one declaration of a name inside a scope. end is the byte offset
// from which the declaration is in scope; parameters use 0.
type goDecl struct {
	end   uint32
	kind  goDeclKind
	value string
	// spec is the var_spec, short_var_declaration or parameter declaration
	// that binds a goDeclVar or goDeclParam, and init the expression a
	// goDeclVar is initialized with: nil when it has none, or when several
	// names take the values of one call (tuple).
	spec  *sitter.Node
	init  *sitter.Node
	tuple bool
	// index is a goDeclParam's position among the arguments a call passes.
	index int
}

// goConstScopes indexes, once per scope node, the names each lexical scope
// declares, so resolving an argument costs the scope depth rather than a scan
// of every enclosing scope's statements. Reset it when the tree is closed.
type goConstScopes struct {
	byScope map[uintptr]map[string][]goDecl
	// crossFile resolves a name no scope of the current file declares against
	// the other files of its package. Nil when the file is parsed alone.
	crossFile func(name string) (string, bool)
	// work counts declarations visited while indexing scopes and compared
	// while resolving names; tests bound it to pin near-linear cost.
	work int
}

func (c *goConstScopes) reset() { c.byScope, c.crossFile = nil, nil }

func (c *goConstScopes) index(scope *sitter.Node, src []byte) map[string][]goDecl {
	if c.byScope == nil {
		c.byScope = make(map[uintptr]map[string][]goDecl)
	}
	id := scope.ID()
	if idx, ok := c.byScope[id]; ok {
		return idx
	}
	idx := make(map[string][]goDecl)
	goCollectBoundNames(scope, src, idx)
	for i := 0; i < int(scope.NamedChildCount()); i++ {
		c.work++
		goCollectDecls(scope.NamedChild(i), src, idx)
	}
	c.byScope[id] = idx
	return idx
}

// resolve returns the declaration of the file that name at use denotes, with
// the scope node declaring it; nil when no scope of the file declares name. It
// walks outward through the enclosing scopes; the innermost scope that
// declares name decides, so a shadowed name never inherits an outer const.
func (c *goConstScopes) resolve(use *sitter.Node, name string, src []byte) (*goDecl, *sitter.Node) {
	for child, scope := use, use.Parent(); scope != nil; child, scope = scope, scope.Parent() {
		position := child.StartByte()
		if scope.Type() == goNodeSourceFile {
			position = math.MaxUint32
		}
		var best *goDecl
		decls := c.index(scope, src)[name]
		for i := range decls {
			c.work++
			if decls[i].end <= position && (best == nil || decls[i].end >= best.end) {
				best = &decls[i]
			}
		}
		if best != nil {
			return best, scope
		}
	}
	return nil, nil
}

// goCollectDecls records the names a scope child declares. It looks through the
// clause nodes that hold a binding without opening a scope of their own: the
// init of a for clause, a labeled statement, and a select receive case.
func goCollectDecls(n *sitter.Node, src []byte, idx map[string][]goDecl) {
	switch n.Type() {
	case goNodeConstDeclaration:
		for i := 0; i < int(n.NamedChildCount()); i++ {
			goCollectConstSpec(n.NamedChild(i), src, idx)
		}
	case goNodeVarDeclaration:
		goWalk(n, func(c *sitter.Node) {
			if c.Type() == goNodeVarSpec {
				goAddVarNames(c, goFieldNamed(c, javaFieldName), c.ChildByFieldName("value"), n.EndByte(), src, idx)
			}
		})
	case goNodeShortVarDeclaration:
		goAddVarNames(n, goListItems(n.ChildByFieldName(goFieldLeft)), n.ChildByFieldName(goFieldRight), n.EndByte(), src, idx)
	case goNodeRangeClause:
		goAddIdentifiers(n.ChildByFieldName(goFieldLeft), n.EndByte(), src, idx)
	case goNodeReceiveStatement:
		if goHasToken(n, ":=") {
			goAddIdentifiers(n.ChildByFieldName(goFieldLeft), n.EndByte(), src, idx)
		}
	case goNodeForClause, goNodeLabeledStatement:
		for i := 0; i < int(n.NamedChildCount()); i++ {
			goCollectDecls(n.NamedChild(i), src, idx)
		}
	}
}

func goCollectConstSpec(spec *sitter.Node, src []byte, idx map[string][]goDecl) {
	if spec.Type() != goNodeConstSpec {
		return
	}
	var names []*sitter.Node
	for i := 0; i < int(spec.ChildCount()); i++ {
		if c := spec.Child(i); c.IsNamed() && spec.FieldNameForChild(i) == javaFieldName {
			names = append(names, c)
		}
	}
	values := spec.ChildByFieldName("value")
	typed := spec.ChildByFieldName(goFieldType)
	literal := values != nil && int(values.NamedChildCount()) == len(names) &&
		(typed == nil || goConstTypes[typed.Content(src)])
	for i, name := range names {
		decl := goDecl{end: spec.EndByte(), kind: goDeclOpaque}
		if literal {
			if text, ok := goLiteralText(values.NamedChild(i), src); ok {
				decl.kind, decl.value = goDeclLiteral, text
			}
		}
		idx[name.Content(src)] = append(idx[name.Content(src)], decl)
	}
}

// goLiteralText returns the text of a plain decimal integer or string literal.
// A leading zero, a base prefix or an underscore changes what the digits mean
// downstream, so those give nothing.
func goLiteralText(n *sitter.Node, src []byte) (string, bool) {
	text := n.Content(src)
	switch n.Type() {
	case goNodeIntLiteral:
		if text == "" || (len(text) > 1 && text[0] == '0') {
			return "", false
		}
		for _, r := range text {
			if r < '0' || r > '9' {
				return "", false
			}
		}
		return text, true
	case goNodeInterpretedStr, goNodeRawStr:
		return text, true
	}
	return "", false
}

// goAddVarNames records the names a var spec or a short variable declaration
// binds, each paired with its own initializer when the right side lists one
// value per name.
func goAddVarNames(spec *sitter.Node, names []*sitter.Node, values *sitter.Node, end uint32, src []byte, idx map[string][]goDecl) {
	inits := goListItems(values)
	for i, name := range names {
		if name.Type() != goNodeIdentifier {
			continue
		}
		decl := goDecl{end: end, kind: goDeclVar, spec: spec, tuple: values != nil && len(inits) != len(names)}
		if len(inits) == len(names) {
			decl.init = inits[i]
		}
		idx[name.Content(src)] = append(idx[name.Content(src)], decl)
	}
}

// goFieldNamed returns the named children of n held in field.
func goFieldNamed(n *sitter.Node, field string) []*sitter.Node {
	var out []*sitter.Node
	for i := 0; i < int(n.ChildCount()); i++ {
		if c := n.Child(i); c.IsNamed() && n.FieldNameForChild(i) == field {
			out = append(out, c)
		}
	}
	return out
}

// goListItems returns the expressions of an expression list, comments left
// out; a lone expression is a list of one.
func goListItems(list *sitter.Node) []*sitter.Node {
	if list == nil {
		return nil
	}
	if list.Type() != goNodeExpressionList {
		return []*sitter.Node{list}
	}
	out := make([]*sitter.Node, 0, list.NamedChildCount())
	for i := 0; i < int(list.NamedChildCount()); i++ {
		if c := list.NamedChild(i); c.Type() != goNodeComment {
			out = append(out, c)
		}
	}
	return out
}

func goAddNames(n *sitter.Node, end uint32, src []byte, idx map[string][]goDecl) {
	for i := 0; i < int(n.ChildCount()); i++ {
		if c := n.Child(i); c.IsNamed() && n.FieldNameForChild(i) == javaFieldName {
			idx[c.Content(src)] = append(idx[c.Content(src)], goDecl{end: end, kind: goDeclOpaque})
		}
	}
}

func goAddIdentifiers(list *sitter.Node, end uint32, src []byte, idx map[string][]goDecl) {
	if list == nil {
		return
	}
	if list.Type() == goNodeIdentifier {
		idx[list.Content(src)] = append(idx[list.Content(src)], goDecl{end: end, kind: goDeclOpaque})
		return
	}
	for i := 0; i < int(list.NamedChildCount()); i++ {
		if c := list.NamedChild(i); c.Type() == goNodeIdentifier {
			idx[c.Content(src)] = append(idx[c.Content(src)], goDecl{end: end, kind: goDeclOpaque})
		}
	}
}

func goHasToken(n *sitter.Node, token string) bool {
	for i := 0; i < int(n.ChildCount()); i++ {
		if c := n.Child(i); !c.IsNamed() && c.Type() == token {
			return true
		}
	}
	return false
}

func goWalk(n *sitter.Node, visit func(*sitter.Node)) {
	visit(n)
	for i := 0; i < int(n.NamedChildCount()); i++ {
		goWalk(n.NamedChild(i), visit)
	}
}

// goCollectBoundNames records what a scope node binds itself: the parameters,
// receiver and named results of a function or literal, and a type switch alias.
// They are in scope for the whole body.
func goCollectBoundNames(scope *sitter.Node, src []byte, idx map[string][]goDecl) {
	switch scope.Type() {
	case nodeFunctionDeclaration, javaNodeMethodDeclaration, goNodeFuncLiteral:
		// A declaration's parameters are filled by its callers' arguments; a
		// literal's are filled by whatever calls the func value, so they stay
		// opaque like the receiver and the named results.
		opaque := []string{"receiver", "parameters", "result", "type_parameters"}
		if scope.Type() != goNodeFuncLiteral {
			goAddParameters(scope.ChildByFieldName("parameters"), src, idx)
			opaque = []string{"receiver", "result", "type_parameters"}
		}
		for _, field := range opaque {
			if list := scope.ChildByFieldName(field); list != nil {
				goWalk(list, func(c *sitter.Node) {
					if c.Type() == goNodeParameterDecl || c.Type() == goNodeVariadicParam || c.Type() == "type_parameter_declaration" {
						goAddNames(c, 0, src, idx)
					}
				})
			}
		}
	case goNodeTypeSwitch:
		goAddIdentifiers(scope.ChildByFieldName("alias"), 0, src, idx)
	}
}

// goAddParameters records the parameters of a function or method declaration
// with their position among a call's arguments; a method's receiver is not
// one. A variadic parameter receives a slice of the trailing arguments, not
// one of them, so it is recorded as opaque.
func goAddParameters(list *sitter.Node, src []byte, idx map[string][]goDecl) {
	if list == nil {
		return
	}
	index := 0
	for i := 0; i < int(list.NamedChildCount()); i++ {
		param := list.NamedChild(i)
		switch param.Type() {
		case goNodeParameterDecl:
			names := goFieldNamed(param, javaFieldName)
			if len(names) == 0 {
				index++
				continue
			}
			for _, name := range names {
				idx[name.Content(src)] = append(idx[name.Content(src)], goDecl{kind: goDeclParam, spec: param, index: index})
				index++
			}
		case goNodeVariadicParam:
			goAddNames(param, 0, src, idx)
			index++
		}
	}
}
