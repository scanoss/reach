// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// node_value_shapes.go follows a value through the source of one package: what
// an expression evaluates to, what a member of it is, what calling it returns
// and what constructing it builds. NodeShapes.Definition follows a member path
// below an export; this follows the calls and constructions along the way
// too, so that `pkg.client().getKey` and `new pkg.Totp().validate` name the
// functions they run:
//
//	exports.client = function () { return { getKey(n) {..} }; };   // client, called, member getKey
//	class Totp { validate(d) {..} }                                 // Totp, constructed, member validate
//	const i = new Pure(); exports.finalize = i.finalize;            // finalize is Pure's method
//	exports.vverify = require('./vs').verify;                       // vverify is vs's verify
//
// A value is a node of the source: an object literal, a function, a class, a
// method, an instance of a class or constructor function, or the exports of a
// module. An expression that may evaluate to several (two returns, `a || b`)
// yields them all. Whatever is only decided at run time, such as a parameter,
// a property of an unknown object or a value from another package, yields
// nothing: a path through it resolves to no function.

const (
	// nodeValueBudget bounds the expressions one question follows.
	nodeValueBudget = 4096
	// nodeValueFanout bounds the values one expression yields.
	nodeValueFanout = 32
)

// nodeShapeValue is one value the source builds.
type nodeShapeValue struct {
	m *nodeShapeModule
	n *sitter.Node
	// instance marks an instance of the class or constructor function n.
	instance bool
	// module marks the exports of module m; n is its program node.
	module bool
	// external is a value of another package, spelled as the steps from its
	// import (node_value_access.go); m and n are nil.
	external *nodeValueAccess
	// passed marks a function a caller passed as an argument, read from the
	// parameter that received it: the caller already reaches it for handing
	// it over (nodeValueFlow.handOver), so calling it draws no second edge
	// from a callee that every other caller shares.
	passed bool
}

func (v nodeShapeValue) same(o nodeShapeValue) bool {
	if v.external != nil || o.external != nil {
		if v.external == nil || o.external == nil || v.external.module != o.external.module || len(v.external.steps) != len(o.external.steps) {
			return false
		}
		for i := range v.external.steps {
			if v.external.steps[i] != o.external.steps[i] {
				return false
			}
		}
		return true
	}
	return v.m == o.m && v.instance == o.instance && v.module == o.module && sameSyntaxNode(v.n, o.n)
}

// callable reports a function, class or method the source writes.
func (v nodeShapeValue) callable() bool {
	return v.external == nil && !v.instance && !v.module && (nodeIsFunction(v.n) || v.n.Type() == nodeMethodDefinition || v.n.Type() == nodeGeneratorDeclaration || v.n.Type() == nodeGeneratorFunction)
}

// class reports a class.
func (v nodeShapeValue) class() bool {
	return v.external == nil && !v.module && (v.n.Type() == nodeClassDeclaration || v.n.Type() == nodeClassExpression || v.n.Type() == nodeAbstractClassDeclaration)
}

// object reports an object literal.
func (v nodeShapeValue) object() bool {
	return v.external == nil && !v.instance && !v.module && v.n.Type() == nodeObjectLiteral
}

// nodeExternalValue is the value of the module spec names when it is not a
// file of the package: another package's, or one the runtime provides.
func nodeExternalValue(spec string) []nodeShapeValue {
	spec = strings.TrimSpace(spec)
	if spec == "" || isNodeRelativeSpecifier(spec) || strings.HasPrefix(spec, "/") {
		return nil
	}
	runtime := strings.HasPrefix(spec, "node:") || nodeBuiltinModules[spec]
	return []nodeShapeValue{{external: &nodeValueAccess{module: spec, runtime: runtime}}}
}

// step is the external value v followed by one step of its access.
func (v nodeShapeValue) step(step nodeAccessStep) []nodeShapeValue {
	next := v.external.then(step)
	if next == nil {
		return nil
	}
	return []nodeShapeValue{{external: next}}
}

// nodeValueQuery is one question asked of the shapes, with the budget that
// bounds it.
type nodeValueQuery struct {
	s      *NodeShapes
	budget int
	// active holds the parameters the question is reading; see enter
	// (node_value_params.go).
	active map[nodeParamKey]bool
	// cut is set when the question ran out of budget.
	cut bool
}

func (s *NodeShapes) query() *nodeValueQuery {
	return &nodeValueQuery{s: s, budget: nodeValueBudget}
}

func (q *nodeValueQuery) spend() bool {
	q.budget--
	if q.budget < 0 {
		q.cut = true
	}
	return q.budget >= 0
}

func appendNodeValues(out []nodeShapeValue, values ...nodeShapeValue) []nodeShapeValue {
	for _, v := range values {
		if (v.external == nil && (v.n == nil || v.m == nil)) || len(out) >= nodeValueFanout {
			continue
		}
		seen := false
		for i := range out {
			if out[i].same(v) {
				seen = true
				break
			}
		}
		if !seen {
			out = append(out, v)
		}
	}
	return out
}

// moduleValues is what loading a module yields: the value it assigns to
// module.exports or exports by default, and its named exports.
func (q *nodeValueQuery) moduleValues(m *nodeShapeModule, depth int) []nodeShapeValue {
	if m == nil {
		return nil
	}
	out := []nodeShapeValue{{m: m, n: m.root, module: true}}
	if value, vm := q.s.exportValue(m, nodeDefaultExport, depth); value != nil {
		out = appendNodeValues(out, q.values(vm, value, depth+1)...)
	}
	return out
}

// values is what the expression n of module m evaluates to.
func (q *nodeValueQuery) values(m *nodeShapeModule, n *sitter.Node, depth int) []nodeShapeValue {
	n = nodeUnwrapValue(n)
	if n == nil || m == nil || depth > nodeShapeDepth || !q.spend() {
		return nil
	}
	switch n.Type() {
	case nodeObjectLiteral, nodeClassDeclaration, nodeClassExpression, nodeAbstractClassDeclaration, nodeFunctionDeclaration,
		nodeFunctionExpression, nodeArrowFunction, nodeGeneratorDeclaration, nodeGeneratorFunction, nodeMethodDefinition:
		return []nodeShapeValue{{m: m, n: n}}
	case goNodeIdentifier, nodeShorthandProperty:
		return q.nameValues(m, n, depth)
	case nodeNewExpression:
		return nodeInstancesOf(q.values(m, n.ChildByFieldName("constructor"), depth+1))
	case nodeCallExpression:
		return q.callValues(m, n, depth)
	case nodeMemberExpression, nodeSubscriptExpression:
		object, name, ok := nodeReadMember(n, m.src)
		if !ok {
			if n.Type() == nodeSubscriptExpression {
				return q.elementValues(m, n, depth)
			}
			return nil
		}
		if n.Content(m.src) == nodeModuleExportsTarget {
			return q.moduleValues(m, depth+1)
		}
		var out []nodeShapeValue
		for _, o := range q.values(m, object, depth+1) {
			out = appendNodeValues(out, q.member(o, strings.TrimPrefix(name, "#"), depth+1)...)
		}
		return out
	case nodeThisNode:
		return q.thisValues(m, n, depth)
	case "ternary_expression":
		out := q.values(m, n.ChildByFieldName("consequence"), depth+1)
		return appendNodeValues(out, q.values(m, n.ChildByFieldName("alternative"), depth+1)...)
	case "binary_expression":
		op := n.ChildByFieldName("operator")
		if op == nil || (op.Type() != "||" && op.Type() != "??" && op.Type() != "&&") {
			return nil
		}
		var out []nodeShapeValue
		if op.Type() != "&&" {
			out = q.values(m, n.ChildByFieldName("left"), depth+1)
		}
		return appendNodeValues(out, q.values(m, n.ChildByFieldName("right"), depth+1)...)
	case nodeAssignmentExpression:
		return q.values(m, n.ChildByFieldName("right"), depth+1)
	case nodePair:
		return q.values(m, n.ChildByFieldName("value"), depth+1)
	case "as_expression", "satisfies_expression", "non_null_expression":
		if n.NamedChildCount() > 0 {
			return q.values(m, n.NamedChild(0), depth+1)
		}
	}
	return nil
}

// nameValues is what a name read at n holds: what the declaration that
// binds it in an enclosing scope or at the module's top level initialises it
// with, the export of the relative module it is imported from, or the value
// of the package it is imported from. A parameter, a loop variable and a
// name declared without a value hold nothing known.
func (q *nodeValueQuery) nameValues(m *nodeShapeModule, n *sitter.Node, depth int) []nodeShapeValue {
	name := n.Content(m.src)
	for scope := n.Parent(); scope != nil; scope = scope.Parent() {
		switch scope.Type() {
		case nodeFunctionDeclaration, nodeFunctionExpression, nodeArrowFunction, nodeMethodDefinition, nodeGeneratorDeclaration, nodeGeneratorFunction:
			if m.parameters(scope)[name] {
				if m.assignments().aliases[name] {
					// The parameter an IIFE receives module.exports as.
					return []nodeShapeValue{{m: m, n: m.root, module: true}}
				}
				return q.parameterValues(m, scope, name)
			}
			if own := scope.ChildByFieldName(nodeFieldName); own != nil && scope.Type() == nodeFunctionExpression && own.Content(m.src) == name {
				return []nodeShapeValue{{m: m, n: scope}}
			}
		case "catch_clause", nodeForInStatement:
			bound := make(map[string]bool)
			collectNodePatternNames(scope.ChildByFieldName("parameter"), m.src, bound)
			collectNodePatternNames(scope.ChildByFieldName("left"), m.src, bound)
			if bound[name] {
				return nil
			}
		case nodeStatementBlock, nodeProgram:
			if decl, ok := m.declarations(scope)[name]; ok {
				return q.declared(m, scope, decl, n, depth)
			}
		}
	}
	imp, ok := m.imports()[name]
	if !ok {
		if name == nodeCommonJSExportsObject || m.assignments().aliases[name] {
			// The CommonJS exports object, or a name the module binds to it.
			return []nodeShapeValue{{m: m, n: m.root, module: true}}
		}
		return nil
	}
	target := q.s.local(m, imp.spec)
	if target == nil {
		out := nodeExternalValue(imp.spec)
		if len(out) > 0 && imp.name != "" && imp.name != nodeDefaultExport {
			return out[0].step(nodeAccessStep{name: imp.name})
		}
		return out
	}
	switch imp.name {
	case "":
		return []nodeShapeValue{{m: target, n: target.root, module: true}}
	case nodeDefaultExport:
		return q.moduleValues(target, depth+1)
	}
	return q.moduleMember(nodeShapeValue{m: target, n: target.root, module: true}, imp.name, depth+1)
}

// parameters lists the names the parameters of a function bind, destructured
// ones included.
func (m *nodeShapeModule) parameters(fn *sitter.Node) map[string]bool {
	if found, ok := m.params[fn.StartByte()]; ok {
		return found
	}
	found := make(map[string]bool)
	if single := fn.ChildByFieldName("parameter"); single != nil {
		collectNodePatternNames(single, m.src, found)
	}
	if params := fn.ChildByFieldName("parameters"); params != nil {
		nodeEachNamedChild(params, func(param *sitter.Node) {
			if param.Type() == nodeRequiredParameter || param.Type() == nodeOptionalParameter {
				param = param.ChildByFieldName("pattern")
			}
			collectNodePatternNames(param, m.src, found)
		})
	}
	if m.params == nil {
		m.params = make(map[uint32]map[string]bool)
	}
	m.params[fn.StartByte()] = found
	return found
}

// nodeScopedName is a name as one scope declares it: the block or program
// that holds the declaration, by where it starts.
type nodeScopedName struct {
	scope uint32
	name  string
}

// reassigned reports whether the module assigns the name the scope declares
// outside its declaration: `x = v`, `x += v`, `x++`, resolved from where the
// assignment is written, so the `i` of one function's loop is not the `i`
// another scope declares. A `let` or `var` assigned again holds its
// initialiser only until then, so what it holds is not known.
func (m *nodeShapeModule) reassigned(scope *sitter.Node, name string) bool {
	_, ok := m.assignedValues(scope, name)
	return ok
}

// assignedValues lists the values the module assigns to the name the scope
// declares, outside its declaration; ok is false for a name never assigned
// again. A nil entry is an assignment whose value is not an expression to
// read: `x += v`, `x++`, a destructuring.
func (m *nodeShapeModule) assignedValues(scope *sitter.Node, name string) ([]*sitter.Node, bool) {
	if m.rebound == nil {
		m.rebound = make(map[nodeScopedName][]*sitter.Node)
		m.walk(func(n *sitter.Node) {
			var target *sitter.Node
			switch n.Type() {
			case nodeAssignmentExpression, "augmented_assignment_expression":
				target = n.ChildByFieldName("left")
			case "update_expression":
				target = n.ChildByFieldName("argument")
			}
			if target == nil {
				return
			}
			names := make(map[string]bool)
			var value *sitter.Node
			switch target.Type() {
			case goNodeIdentifier:
				names[target.Content(m.src)] = true
				if n.Type() == nodeAssignmentExpression {
					value = n.ChildByFieldName("right")
				}
			case nodeObjectPattern, "array_pattern":
				collectNodePatternNames(target, m.src, names)
			}
			for assigned := range names {
				if declaring := m.declaringScope(n, assigned); declaring != nil {
					key := nodeScopedName{declaring.StartByte(), assigned}
					m.rebound[key] = append(m.rebound[key], value)
				}
			}
		})
	}
	values, ok := m.rebound[nodeScopedName{scope.StartByte(), name}]
	return values, ok
}

// declaringScope is the block or program whose declaration a use of name at
// n reads, nil for a parameter or a name no scope of the module declares.
func (m *nodeShapeModule) declaringScope(n *sitter.Node, name string) *sitter.Node {
	for scope := n.Parent(); scope != nil; scope = scope.Parent() {
		switch scope.Type() {
		case nodeFunctionDeclaration, nodeFunctionExpression, nodeArrowFunction, nodeMethodDefinition, nodeGeneratorDeclaration, nodeGeneratorFunction:
			if m.parameters(scope)[name] {
				return nil
			}
		case nodeStatementBlock, nodeProgram:
			if _, ok := m.declarations(scope)[name]; ok {
				return scope
			}
		}
	}
	return nil
}

// nodeIsNothing reports `null` and `undefined`: a variable set to one holds
// no value a call could be made on.
func nodeIsNothing(n *sitter.Node) bool {
	return n.Type() == nodeLiteralNull || n.Type() == "undefined"
}

// nodeAssignedLater reports whether the read at use cannot see the value an
// assignment gives: the read is part of the assigned expression (`method =
// wrap(method)` reads the value from before), or the assignment is written
// after it in the same function.
func nodeAssignedLater(value, use *sitter.Node) bool {
	if use == nil {
		return false
	}
	if value.StartByte() <= use.StartByte() && use.EndByte() <= value.EndByte() {
		return true
	}
	return value.StartByte() > use.StartByte() && sameSyntaxNode(nodeEnclosingFunction(value), nodeEnclosingFunction(use))
}

// nodeAssignmentFanout bounds the assignments one variable's value is read
// from.
const nodeAssignmentFanout = 4

// declared is the value a declaration gives its name: its initialiser, or
// the member of it a destructuring pattern reads. A `let` or `var` that is
// assigned again (`let mailer; .. mailer = new Mailer()`) holds any of the
// values it is given, when each one is known; one unknown value, or an
// exported `let`, and what it holds is not known.
func (q *nodeValueQuery) declared(m *nodeShapeModule, scope *sitter.Node, decl nodeShapeDecl, use *sitter.Node, depth int) []nodeShapeValue {
	if decl.mutable && decl.exported {
		return nil
	}
	if assigned, again := m.assignedValues(scope, decl.name); decl.mutable && again {
		if decl.member != "" || len(assigned) > nodeAssignmentFanout {
			return nil
		}
		var out []nodeShapeValue
		if decl.value != nil {
			assigned = append([]*sitter.Node{decl.value}, assigned...)
		}
		for _, value := range assigned {
			if value == nil {
				return nil
			}
			if nodeIsNothing(value) || nodeAssignedLater(value, use) {
				continue
			}
			held := q.values(m, value, depth+1)
			if len(held) == 0 {
				return nil
			}
			out = appendNodeValues(out, held...)
		}
		return out
	}
	if decl.value == nil {
		return nil
	}
	values := q.values(m, decl.value, depth+1)
	if decl.member == "" {
		return values
	}
	var out []nodeShapeValue
	for _, v := range values {
		out = appendNodeValues(out, q.member(v, decl.member, depth+1)...)
	}
	return out
}

// nodeShapeDecl is what a scope declares a name as: the function or class
// declared, or the initialiser of a variable, with the member of it that an
// object pattern binds (`const { a: name } = value`).
type nodeShapeDecl struct {
	name   string
	value  *sitter.Node
	member string
	// mutable marks a `let` or `var`, exported one that an export statement
	// declares.
	mutable, exported bool
}

// declarations indexes the names the direct statements of a block or a
// program declare, the first declaration of each. A lookup by name walked
// the statements by index, which is quadratic in a bundle's one long block.
func (m *nodeShapeModule) declarations(scope *sitter.Node) map[string]nodeShapeDecl {
	if found, ok := m.declared[scope.StartByte()]; ok && scope.Type() != nodeProgram {
		return found
	}
	if scope.Type() == nodeProgram && m.programDeclared != nil {
		return m.programDeclared
	}
	found := make(map[string]nodeShapeDecl)
	mutable, exported := false, false
	add := func(name string, decl nodeShapeDecl) {
		if _, seen := found[name]; !seen && name != "" {
			decl.name, decl.mutable, decl.exported = name, mutable, exported
			found[name] = decl
		}
	}
	nodeEachNamedChild(scope, func(stmt *sitter.Node) {
		exported = false
		if stmt.Type() == nodeExportKind {
			if decl := stmt.ChildByFieldName("declaration"); decl != nil {
				stmt, exported = decl, true
			}
		}
		mutable = stmt.Type() == nodeVariableDeclaration || (stmt.Type() == nodeLexicalDeclaration && !hasNodeToken(stmt, "const"))
		switch stmt.Type() {
		case nodeFunctionDeclaration, nodeGeneratorDeclaration, nodeClassDeclaration, nodeAbstractClassDeclaration:
			if name := stmt.ChildByFieldName(nodeFieldName); name != nil {
				add(name.Content(m.src), nodeShapeDecl{value: stmt})
			}
		case nodeLexicalDeclaration, nodeVariableDeclaration:
			nodeEachNamedChild(stmt, func(d *sitter.Node) {
				if d.Type() != nodeVariableDeclarator {
					return
				}
				name, value := d.ChildByFieldName(nodeFieldName), d.ChildByFieldName("value")
				if name == nil {
					return
				}
				switch name.Type() {
				case goNodeIdentifier:
					add(name.Content(m.src), nodeShapeDecl{value: value})
				case nodeObjectPattern:
					nodeEachNamedChild(name, func(item *sitter.Node) {
						switch item.Type() {
						case nodeShorthandPattern:
							add(item.Content(m.src), nodeShapeDecl{value: value, member: item.Content(m.src)})
						case nodePairPattern:
							key, alias := item.ChildByFieldName("key"), item.ChildByFieldName("value")
							if key != nil && alias != nil && alias.Type() == goNodeIdentifier {
								add(alias.Content(m.src), nodeShapeDecl{value: value, member: unquoteNodeString(key.Content(m.src))})
							}
						}
					})
				}
				// Any other name the pattern binds is declared here with a
				// value this does not read.
				bound := make(map[string]bool)
				collectNodePatternNames(name, m.src, bound)
				for other := range bound {
					add(other, nodeShapeDecl{})
				}
			})
		}
	})
	if scope.Type() == nodeProgram {
		m.programDeclared = found
		return found
	}
	if m.declared == nil {
		m.declared = make(map[uint32]map[string]nodeShapeDecl)
	}
	m.declared[scope.StartByte()] = found
	return found
}

// nodeEachNamedChild visits the named children of n in order, without the
// index lookups that cost the position of each child.
func nodeEachNamedChild(n *sitter.Node, visit func(*sitter.Node)) {
	cursor := sitter.NewTreeCursor(n)
	defer cursor.Close()
	if !cursor.GoToFirstChild() {
		return
	}
	for {
		if child := cursor.CurrentNode(); child.IsNamed() {
			visit(child)
		}
		if !cursor.GoToNextSibling() {
			return
		}
	}
}

// nodeShapeImport is the module a top-level import binds a name from and the
// name imported: "default" for a default import, "" for the module itself.
type nodeShapeImport struct {
	spec, name string
}

// imports indexes the names the module's import statements bind, and
// TypeScript's `import x = require('m')`.
func (m *nodeShapeModule) imports() map[string]nodeShapeImport {
	if m.imported != nil {
		return m.imported
	}
	m.imported = make(map[string]nodeShapeImport)
	for _, stmt := range m.topLevel() {
		if stmt.Type() != nodeImportStatement {
			continue
		}
		if name, module, ok := nodeImportRequireClause(stmt, m.src); ok {
			m.imported[name] = nodeShapeImport{spec: module}
			continue
		}
		source := stmt.ChildByFieldName("source")
		if source == nil {
			continue
		}
		spec := unquoteNodeString(source.Content(m.src))
		nodeWalk(stmt, func(n *sitter.Node) {
			switch n.Type() {
			case nodeImportSpecifier:
				name, alias := n.ChildByFieldName(nodeFieldName), n.ChildByFieldName("alias")
				if alias == nil {
					alias = name
				}
				if name != nil {
					m.imported[alias.Content(m.src)] = nodeShapeImport{spec: spec, name: unquoteNodeString(name.Content(m.src))}
				}
			case nodeNamespaceImport:
				if n.NamedChildCount() > 0 {
					m.imported[n.NamedChild(0).Content(m.src)] = nodeShapeImport{spec: spec}
				}
			case goNodeIdentifier:
				if parent := n.Parent(); parent != nil && parent.Type() == nodeImportClause {
					m.imported[n.Content(m.src)] = nodeShapeImport{spec: spec, name: nodeDefaultExport}
				}
			}
		})
	}
	return m.imported
}

// callValues is what a call expression yields: the module a require loads,
// the object Object.assign or Object.freeze passes on, the function a bind
// wraps, or what the function called returns.
func (q *nodeValueQuery) callValues(m *nodeShapeModule, call *sitter.Node, depth int) []nodeShapeValue {
	fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if fn == nil || args == nil {
		return nil
	}
	if text := fn.Content(m.src); text == nodeRequireFunction || fn.Type() == "import" {
		if args.NamedChildCount() != 1 {
			return nil
		}
		if args.NamedChild(0).Type() != nodeStringNode {
			return q.loaded(m, args.NamedChild(0), depth)
		}
		spec := unquoteNodeString(args.NamedChild(0).Content(m.src))
		if target := q.s.local(m, spec); target != nil {
			return q.moduleValues(target, depth+1)
		}
		return nodeExternalValue(spec)
	}
	if isNodeImportInteropHelper(fn, m.src) && args.NamedChildCount() == 1 {
		return q.values(m, args.NamedChild(0), depth+1)
	}
	switch fn.Content(m.src) {
	case nodeObjectFreeze, "Object.assign", "Object.seal":
		var out []nodeShapeValue
		for i := 0; i < int(args.NamedChildCount()); i++ {
			out = appendNodeValues(out, q.values(m, args.NamedChild(i), depth+1)...)
		}
		return out
	}
	callee := unwrapNodeCallee(fn)
	if callee.Type() == nodeMemberExpression {
		if property := callee.ChildByFieldName("property"); property != nil && property.Content(m.src) == "bind" {
			return q.values(m, callee.ChildByFieldName("object"), depth+1)
		}
	}
	var out []nodeShapeValue
	for _, f := range q.values(m, callee, depth+1) {
		out = appendNodeValues(out, q.results(f, depth+1)...)
	}
	return out
}

// calleeValues is what the callee of a call expression is: the values of
// the expression, or for `f.call(..)`, `f.apply(..)` and `f.bind(..)` those
// of f, which is the function that runs.
func (q *nodeValueQuery) calleeValues(m *nodeShapeModule, callee *sitter.Node, depth int) []nodeShapeValue {
	callee = unwrapNodeCallee(callee)
	if callee.Type() == nodeMemberExpression {
		if property := callee.ChildByFieldName("property"); property != nil {
			switch property.Content(m.src) {
			case "call", "apply", "bind":
				if values := q.values(m, callee.ChildByFieldName("object"), depth+1); len(values) > 0 {
					return values
				}
			}
		}
	}
	return q.values(m, callee, depth)
}

// results is what calling v returns: each value a return statement of its
// own body yields, or the expression an arrow function evaluates to.
func (q *nodeValueQuery) results(v nodeShapeValue, depth int) []nodeShapeValue {
	if v.external != nil {
		return v.step(nodeAccessStep{call: true})
	}
	if !v.callable() || v.class() || depth > nodeShapeDepth {
		return nil
	}
	body := v.n.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	if body.Type() != nodeStatementBlock {
		return q.values(v.m, body, depth+1)
	}
	var out []nodeShapeValue
	nodeWalkSkippingFunctions(body, func(n *sitter.Node) {
		if n.Type() == goNodeReturnStatement && n.NamedChildCount() > 0 {
			out = appendNodeValues(out, q.values(v.m, n.NamedChild(0), depth+1)...)
		}
	})
	return out
}

// instances is what constructing each of values builds.
func nodeInstancesOf(values []nodeShapeValue) []nodeShapeValue {
	var out []nodeShapeValue
	for _, v := range values {
		if v.external != nil {
			out = appendNodeValues(out, v.step(nodeAccessStep{ctor: true})...)
			continue
		}
		if v.callable() && v.n.Type() != nodeMethodDefinition && v.n.Type() != nodeArrowFunction {
			out = appendNodeValues(out, nodeShapeValue{m: v.m, n: v.n, instance: true})
		}
	}
	return out
}

// thisValues is what `this` is where n reads it: an instance of the class
// whose method reads it, the object literal whose method does, the object a
// function is assigned as a property of, or an instance of the constructor
// function itself. An arrow function reads the `this` around it.
func (q *nodeValueQuery) thisValues(m *nodeShapeModule, n *sitter.Node, depth int) []nodeShapeValue {
	for fn := n.Parent(); fn != nil; fn = fn.Parent() {
		switch fn.Type() {
		case nodeMethodDefinition:
			owner := nodeMethodOwner(m, fn)
			if hasNodeToken(fn, "static") {
				return owner
			}
			return appendNodeValues(owner, q.receiverValues(m, fn)...)
		case nodeFieldDefinition, nodePublicFieldDefinition:
			if body := fn.Parent(); body != nil && body.Parent() != nil {
				return []nodeShapeValue{{m: m, n: body.Parent(), instance: !hasNodeToken(fn, "static")}}
			}
			return nil
		case nodeFunctionExpression, nodeFunctionDeclaration, nodeGeneratorDeclaration, nodeGeneratorFunction:
			return q.functionThis(m, fn, depth)
		}
	}
	return nil
}

// nodeMethodOwner is the value a method is a member of: an instance of its
// class (the class itself for a static method), or its object literal.
func nodeMethodOwner(m *nodeShapeModule, method *sitter.Node) []nodeShapeValue {
	owner := method.Parent()
	if owner == nil {
		return nil
	}
	if owner.Type() == nodeObjectLiteral {
		return []nodeShapeValue{{m: m, n: owner}}
	}
	if owner.Type() == nodeClassBody && owner.Parent() != nil {
		return []nodeShapeValue{{m: m, n: owner.Parent(), instance: !hasNodeToken(method, "static")}}
	}
	return nil
}

// functionThis is `this` in a function written with the function keyword:
// what the assignment that stores it makes it a member of, else an instance
// of the function itself.
func (q *nodeValueQuery) functionThis(m *nodeShapeModule, fn *sitter.Node, depth int) []nodeShapeValue {
	holder := fn.Parent()
	for holder != nil && (holder.Type() == goNodeParenExpr) {
		holder = holder.Parent()
	}
	if holder != nil && holder.Type() == nodePair {
		if object := holder.Parent(); object != nil && object.Type() == nodeObjectLiteral {
			return []nodeShapeValue{{m: m, n: object}}
		}
	}
	if holder != nil && holder.Type() == nodeAssignmentExpression {
		left := holder.ChildByFieldName("left")
		if left != nil && left.Type() == nodeMemberExpression {
			return q.values(m, left.ChildByFieldName("object"), depth+1)
		}
	}
	return []nodeShapeValue{{m: m, n: fn, instance: true}}
}

// nodeValueNames lists the names the source knows a function, class or
// object by: its own name and the variable it is bound to. Assignments such
// as `Name.prototype.m = ..` and `name.m = ..` are found through them.
func nodeValueNames(v nodeShapeValue) []string {
	var names []string
	if v.external != nil {
		return nil
	}
	add := func(name string) {
		if name != "" && (len(names) == 0 || names[0] != name) {
			names = append(names, name)
		}
	}
	if v.n.Type() != nodeObjectLiteral && v.n.Type() != nodeProgram {
		if own := v.n.ChildByFieldName(nodeFieldName); own != nil && v.n.Type() != nodeMethodDefinition {
			add(own.Content(v.m.src))
		}
	}
	holder := v.n.Parent()
	// The value of a default (`ns.x = ns.x || {}`) and of a chain of
	// assignments (`var x = ns.x = ns.x || {}`) is named by each target.
	for holder != nil {
		switch {
		case holder.Type() == goNodeParenExpr:
		case holder.Type() == "binary_expression" && nodeDefaultOperator(holder, v.m.src):
		case holder.Type() == nodeAssignmentExpression && holder.ChildByFieldName("left") != nil &&
			holder.ChildByFieldName("left").Type() == nodeMemberExpression:
			add(holder.ChildByFieldName("left").Content(v.m.src))
		default:
			goto named
		}
		holder = holder.Parent()
	}
named:
	if holder == nil {
		return names
	}
	switch holder.Type() {
	case nodeVariableDeclarator:
		if name := holder.ChildByFieldName(nodeFieldName); name != nil && name.Type() == goNodeIdentifier {
			add(name.Content(v.m.src))
		}
	case nodeAssignmentExpression:
		if left := holder.ChildByFieldName("left"); left != nil && left.Type() == goNodeIdentifier {
			add(left.Content(v.m.src))
		}
	}
	return names
}

// nodeDefaultOperator reports whether the binary expression n is `a || b`
// or `a ?? b`, which hold the value of either operand.
func nodeDefaultOperator(n *sitter.Node, src []byte) bool {
	op := n.ChildByFieldName("operator")
	return op != nil && (op.Content(src) == "||" || op.Content(src) == "??")
}

// member is what the member name of v is.
func (q *nodeValueQuery) member(v nodeShapeValue, name string, depth int) []nodeShapeValue {
	if depth > nodeShapeDepth || !q.spend() {
		return nil
	}
	switch {
	case v.external != nil:
		if name == nodeDefaultExport && len(v.external.steps) == 0 {
			return []nodeShapeValue{v} // the module's own value, as an import reads it
		}
		return v.step(nodeAccessStep{name: name})
	case v.module:
		return q.moduleMember(v, name, depth)
	case v.instance:
		return q.instanceMember(v, name, depth, 0)
	case v.n.Type() == nodeObjectLiteral:
		if value, vm := q.s.objectMember(v.m, v.n, name, depth); value != nil {
			return q.values(vm, value, depth+1)
		}
		for _, base := range nodeValueNames(v) {
			if value := v.m.definedMembers()[base][name]; value != nil {
				return q.values(v.m, value, depth+1)
			}
		}
		if values := q.assignedMember(v, name, depth); len(values) > 0 {
			return values
		}
		return q.foreignMember(v, name, depth)
	case v.callable() && v.n.Type() != nodeMethodDefinition:
		if name == nodePrototypeMember {
			return []nodeShapeValue{{m: v.m, n: v.n, instance: true}}
		}
		if v.class() {
			if member := nodeClassMember(v.m, v.n, name, true); member != nil {
				return q.classMemberValues(v.m, member, depth)
			}
		}
		return q.assignedMember(v, name, depth)
	}
	return nil
}

// moduleMember is the export name of a module: what it exports under that
// name, what it assigns to that property of its exports object, or for
// "default" its own value.
func (q *nodeValueQuery) moduleMember(v nodeShapeValue, name string, depth int) []nodeShapeValue {
	if decl, ok := v.m.declarations(v.m.root)[name]; ok && decl.mutable && (decl.exported || v.m.reassigned(v.m.root, name)) {
		return nil // a `let` the module may assign again
	}
	if value, vm := q.s.exportValue(v.m, name, depth); value != nil {
		return q.values(vm, value, depth+1)
	}
	if name == nodeDefaultExport {
		return []nodeShapeValue{v}
	}
	if value := assignedExportPath(v.m, name, nil); value != nil {
		return q.values(v.m, q.s.followExportAlias(v.m, value, 0), depth+1)
	}
	return nil
}

// foreignMember is what other modules of the package assign to the member
// name of the object a module exports, through the name they require it
// under: node-forge's forge.js exports `{ options }`, and pbkdf2.js writes
// `forge.pkcs5 = forge.pkcs5 || {}` into it with `forge = require('./forge')`.
func (q *nodeValueQuery) foreignMember(v nodeShapeValue, name string, depth int) []nodeShapeValue {
	writes := q.s.foreign[filepath.Clean(v.m.path)][name]
	if len(writes) == 0 {
		return nil
	}
	if exported, em := q.s.exportValue(v.m, nodeDefaultExport, depth); exported == nil || em != v.m || !sameSyntaxNode(nodeUnfrozen(exported, v.m.src), v.n) {
		return nil
	}
	var out []nodeShapeValue
	for _, w := range writes {
		out = appendNodeValues(out, q.values(w.m, w.value, depth+1)...)
	}
	return out
}

// assignedMember is the value the module assigns to `<v>.name` after v is
// built: `hotp.gen = function`, `VerifyStream.verify = function`.
func (q *nodeValueQuery) assignedMember(v nodeShapeValue, name string, depth int) []nodeShapeValue {
	for _, base := range nodeValueNames(v) {
		if value := nodeAssignedValue(v.m, base+"."+name); value != nil {
			return q.values(v.m, value, depth+1)
		}
	}
	return nil
}

// nodeClassMember finds the member of a class body called name: a static
// one when static is set, an instance one otherwise.
func nodeClassMember(m *nodeShapeModule, class *sitter.Node, name string, static bool) *sitter.Node {
	body := class.ChildByFieldName("body")
	if body == nil || body.Type() != nodeClassBody {
		return nil
	}
	for i := 0; i < int(body.NamedChildCount()); i++ {
		member := body.NamedChild(i)
		if nodeClassMemberName(m, member) == name && hasNodeToken(member, "static") == static {
			return member
		}
	}
	return nil
}

// classMemberValues is the value of a class member: the method itself, or
// what a field's initialiser evaluates to.
func (q *nodeValueQuery) classMemberValues(m *nodeShapeModule, member *sitter.Node, depth int) []nodeShapeValue {
	if member.Type() == nodeMethodDefinition {
		return []nodeShapeValue{{m: m, n: member}}
	}
	return q.values(m, member.ChildByFieldName("value"), depth+1)
}

// nodeInheritanceDepth bounds the base classes one member is looked up in.
const nodeInheritanceDepth = 8

// instanceMember is the member name of an instance of v: a method or field of
// the class, a `Name.prototype.name` assignment, a member of the object
// assigned to `Name.prototype`, a `this.name = ..` assignment of the
// constructor, or the same in the class it extends or inherits from.
func (q *nodeValueQuery) instanceMember(v nodeShapeValue, name string, depth, up int) []nodeShapeValue {
	if up > nodeInheritanceDepth || !q.spend() {
		return nil
	}
	if v.external != nil {
		return v.step(nodeAccessStep{name: name})
	}
	if v.class() {
		// A field declared without a value (`adapter: Adapter;`) holds what
		// the constructor or a method assigns it.
		if member := nodeClassMember(v.m, v.n, name, false); member != nil && (member.Type() == nodeMethodDefinition || member.ChildByFieldName("value") != nil) {
			return q.classMemberValues(v.m, member, depth)
		}
	}
	for _, base := range nodeValueNames(nodeShapeValue{m: v.m, n: v.n}) {
		if value := nodeAssignedValue(v.m, base+"."+nodePrototypeMember+"."+name); value != nil {
			return q.values(v.m, value, depth+1)
		}
		if proto := nodeAssignedValue(v.m, base+"."+nodePrototypeMember); proto != nil {
			for _, object := range q.values(v.m, proto, depth+1) {
				if object.object() {
					if found := q.member(object, name, depth+1); len(found) > 0 {
						return found
					}
				}
			}
		}
	}
	if value := v.m.thisAssignments(nodeConstructorBody(v))[name]; value != nil {
		if found := q.values(v.m, value, depth+1); len(found) > 0 {
			return found
		}
		// A field the constructor empties (`this.next = null`) holds what
		// the methods assign it.
	}
	if found := q.fieldValues(v, name, depth); len(found) > 0 {
		return found
	}
	var out []nodeShapeValue
	for _, base := range q.bases(v, depth) {
		out = appendNodeValues(out, q.instanceMember(base, name, depth+1, up+1)...)
	}
	return out
}

// fieldValues is what the methods of a class assign to the field name of
// this, outside the constructor: `connect() { this.sock = new Socket() }`.
// The field holds any of them, when each one is known.
func (q *nodeValueQuery) fieldValues(v nodeShapeValue, name string, depth int) []nodeShapeValue {
	if !v.class() {
		return nil
	}
	body := v.n.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	var out []nodeShapeValue
	unknown, count, steps := false, 0, false
	nodeEachNamedChild(body, func(member *sitter.Node) {
		if member.Type() != nodeMethodDefinition || unknown {
			return
		}
		for _, value := range v.m.thisAssignmentsOf(member.ChildByFieldName("body"), name) {
			if nodeIsNothing(value) {
				continue
			}
			if nodeCallsThisField(value, name, v.m.src) {
				steps = true // `this.next = this.next(p)`: read below
				continue
			}
			count++
			held := q.values(v.m, value, depth+1)
			if len(held) == 0 || count > nodeAssignmentFanout {
				unknown = true
				return
			}
			out = appendNodeValues(out, held...)
		}
	})
	if unknown {
		return nil
	}
	if steps {
		// A field a method sets to what calling it returns (a state
		// machine: each state returns the next) holds the functions the
		// others assign and what calling those returns, to a fixed point.
		for round := 0; round < nodeAssignmentFanout; round++ {
			grown := false
			for _, state := range slices.Clone(out) {
				for _, next := range q.results(state, depth+1) {
					if next.callable() && !next.class() && !slices.ContainsFunc(out, next.same) {
						out = appendNodeValues(out, next)
						grown = true
					}
				}
			}
			if !grown {
				break
			}
		}
	}
	return out
}

// nodeCallsThisField reports whether value calls the field name of this:
// `this.next(p)` or `this.next.call(this, p)`.
func nodeCallsThisField(value *sitter.Node, name string, src []byte) bool {
	value = nodeUnwrapValue(value)
	if value == nil || value.Type() != nodeCallExpression {
		return false
	}
	callee := value.ChildByFieldName("function")
	if callee != nil && callee.Type() == nodeMemberExpression && nodeCallsThrough(callee, src) {
		callee = callee.ChildByFieldName("object")
	}
	return callee != nil && strings.TrimPrefix(nodeThisField(callee, src), nodeThisNode+".") == name
}

// thisAssignmentsOf lists every value body assigns to the field name of
// this, outside nested functions, in source order.
func (m *nodeShapeModule) thisAssignmentsOf(body *sitter.Node, name string) []*sitter.Node {
	if body == nil {
		return nil
	}
	var out []*sitter.Node
	nodeWalkSkippingFunctions(body, func(n *sitter.Node) {
		if n.Type() != nodeAssignmentExpression {
			return
		}
		field := nodeThisField(n.ChildByFieldName("left"), m.src)
		if strings.TrimPrefix(strings.TrimPrefix(field, nodeThisNode+"."), "#") == name {
			out = append(out, n.ChildByFieldName("right"))
		}
	})
	return out
}

// nodeConstructorBody is the body that runs when v is constructed: the
// class's constructor, or the constructor function's own body.
func nodeConstructorBody(v nodeShapeValue) *sitter.Node {
	if !v.class() {
		return v.n.ChildByFieldName("body")
	}
	if ctor := nodeClassMember(v.m, v.n, nodeConstructorKeyword, false); ctor != nil {
		return ctor.ChildByFieldName("body")
	}
	return nil
}

// thisAssignments indexes the `this.name = value` assignments body makes
// outside any function nested in it, the first of each name.
func (m *nodeShapeModule) thisAssignments(body *sitter.Node) map[string]*sitter.Node {
	if body == nil {
		return nil
	}
	if found, ok := m.thisAssigned[body.StartByte()]; ok {
		return found
	}
	found := make(map[string]*sitter.Node)
	nodeWalkSkippingFunctions(body, func(n *sitter.Node) {
		if n.Type() != nodeAssignmentExpression {
			return
		}
		field := nodeThisField(n.ChildByFieldName("left"), m.src)
		if field == "" {
			return
		}
		name := strings.TrimPrefix(strings.TrimPrefix(field, nodeThisNode+"."), "#")
		if _, seen := found[name]; !seen {
			found[name] = n.ChildByFieldName("right")
		}
	})
	if m.thisAssigned == nil {
		m.thisAssigned = make(map[uint32]map[string]*sitter.Node)
	}
	m.thisAssigned[body.StartByte()] = found
	return found
}

// bases lists the classes an instance of v inherits from: the class its
// `extends` clause names, and the base a call such as `inherits(Name, Base)`
// or an assignment such as `Name.prototype = Object.create(Base.prototype)`
// gives a constructor function.
func (q *nodeValueQuery) bases(v nodeShapeValue, depth int) []nodeShapeValue {
	var out []nodeShapeValue
	add := func(expr *sitter.Node) {
		for _, base := range q.values(v.m, expr, depth+1) {
			if base.external != nil {
				out = appendNodeValues(out, base.step(nodeAccessStep{ctor: true})...)
				continue
			}
			if base.callable() && base.n.Type() != nodeMethodDefinition && !sameSyntaxNode(base.n, v.n) {
				out = appendNodeValues(out, nodeShapeValue{m: base.m, n: base.n, instance: true})
			}
		}
	}
	if v.class() {
		for i := 0; i < int(v.n.NamedChildCount()); i++ {
			if heritage := v.n.NamedChild(i); heritage.Type() == nodeClassHeritage && heritage.NamedChildCount() > 0 {
				expr := heritage.NamedChild(0)
				if expr.Type() == "extends_clause" && expr.NamedChildCount() > 0 {
					expr = expr.NamedChild(0)
				}
				add(expr)
			}
		}
	}
	for _, name := range nodeValueNames(nodeShapeValue{m: v.m, n: v.n}) {
		for _, expr := range v.m.inherited()[name] {
			add(expr)
		}
	}
	return out
}

// inherited indexes, by the name of the constructor, the base each
// inheritance idiom of the module names: `inherits(Name, Base)`,
// `Object.setPrototypeOf(Name.prototype, Base.prototype)`, `Name.prototype =
// Object.create(Base.prototype)`, `Name.prototype = new Base()` and
// `Name.prototype.__proto__ = Base.prototype`.
func (m *nodeShapeModule) inherited() map[string][]*sitter.Node {
	if m.inherits != nil {
		return m.inherits
	}
	m.inherits = make(map[string][]*sitter.Node)
	protoOf := func(n *sitter.Node) *sitter.Node {
		if n == nil || n.Type() != nodeMemberExpression {
			return nil
		}
		if property := n.ChildByFieldName("property"); property == nil || property.Content(m.src) != nodePrototypeMember {
			return nil
		}
		return n.ChildByFieldName("object")
	}
	m.walk(func(n *sitter.Node) {
		switch n.Type() {
		case nodeCallExpression:
			fn, args := n.ChildByFieldName("function"), n.ChildByFieldName("arguments")
			if fn == nil || args == nil || args.NamedChildCount() < 2 {
				return
			}
			child, base := args.NamedChild(0), args.NamedChild(1)
			switch text := fn.Content(m.src); {
			case text == "inherits" || strings.HasSuffix(text, ".inherits"):
			case text == "Object.setPrototypeOf":
				child, base = protoOf(child), protoOf(base)
			default:
				return
			}
			if child != nil && base != nil {
				m.inherits[child.Content(m.src)] = append(m.inherits[child.Content(m.src)], base)
			}
		case nodeAssignmentExpression:
			left, right := n.ChildByFieldName("left"), nodeUnwrapValue(n.ChildByFieldName("right"))
			if left == nil || right == nil {
				return
			}
			child := protoOf(left)
			if child == nil && left.Type() == nodeMemberExpression {
				if property := left.ChildByFieldName("property"); property != nil && property.Content(m.src) == "__proto__" {
					child = protoOf(left.ChildByFieldName("object"))
				}
			}
			if child == nil {
				return
			}
			var base *sitter.Node
			switch right.Type() {
			case nodeNewExpression:
				base = right.ChildByFieldName("constructor")
			case nodeCallExpression:
				fn, args := right.ChildByFieldName("function"), right.ChildByFieldName("arguments")
				if fn != nil && args != nil && fn.Content(m.src) == "Object.create" && args.NamedChildCount() > 0 {
					base = protoOf(args.NamedChild(0))
				}
			case nodeMemberExpression:
				base = protoOf(right)
			}
			if base != nil {
				m.inherits[child.Content(m.src)] = append(m.inherits[child.Content(m.src)], base)
			}
		}
	})
	return m.inherits
}

// nodeMemberNameCap bounds the member names listed for one value.
const nodeMemberNameCap = 256

// memberNames lists the members v is known to have, in a stable order (a
// source's as written, a set's sorted): the
// keys of an object literal and the properties assigned to it, the methods
// and fields of an instance with those it inherits, the static members of a
// class. A module's are its export names.
func (q *nodeValueQuery) memberNames(v nodeShapeValue, depth int) []string {
	var names []string
	seen := make(map[string]bool)
	add := func(name string) {
		name = strings.TrimPrefix(name, "#")
		if name != "" && !seen[name] && len(names) < nodeMemberNameCap {
			seen[name] = true
			names = append(names, name)
		}
	}
	q.collectMemberNames(v, depth, 0, add)
	return names
}

func (q *nodeValueQuery) collectMemberNames(v nodeShapeValue, depth, up int, add func(string)) {
	if v.external != nil || depth > nodeShapeDepth || up > nodeInheritanceDepth || !q.spend() {
		return
	}
	assigned := func(prefixes ...string) {
		for _, target := range slices.Sorted(maps.Keys(v.m.assignments().byTarget)) {
			for _, prefix := range prefixes {
				if rest, ok := strings.CutPrefix(target, prefix); ok && rest != "" && !strings.ContainsAny(rest, ".[(") && rest != nodePrototypeMember {
					add(rest)
				}
			}
		}
	}
	switch {
	case v.module:
		for _, name := range slices.Sorted(maps.Keys(nodeExportedNames(v.m.path, map[string]bool{}, 0))) {
			add(name)
		}
	case v.instance:
		if body := v.n.ChildByFieldName("body"); v.class() && body != nil {
			for i := 0; i < int(body.NamedChildCount()); i++ {
				if member := body.NamedChild(i); !hasNodeToken(member, "static") {
					if name := nodeClassMemberName(v.m, member); name != nodeConstructorKeyword {
						add(name)
					}
				}
			}
		}
		for _, base := range nodeValueNames(nodeShapeValue{m: v.m, n: v.n}) {
			assigned(base + "." + nodePrototypeMember + ".")
			if proto := nodeAssignedValue(v.m, base+"."+nodePrototypeMember); proto != nil {
				for _, object := range q.values(v.m, proto, depth+1) {
					if object.object() {
						q.collectMemberNames(object, depth+1, up, add)
					}
				}
			}
		}
		for _, name := range slices.Sorted(maps.Keys(v.m.thisAssignments(nodeConstructorBody(v)))) {
			add(name)
		}
		for _, base := range q.bases(v, depth) {
			q.collectMemberNames(base, depth+1, up+1, add)
		}
	case v.n.Type() == nodeObjectLiteral:
		for i := 0; i < int(v.n.NamedChildCount()); i++ {
			switch member := v.n.NamedChild(i); member.Type() {
			case nodeShorthandProperty:
				add(member.Content(v.m.src))
			case nodePair, nodeMethodDefinition:
				field := nodeFieldKey
				if member.Type() == nodeMethodDefinition {
					field = nodeFieldName
				}
				if key := member.ChildByFieldName(field); key != nil && key.Type() != "computed_property_name" {
					add(unquoteNodeString(key.Content(v.m.src)))
				}
			case nodeSpreadElement:
				if member.NamedChildCount() > 0 {
					for _, spread := range q.values(v.m, member.NamedChild(0), depth+1) {
						q.collectMemberNames(spread, depth+1, up, add)
					}
				}
			}
		}
		for _, base := range nodeValueNames(v) {
			assigned(base + ".")
			for _, name := range slices.Sorted(maps.Keys(v.m.definedMembers()[base])) {
				add(name)
			}
		}
	case v.callable() && v.n.Type() != nodeMethodDefinition:
		if body := v.n.ChildByFieldName("body"); v.class() && body != nil {
			for i := 0; i < int(body.NamedChildCount()); i++ {
				if member := body.NamedChild(i); hasNodeToken(member, "static") {
					add(nodeClassMemberName(v.m, member))
				}
			}
		}
		for _, base := range nodeValueNames(v) {
			assigned(base + ".")
		}
	}
}

// constructors lists the function `new` runs for an instance v: the class's
// constructor, else the one it inherits, or the constructor function itself.
func (q *nodeValueQuery) constructors(v nodeShapeValue, depth, up int) []nodeShapeValue {
	if v.external != nil || !v.instance || up > nodeInheritanceDepth {
		return nil
	}
	if !v.class() {
		return []nodeShapeValue{{m: v.m, n: v.n}}
	}
	if ctor := nodeClassMember(v.m, v.n, nodeConstructorKeyword, false); ctor != nil {
		return []nodeShapeValue{{m: v.m, n: ctor}}
	}
	var out []nodeShapeValue
	for _, base := range q.bases(v, depth) {
		out = appendNodeValues(out, q.constructors(base, depth+1, up+1)...)
	}
	return out
}

// local returns the module of the package a relative specifier written in
// from names, as the builder resolves it (resolveNodeRelativeModule): the
// file as written, else the file with the first source extension a resolver
// tries, else the directory's index. A specifier written with `.js` in a
// TypeScript source names the `.ts` beside it.
func (s *NodeShapes) local(from *nodeShapeModule, spec string) *nodeShapeModule {
	if !isNodeRelativeSpecifier(spec) {
		return nil
	}
	base := filepath.Join(filepath.Dir(from.path), filepath.FromSlash(spec))
	candidates := make([]string, 0, 2*len(nodeSourceExtensions)+2)
	if nodeSourceFileName(base) {
		candidates = append(candidates, base)
		if stem, ok := strings.CutSuffix(base, ".js"); ok {
			candidates = append(candidates, stem+".ts", stem+".tsx")
		}
	}
	for _, ext := range nodeSourceExtensions {
		candidates = append(candidates, base+ext)
	}
	for _, ext := range nodeSourceExtensions {
		candidates = append(candidates, filepath.Join(base, "index"+ext))
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return s.module(candidate)
		}
	}
	return nil
}
