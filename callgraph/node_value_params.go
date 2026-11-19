// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"

	sitter "github.com/smacker/go-tree-sitter"
)

// node_value_params.go follows a value from the calls of a function into its
// parameters, and three things that only resolve once a parameter does:
//
//	module.exports = function (deps) { const Client = deps.Client; .. new Client() }
//	const Provider = require('./provider')({ Client });       // deps holds { Client }
//
//	async function loadModule(path) { return (await import(path)).default; }
//	const Adapter = await loadModule('@acme/push');            // path is '@acme/push'
//
//	this.senders[type] = new Web(config);                      // a table filled by key
//	const sender = this.senders[type]; sender.send(data);      // holds what was put in it
//
// A parameter holds what the arguments of the function's calls hold: the
// union over the call sites the value flow has resolved to that function
// (nodeValueFlow records each as it draws the edge). A call site whose
// callee is itself unknown passes nothing, so the union is over the calls
// the source shows, never over functions that merely share a name. A
// function called from outside the package also receives what those callers
// pass, which this cannot see: what it finds is a lower bound.

const (
	// nodeParamNesting bounds the parameters being read at once: a value
	// handed down through more functions than this is read over the rounds.
	nodeParamNesting = 16
	// nodeParamSiteCap bounds the call sites one parameter is read from.
	nodeParamSiteCap = 24
	// nodeStringFanout bounds the string constants one expression yields.
	nodeStringFanout = 8
	// nodeElementWriteCap bounds the computed writes one table is read from.
	nodeElementWriteCap = 16
)

// nodeUnknownArguments is the shift of a call site that spells no argument
// of the function it runs (`f.apply(self, list)`).
const nodeUnknownArguments = -1

// nodeCallRef is one call site of a function: the call or `new` expression
// and its module. shift is how many leading arguments are not parameters
// (`f.call(self, a)` passes a first).
type nodeCallRef struct {
	m     *nodeShapeModule
	n     *sitter.Node
	shift int
}

// nodeCallRefKey identifies a call site of a function, to record it once.
type nodeCallRefKey struct {
	fn   nodeDeclStart
	file string
	at   uint32
}

// nodeCallSites holds the call sites of each function, by where the function
// starts. enabled is false while the first walk records them, so that what a
// parameter holds does not depend on which file was walked first.
type nodeCallSites struct {
	byFunction map[nodeDeclStart][]nodeCallRef
	seen       map[nodeCallRefKey]bool
	enabled    bool
	// added counts the sites recorded, for the caller to see a round add none.
	added int
	// values and strings remember what each parameter holds, for one round:
	// the sites a round records change the answer for the next. previous
	// holds the round before's, which a parameter read while it is itself
	// being read answers with (a function that passes its parameter on to
	// itself, or two that pass theirs to each other), so the rounds grow
	// such a value to a fixed point where one read alone would loop.
	values, previous map[nodeParamKey][]nodeShapeValue
	// shared is set once the value flow is done: a parameter read then
	// spends the budget of the question that asked for it, so the reads one
	// question nests stay within that question's budget (the exports of a
	// package are listed by many questions, each over every member).
	shared             bool
	strings, previousS map[nodeParamKey][]string
	// grew is set when a parameter holds more than the round before.
	grew bool
	// reads counts the parameters read, enabled or not: a question that
	// reads none has the same answer in every round.
	reads int
}

// round starts a round of reads: what the parameters held becomes the
// previous answer, and the sites recorded are counted from here.
func (c *nodeCallSites) round() {
	c.enabled, c.added, c.grew = true, 0, false
	c.previous, c.previousS = c.values, c.strings
	c.values, c.strings = make(map[nodeParamKey][]nodeShapeValue), make(map[nodeParamKey][]string)
}

func newNodeCallSites() *nodeCallSites {
	return &nodeCallSites{byFunction: make(map[nodeDeclStart][]nodeCallRef), seen: make(map[nodeCallRefKey]bool)}
}

// nodeFunctionStart is where the function node n of module m starts, the
// identity the call sites are kept under.
func nodeFunctionStart(m *nodeShapeModule, n *sitter.Node) nodeDeclStart {
	return nodeDeclStart{file: filepath.Clean(m.path), line: nodeLine(n), col: int(n.StartPoint().Column) + 1}
}

// add records that the call at site runs the function that starts at fn.
func (c *nodeCallSites) add(fn nodeDeclStart, site nodeCallRef) {
	if c == nil || site.m == nil || site.n == nil {
		return
	}
	key := nodeCallRefKey{fn: fn, file: site.m.path, at: site.n.StartByte()}
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	c.byFunction[fn] = append(c.byFunction[fn], site)
	c.added++
}

// argument is the expression the site passes as the parameter at index, nil
// when it passes none or spreads a list before it.
func (r nodeCallRef) argument(index int) *sitter.Node {
	args := r.n.ChildByFieldName("arguments")
	if args == nil || r.shift == nodeUnknownArguments {
		return nil
	}
	var found *sitter.Node
	at, spread := 0, false
	nodeEachNamedChild(args, func(arg *sitter.Node) {
		if arg.Type() == goNodeComment {
			return
		}
		if arg.Type() == nodeSpreadElement {
			spread = true
		}
		if !spread && at == index+r.shift {
			found = arg
		}
		at++
	})
	return found
}

// nodeParameter is where a function binds a name among its parameters: the
// position a caller fills, the member of that argument an object pattern
// reads (`function f({ client })`), and the default value.
type nodeParameter struct {
	index  int
	member string
	value  *sitter.Node
}

// parameter finds the parameter of fn that binds name. A rest parameter, an
// array pattern and a nested pattern bind names from values this does not
// follow.
func (m *nodeShapeModule) parameter(fn *sitter.Node, name string) (nodeParameter, bool) {
	if single := fn.ChildByFieldName("parameter"); single != nil {
		return nodeParameter{}, single.Type() == goNodeIdentifier && single.Content(m.src) == name
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return nodeParameter{}, false
	}
	var found nodeParameter
	ok, index := false, 0
	nodeEachNamedChild(params, func(param *sitter.Node) {
		if param.Type() == goNodeComment {
			return
		}
		at := nodeParameter{index: index}
		index++
		if ok {
			return
		}
		if param.Type() == nodeRequiredParameter || param.Type() == nodeOptionalParameter {
			at.value = param.ChildByFieldName("value")
			param = param.ChildByFieldName("pattern")
		}
		if param != nil && param.Type() == nodeAssignmentPattern {
			at.value = param.ChildByFieldName("right")
			param = param.ChildByFieldName("left")
		}
		if param == nil {
			return
		}
		switch param.Type() {
		case goNodeIdentifier:
			found, ok = at, param.Content(m.src) == name
		case nodeObjectPattern:
			at.value = nil // the default is the whole object's, not the member's
			nodeEachNamedChild(param, func(item *sitter.Node) {
				if item.Type() == "object_assignment_pattern" {
					item = item.ChildByFieldName("left")
				}
				if ok || item == nil {
					return
				}
				switch item.Type() {
				case nodeShorthandPattern:
					if item.Content(m.src) == name {
						at.member = name
						found, ok = at, true
					}
				case nodePairPattern:
					key, alias := item.ChildByFieldName("key"), item.ChildByFieldName("value")
					if key != nil && alias != nil && alias.Type() == goNodeIdentifier && alias.Content(m.src) == name {
						at.member = unquoteNodeString(key.Content(m.src))
						found, ok = at, true
					}
				}
			})
		}
	})
	return found, ok
}

// nodeParamKey names one parameter of one function, while a query reads it.
type nodeParamKey struct {
	fn   nodeDeclStart
	name string
}

// enter marks the parameter as being read; it reports false when it already
// is, or when too many are.
func (q *nodeValueQuery) enter(key nodeParamKey) bool {
	if q.active[key] || len(q.active) >= nodeParamNesting {
		return false
	}
	if q.active == nil {
		q.active = make(map[nodeParamKey]bool)
	}
	q.active[key] = true
	return true
}

// sites lists the recorded call sites of fn a parameter is read from.
func (q *nodeValueQuery) sites(fn nodeDeclStart) []nodeCallRef {
	sites := q.s.sites.byFunction[fn]
	if len(sites) > nodeParamSiteCap {
		sites = sites[:nodeParamSiteCap]
	}
	return sites
}

// parameterQuery is the question a parameter is read with: one of its own,
// so that what the parameter holds does not depend on the budget left to
// whoever asked first. It shares the parameters being read.
func (q *nodeValueQuery) parameterQuery() *nodeValueQuery {
	sub := q.s.query()
	sub.active = q.active
	return sub
}

// parameterValues is what the parameter name of fn holds: its default value,
// and what each recorded call of fn passes in its position.
func (q *nodeValueQuery) parameterValues(m *nodeShapeModule, fn *sitter.Node, name string) []nodeShapeValue {
	c := q.s.sites
	if c == nil {
		return nil
	}
	c.reads++
	if !c.enabled {
		return nil
	}
	param, ok := m.parameter(fn, name)
	if !ok {
		return nil
	}
	at := nodeFunctionStart(m, fn)
	key := nodeParamKey{fn: at, name: name}
	if held, ok := c.values[key]; ok {
		return held
	}
	if !q.enter(key) {
		return c.previous[key]
	}
	sub := q.parameterQuery()
	if c.shared {
		sub.budget = q.budget
		defer func() {
			q.budget = sub.budget
			q.cut = q.cut || sub.cut
		}()
	}
	// An argument is read where the caller writes it, as a question of its
	// own, from depth 0.
	out := sub.values(m, param.value, 0)
	for _, site := range q.sites(at) {
		passed := sub.values(site.m, site.argument(param.index), 0)
		if param.member == "" {
			for _, v := range passed {
				v.passed = v.passed || (v.external == nil && v.callable() && !v.class())
				out = appendNodeValues(out, v)
			}
			continue
		}
		for _, v := range passed {
			out = appendNodeValues(out, sub.member(v, param.member, 0)...)
		}
	}
	delete(q.active, key)
	if sub.cut {
		return out // out of budget: part of the answer, not remembered
	}
	c.values[key] = out
	c.grew = c.grew || len(out) > len(c.previous[key])
	return out
}

// nodeNameBinding is what binds a name where it is read: the function whose
// parameter it is, or the scope whose declaration it is.
type nodeNameBinding struct {
	param *sitter.Node
	scope *sitter.Node
	decl  nodeShapeDecl
}

// nameBinding finds what binds the name read at n in the scopes around it.
// A catch or loop variable, a function expression's own name and a name no
// scope of the module declares bind nothing this follows.
func (m *nodeShapeModule) nameBinding(n *sitter.Node) (nodeNameBinding, bool) {
	name := n.Content(m.src)
	for scope := n.Parent(); scope != nil; scope = scope.Parent() {
		switch scope.Type() {
		case nodeFunctionDeclaration, nodeFunctionExpression, nodeArrowFunction, nodeMethodDefinition, nodeGeneratorDeclaration, nodeGeneratorFunction:
			if m.parameters(scope)[name] {
				return nodeNameBinding{param: scope}, true
			}
			if own := scope.ChildByFieldName(nodeFieldName); own != nil && scope.Type() == nodeFunctionExpression && own.Content(m.src) == name {
				return nodeNameBinding{}, false
			}
		case "catch_clause", nodeForInStatement:
			bound := make(map[string]bool)
			collectNodePatternNames(scope.ChildByFieldName("parameter"), m.src, bound)
			collectNodePatternNames(scope.ChildByFieldName("left"), m.src, bound)
			if bound[name] {
				return nodeNameBinding{}, false
			}
		case nodeStatementBlock, nodeProgram:
			if decl, ok := m.declarations(scope)[name]; ok {
				return nodeNameBinding{scope: scope, decl: decl}, true
			}
		}
	}
	return nodeNameBinding{}, false
}

func appendNodeStrings(out []string, values ...string) []string {
	for _, v := range values {
		seen := v == "" || len(out) >= nodeStringFanout
		for i := 0; i < len(out) && !seen; i++ {
			seen = out[i] == v
		}
		if !seen {
			out = append(out, v)
		}
	}
	return out
}

// strings lists the string constants the expression n of module m may
// evaluate to: a literal, a name bound to one, a parameter some call passes
// one for, a member of an object literal, or either side of a choice. An
// expression that builds its string (a template with values, a
// concatenation) yields none.
func (q *nodeValueQuery) strings(m *nodeShapeModule, n *sitter.Node, depth int) []string {
	n = nodeUnwrapValue(n)
	if n == nil || m == nil || depth > nodeShapeDepth || !q.spend() {
		return nil
	}
	switch n.Type() {
	case nodeStringNode:
		if text, ok := canonicalNodeStringLiteral(n.Content(m.src)); ok {
			return []string{unquoteNodeString(text)}
		}
	case nodeTemplateString:
		constant := true
		nodeEachNamedChild(n, func(part *sitter.Node) { constant = constant && part.Type() != "template_substitution" })
		if constant {
			return []string{unquoteNodeString(n.Content(m.src))}
		}
	case goNodeIdentifier:
		return q.nameStrings(m, n, depth)
	case nodeMemberExpression, nodeSubscriptExpression:
		object, name, ok := nodeReadMember(n, m.src)
		if !ok {
			return nil
		}
		var out []string
		for _, o := range q.values(m, object, depth+1) {
			if !o.object() {
				continue
			}
			if value, vm := q.s.objectMember(o.m, o.n, name, depth); value != nil {
				out = appendNodeStrings(out, q.strings(vm, value, depth+1)...)
			}
		}
		return out
	case "ternary_expression":
		out := q.strings(m, n.ChildByFieldName("consequence"), depth+1)
		return appendNodeStrings(out, q.strings(m, n.ChildByFieldName("alternative"), depth+1)...)
	case "binary_expression":
		if op := n.ChildByFieldName("operator"); op != nil && (op.Type() == "||" || op.Type() == "??") {
			out := q.strings(m, n.ChildByFieldName("left"), depth+1)
			return appendNodeStrings(out, q.strings(m, n.ChildByFieldName("right"), depth+1)...)
		}
	case "as_expression", "satisfies_expression", "non_null_expression":
		if n.NamedChildCount() > 0 {
			return q.strings(m, n.NamedChild(0), depth+1)
		}
	}
	return nil
}

// nameStrings lists the string constants the name read at n holds: those of
// its initialiser, of each value it is assigned, or of the argument each
// recorded call passes for the parameter it is.
func (q *nodeValueQuery) nameStrings(m *nodeShapeModule, n *sitter.Node, depth int) []string {
	binding, ok := m.nameBinding(n)
	if !ok {
		return nil
	}
	name := n.Content(m.src)
	if binding.param == nil {
		if binding.decl.member != "" || binding.decl.value == nil || (binding.decl.mutable && binding.decl.exported) {
			return nil
		}
		out := q.strings(m, binding.decl.value, depth+1)
		if assigned, again := m.assignedValues(binding.scope, name); binding.decl.mutable && again {
			for _, value := range assigned {
				if value != nil && !nodeAssignedLater(value, n) {
					out = appendNodeStrings(out, q.strings(m, value, depth+1)...)
				}
			}
		}
		return out
	}
	c := q.s.sites
	if c == nil {
		return nil
	}
	c.reads++
	if !c.enabled {
		return nil
	}
	param, ok := m.parameter(binding.param, name)
	if !ok || param.member != "" {
		return nil
	}
	at := nodeFunctionStart(m, binding.param)
	key := nodeParamKey{fn: at, name: name}
	if held, ok := c.strings[key]; ok {
		return held
	}
	if !q.enter(key) {
		return c.previousS[key]
	}
	sub := q.parameterQuery()
	out := sub.strings(m, param.value, 0)
	for _, site := range q.sites(at) {
		out = appendNodeStrings(out, sub.strings(site.m, site.argument(param.index), 0)...)
	}
	delete(q.active, key)
	if sub.cut {
		return out
	}
	c.strings[key] = out
	c.grew = c.grew || len(out) > len(c.previousS[key])
	return out
}

// loaded is what `require(x)` or `import(x)` yields when x is not written as
// a string: the modules the string constants x may hold name.
func (q *nodeValueQuery) loaded(m *nodeShapeModule, spec *sitter.Node, depth int) []nodeShapeValue {
	var out []nodeShapeValue
	for _, name := range q.strings(m, spec, depth+1) {
		if target := q.s.local(m, name); target != nil {
			out = appendNodeValues(out, q.moduleValues(target, depth+1)...)
			continue
		}
		out = appendNodeValues(out, nodeExternalValue(name)...)
	}
	return out
}

// nodeElementWrite is one `table[key] = value` of a module.
type nodeElementWrite struct {
	at, value *sitter.Node
}

// elementWrites indexes the assignments through a computed key by the text
// of the table they write: `this.senders[type] = new Web()` under
// `this.senders`.
func (m *nodeShapeModule) elementWrites() map[string][]nodeElementWrite {
	if m.elements != nil {
		return m.elements
	}
	m.elements = make(map[string][]nodeElementWrite)
	m.walk(func(n *sitter.Node) {
		if n.Type() != nodeAssignmentExpression {
			return
		}
		left, right := n.ChildByFieldName("left"), n.ChildByFieldName("right")
		if left == nil || right == nil || left.Type() != nodeSubscriptExpression {
			return
		}
		if _, _, named := nodeReadMember(left, m.src); named {
			return
		}
		if table := left.ChildByFieldName("object"); table != nil {
			text := table.Content(m.src)
			m.elements[text] = append(m.elements[text], nodeElementWrite{at: left, value: right})
		}
	})
	return m.elements
}

// nodeEnclosingClassBody is the class body around n, nil outside a class.
func nodeEnclosingClassBody(n *sitter.Node) *sitter.Node {
	for ; n != nil; n = n.Parent() {
		if n.Type() == nodeClassBody {
			return n
		}
	}
	return nil
}

// sameTable reports whether the table a computed write names is the one read
// at table, both spelled alike: a field of this in the same class or the
// same constructor function's module, a name the same scope declares, or a
// member path of such a name (`Encryption.algorithms`).
func (m *nodeShapeModule) sameTable(table, written *sitter.Node) bool {
	switch table.Type() {
	case goNodeIdentifier:
		scope := m.declaringScope(table, table.Content(m.src))
		return scope != nil && sameSyntaxNode(scope, m.declaringScope(written, table.Content(m.src)))
	case nodeMemberExpression:
		if nodeThisField(table, m.src) != "" {
			return sameOptionalNode(nodeEnclosingClassBody(table), nodeEnclosingClassBody(written))
		}
		head, writtenHead := nodeMemberPathHead(table), nodeMemberPathHead(written)
		return head != nil && writtenHead != nil && m.sameTable(head, writtenHead)
	}
	return false
}

// nodeMemberPathHead is the name a path of plain member reads starts at
// (`Encryption` for `Encryption.algorithms`), nil for any other expression.
func nodeMemberPathHead(n *sitter.Node) *sitter.Node {
	for n != nil && n.Type() == nodeMemberExpression {
		n = n.ChildByFieldName("object")
	}
	if n == nil || n.Type() != goNodeIdentifier {
		return nil
	}
	return n
}

// nodeComputedKey spells the key of `table[key]` as a member declared under
// a computed name is spelled, `[key]`, when the key is a name or a member
// path: `client[kResume]` reads the method `[kResume]() {..}`.
func nodeComputedKey(n *sitter.Node, src []byte) string {
	if n.Type() != nodeSubscriptExpression {
		return ""
	}
	index := n.ChildByFieldName("index")
	if index == nil || (index.Type() != goNodeIdentifier && index.Type() != nodeMemberExpression) {
		return ""
	}
	return "[" + index.Content(src) + "]"
}

// elementValues is what `table[key]` holds for a key only known at run
// time: any member the table is built with, and any value the module writes
// into it through a computed key.
func (q *nodeValueQuery) elementValues(m *nodeShapeModule, n *sitter.Node, depth int) []nodeShapeValue {
	table := n.ChildByFieldName("object")
	if table == nil {
		return nil
	}
	var out []nodeShapeValue
	tables := q.values(m, table, depth+1)
	if key := nodeComputedKey(n, m.src); key != "" {
		for _, held := range tables {
			out = appendNodeValues(out, q.member(held, key, depth+1)...)
		}
		if len(out) > 0 {
			return out // the member declared under that very key
		}
	}
	for _, held := range tables {
		if held.external != nil || held.module {
			continue // a namespace read by a run-time key names no one export
		}
		names := q.memberNames(held, depth+1)
		if len(names) > nodeTableMemberCap {
			continue
		}
		for _, name := range names {
			out = appendNodeValues(out, q.member(held, name, depth+1)...)
		}
	}
	writes := m.elementWrites()[table.Content(m.src)]
	if len(writes) > nodeElementWriteCap {
		return out
	}
	for _, write := range writes {
		if m.sameTable(table, write.at.ChildByFieldName("object")) {
			out = appendNodeValues(out, q.values(m, write.value, depth+1)...)
		}
	}
	return out
}
