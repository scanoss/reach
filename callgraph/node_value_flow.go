// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"
	"sort"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// node_value_flow.go draws the Node call edges that only following a value
// finds. The parser keys a call by its text: a call through an import, a
// call on `this` in a class, a call on a variable whose class the source
// declares. Every other call it leaves unbound, and code reached only
// through one read unreachable. This pass walks each file again with the
// value shapes of its package (node_value_shapes.go) and adds an edge for:
//
//   - a call whose callee is a value the source builds: a method of the
//     object a factory returned, of an instance held in a variable or a field
//     of this, of the object a function is assigned to (`this.gen()` in
//     `hotp.verify = function`), a function held in a variable, an immediately
//     invoked function, and `f.call`, `f.apply`, `f.bind` of any of them;
//   - a call whose callee comes from another package through calls and
//     constructions (`new fc.Totp().validate()`, `fc.client().getKey()`),
//     keyed by its access (nodeAccessKey) for the package's exports to join;
//   - a `new` of a class or constructor function of the package, to its
//     constructor, and `super(..)` to the base's;
//   - a call through a computed member of an object (`signers[alg](..)`): it
//     may run any function the object holds, so it reaches each;
//   - a function handed over as a value: whoever receives it may call it,
//     so the function that hands it over reaches it. As a call argument that
//     is a function named or written inline, alone or in an object or array
//     literal (`promisify(client.getKey)`, `emitter.on('x', onX)`,
//     `pipeline({ func: function () {} })`); as a returned value only a
//     function written inline (`return function sign() {}`, `return { run()
//     {} }`), since returning a function that has a name calls nothing, and
//     not from an immediately invoked function, whose one result the shapes
//     follow to its uses;
//   - a module loaded by a function (`require` or `import()` in its body),
//     and a package loaded by a module or a function, to the module's
//     top-level code.
//
// A call on a receiver the source says nothing about (a parameter, a
// property of one) gets no edge: a method name alone names no function.
//
// No call the parser recorded changes: its key, its arguments and its site
// stay as they were, and what matches a call by its position sees the same
// calls. The edges are added beside them, as references are
// (FunctionCall.Reference).

// nodeTableMemberCap bounds the functions a computed member call reaches.
const nodeTableMemberCap = 64

// nodeValueFlow is the state of one linkNodeValueFlow pass.
type nodeValueFlow struct {
	b      *Builder
	graph  *CallGraph
	shapes *NodeShapes
	// starts maps the start of each function's node to its key, and clinits
	// the start of each class body with field initialisers to its <clinit>.
	starts  map[nodeDeclStart]string
	clinits map[nodeDeclStart]string
	// callers holds the caller set of each callee the pass has touched.
	callers map[string]map[string]bool
	// sites indexes, per function, the calls the parser recorded by where
	// they are written.
	sites map[string]map[nodeCallSite]*FunctionCall
	// bindings holds the import bindings of each module, for route
	// registrations.
	bindings map[*nodeShapeModule]nodeBindings
	// modules maps a file to its module path, and packages holds each
	// module path and each member path under one that a callee names.
	modules  map[string]string
	packages map[string]bool
}

// linkNodeValueFlow adds the edges this file's comment lists to a Node graph.
func (b *Builder) linkNodeValueFlow(graph *CallGraph) {
	if b.ecosystem != ecosystemNode {
		return
	}
	f := &nodeValueFlow{
		b:        b,
		graph:    graph,
		shapes:   NewNodeShapes(),
		starts:   make(map[nodeDeclStart]string, len(graph.Functions)),
		clinits:  make(map[nodeDeclStart]string),
		callers:  make(map[string]map[string]bool),
		sites:    make(map[string]map[nodeCallSite]*FunctionCall),
		bindings: make(map[*nodeShapeModule]nodeBindings),
		modules:  make(map[string]string),
		packages: make(map[string]bool),
	}
	defer f.shapes.Close()
	for key, decl := range graph.Functions {
		file := filepath.Clean(decl.FilePath)
		if decl.FunctionType == functionTypeModuleInit {
			f.modules[file] = decl.ID.Package
			continue
		}
		if decl.ID.Name == clinitMethodName {
			f.clinits[nodeDeclStart{file: file, line: decl.StartLine, col: decl.StartCol}] = key
			continue
		}
		f.starts[nodeDeclStart{file: file, line: decl.StartLine, col: decl.StartCol}] = key
		if _, ok := f.modules[file]; !ok {
			f.modules[file] = decl.ID.Package
		}
	}
	files := make([]string, 0, len(f.modules))
	for file, module := range f.modules {
		files = append(files, file)
		f.packages[module] = true
	}
	for _, decl := range graph.Functions {
		for i := range decl.Calls {
			// `mod.a.b()` is keyed with package `<module>.a`.
			pkg := decl.Calls[i].Callee.Package
			for cut := pkg; cut != "" && !f.packages[pkg]; {
				dot := strings.LastIndex(cut, ".")
				if dot < 0 {
					break
				}
				cut = cut[:dot]
				if f.packages[cut] {
					f.packages[pkg] = true
				}
			}
		}
	}
	sort.Strings(files)
	// A module that makes no call at its top level has no <module> function
	// yet. Each gets one for the walk, and keeps it when its top level
	// loads a package or runs a function this pass follows.
	var added []string
	for _, file := range files {
		m := f.shapes.module(file)
		if m == nil || f.moduleKey(file) != "" {
			continue
		}
		decl := &FunctionDecl{
			ID:           FunctionID{Package: f.modules[file], Name: moduleInitMethodName},
			FilePath:     m.path,
			StartLine:    int(m.root.StartPoint().Row) + 1,
			EndLine:      int(m.root.EndPoint().Row) + 1,
			StartCol:     int(m.root.StartPoint().Column) + 1,
			EndCol:       int(m.root.EndPoint().Column) + 1,
			OwnerType:    "module",
			OwnerName:    f.modules[file],
			FunctionType: functionTypeModuleInit,
		}
		graph.Functions[decl.ID.String()] = decl
		added = append(added, decl.ID.String())
	}
	for _, file := range files {
		if m := f.shapes.module(file); m != nil {
			f.walk(m, m.root, f.moduleKey(file))
		}
	}
	for _, key := range added {
		if len(graph.Functions[key].ImplicitCalls) == 0 {
			delete(graph.Functions, key)
			delete(graph.Callers, key)
		}
	}
}

// moduleKey is the key of a file's <module> function, "" when the file
// declares none.
func (f *nodeValueFlow) moduleKey(file string) string {
	module, ok := f.modules[filepath.Clean(file)]
	if !ok {
		return ""
	}
	key := FunctionID{Package: module, Name: moduleInitMethodName}.String()
	if f.graph.Functions[key] == nil {
		return ""
	}
	return key
}

// functionKey is the key of the function whose node is n, "" when the graph
// holds none there.
func (f *nodeValueFlow) functionKey(m *nodeShapeModule, n *sitter.Node) string {
	return f.starts[nodeDeclStart{file: filepath.Clean(m.path), line: nodeLine(n), col: int(n.StartPoint().Column) + 1}]
}

// isNodeFunctionNode reports a node that is a function of its own in the
// graph.
func isNodeFunctionNode(n *sitter.Node) bool {
	switch n.Type() {
	case nodeFunctionDeclaration, nodeGeneratorDeclaration, nodeFunctionExpression, nodeArrowFunction, nodeMethodDefinition, nodeGeneratorFunction:
		return true
	}
	return false
}

// walk visits the nodes under n, a part of the body of the function fn.
func (f *nodeValueFlow) walk(m *nodeShapeModule, n *sitter.Node, fn string) {
	if isNodeFunctionNode(n) {
		if key := f.functionKey(m, n); key != "" {
			fn = key
		}
		if body := n.ChildByFieldName("body"); body != nil && body.Type() != nodeStatementBlock && n.Type() == nodeArrowFunction && !nodeImmediatelyInvoked(n) {
			f.handOver(m, body, fn, nodeHandReturn) // an arrow function's expression is what it returns
		}
	}
	switch n.Type() {
	case nodeCallExpression:
		f.call(m, n, fn)
	case nodeNewExpression:
		f.construct(m, n, fn)
	case nodeReturnStatement:
		if n.NamedChildCount() > 0 && !nodeImmediatelyInvoked(nodeEnclosingFunction(n)) {
			f.handOver(m, n.NamedChild(0), fn, nodeHandReturn)
		}
	case nodeImportStatement, nodeExportKind:
		if source := n.ChildByFieldName("source"); source != nil {
			collector := &nodeModuleImportCollector{root: m.root, typescript: nodeIsTypeScriptFile(m.path), src: m.src}
			if !nodeIsTypeOnlyModuleStatement(n) && !collector.erased(n) {
				f.load(m, n, unquoteNodeString(source.Content(m.src)), fn)
			}
			return
		}
	case nodeClassBody:
		// A field's initialiser runs in the class's <clinit>.
		clinit := f.clinits[nodeDeclStart{file: filepath.Clean(m.path), line: nodeLine(n), col: int(n.StartPoint().Column) + 1}]
		nodeEachNamedChild(n, func(member *sitter.Node) {
			if clinit != "" && (member.Type() == nodeFieldDefinition || member.Type() == nodePublicFieldDefinition) {
				f.walk(m, member, clinit)
				return
			}
			f.walk(m, member, fn)
		})
		return
	case goNodeComment, nodeStringNode, "regex", "number":
		return
	}
	nodeEachNamedChild(n, func(child *sitter.Node) { f.walk(m, child, fn) })
}

// nodeImmediatelyInvoked reports a function written as the callee of the
// call around it, `(function () {..})()`. What it returns goes to that one
// call, whose value the shapes follow wherever it is used, so its returned
// functions are reached by whoever calls them and not by the call itself.
func nodeImmediatelyInvoked(fn *sitter.Node) bool {
	if fn == nil {
		return false
	}
	holder := fn.Parent()
	for holder != nil && holder.Type() == goNodeParenExpr {
		holder = holder.Parent()
	}
	if holder == nil || holder.Type() != nodeCallExpression {
		return false
	}
	callee := holder.ChildByFieldName("function")
	return callee != nil && sameSyntaxNode(unwrapNodeCallee(callee), fn)
}

// edge adds an edge from caller to callee at n, unless one is there.
func (f *nodeValueFlow) edge(caller, callee string, id FunctionID, n *sitter.Node, raw string) {
	if caller == "" || callee == "" || caller == callee {
		return
	}
	decl := f.graph.Functions[caller]
	if decl == nil {
		return
	}
	set := f.callers[callee]
	if set == nil {
		existing := f.graph.Callers[callee]
		set = make(map[string]bool, len(existing)+1)
		for _, key := range existing {
			set[key] = true
		}
		f.callers[callee] = set
	}
	if set[caller] {
		return
	}
	set[caller] = true
	f.graph.Callers[callee] = append(f.graph.Callers[callee], caller)
	site := FunctionCall{
		FilePath: decl.FilePath,
		Line:     nodeLine(n),
		StartCol: int(n.StartPoint().Column) + 1,
		EndCol:   int(n.EndPoint().Column) + 1,
	}
	if len(raw) > 120 {
		raw = raw[:120]
	}
	decl.ImplicitCalls = append(decl.ImplicitCalls, *callbackReference(&site, id, raw))
	recordEdgeResolution(f.graph, caller, callee, EdgeKindExact, "", site.Line, site.StartCol, site.EndCol)
}

// reach adds an edge from fn to each function among values: a function the
// build declares, and a function of another package, by its access key.
// It reports whether any value named a function.
func (f *nodeValueFlow) reach(m *nodeShapeModule, values []nodeShapeValue, n *sitter.Node, fn string) bool {
	found := false
	for _, v := range values {
		switch {
		case v.external != nil:
			if len(v.external.steps) == 0 || v.external.runtime {
				continue // the module itself: a call of it is keyed by the parser
			}
			if id, ok := v.external.key(); ok {
				f.edge(fn, id.String(), id, n, n.Content(m.src))
				found = true
			}
		case v.callable() && !v.class():
			if key := f.functionKey(v.m, v.n); key != "" {
				f.edge(fn, key, f.graph.Functions[key].ID, n, n.Content(m.src))
				found = true
			}
		}
	}
	return found
}

// nodeCallSite is where a call expression is written.
type nodeCallSite struct {
	line, startCol, endCol int
}

// bound reports whether the parser, or a pass after it, already named the
// function the call at n runs: a function the graph declares, or one of
// another package (a call through an import, or on a receiver a contract
// typed). Such a call keeps the one target it has.
func (f *nodeValueFlow) bound(n *sitter.Node, fn string) bool {
	decl := f.graph.Functions[fn]
	if decl == nil {
		return false
	}
	sites := f.sites[fn]
	if sites == nil {
		sites = make(map[nodeCallSite]*FunctionCall, len(decl.Calls))
		for i := range decl.Calls {
			call := &decl.Calls[i]
			sites[nodeCallSite{call.Line, call.StartCol, call.EndCol}] = call
		}
		f.sites[fn] = sites
	}
	call := sites[nodeCallSite{nodeLine(n), int(n.StartPoint().Column) + 1, int(n.EndPoint().Column) + 1}]
	if call == nil {
		return false
	}
	if f.graph.Functions[call.Callee.String()] != nil {
		return true
	}
	if call.nodeUnboundMember && call.Callee.Type == "" {
		return false
	}
	// A key that names a module of the build and no function of it is a
	// method the class only inherits, or a member the module builds some
	// other way: the value shapes may still find it.
	return !f.packages[call.Callee.Package]
}

// call adds the edges of one call expression.
func (f *nodeValueFlow) call(m *nodeShapeModule, call *sitter.Node, fn string) {
	function, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if function == nil {
		return
	}
	callee := unwrapNodeCallee(function)
	if args != nil && !nodeTakesNoCallback(callee, m.src) && !f.registersRoute(m, call) {
		nodeEachNamedChild(args, func(arg *sitter.Node) { f.handOver(m, arg, fn, nodeHandArgument) })
	}
	q := f.shapes.query()
	switch callee.Type() {
	case nodeFunctionExpression, nodeArrowFunction, nodeGeneratorFunction:
		// An immediately invoked function runs where it is written.
		if key := f.functionKey(m, callee); key != "" {
			f.edge(fn, key, f.graph.Functions[key].ID, call, "")
		}
	case goNodeIdentifier:
		name := callee.Content(m.src)
		if name == nodeRequireFunction {
			if args != nil && args.NamedChildCount() == 1 && args.NamedChild(0).Type() == nodeStringNode {
				f.load(m, call, unquoteNodeString(args.NamedChild(0).Content(m.src)), fn)
			}
			return
		}
		// The name is resolved from where it is read even when the module
		// declares a function under the same key: a bundle's export getter
		// `sign: () => sign` is keyed sign too, and is not what `sign()` runs.
		f.reach(m, q.values(m, callee, 0), call, fn)
	case "import":
		if args != nil && args.NamedChildCount() == 1 && args.NamedChild(0).Type() == nodeStringNode {
			f.load(m, call, unquoteNodeString(args.NamedChild(0).Content(m.src)), fn)
		}
	case "super":
		for _, class := range q.thisValues(m, callee, 0) {
			for _, base := range q.bases(class, 0) {
				f.reach(m, q.constructors(base, 0, 0), call, fn)
			}
		}
	case nodeMemberExpression, nodeSubscriptExpression:
		if nodeCallsThrough(callee, m.src) || !f.bound(call, fn) {
			f.memberCall(m, q, call, callee, fn)
		}
	default:
		f.reach(m, q.values(m, callee, 0), call, fn)
	}
}

// nodeCallsThrough reports `f.call(..)` and `f.apply(..)`: the function
// that runs is f, whatever the call is keyed as.
func nodeCallsThrough(callee *sitter.Node, src []byte) bool {
	if callee.Type() != nodeMemberExpression {
		return false
	}
	property := callee.ChildByFieldName("property")
	return property != nil && (property.Content(src) == "call" || property.Content(src) == "apply")
}

// memberCall adds the edges of a call whose callee is a member of a value.
func (f *nodeValueFlow) memberCall(m *nodeShapeModule, q *nodeValueQuery, call, callee *sitter.Node, fn string) {
	object, name, named := nodeReadMember(callee, m.src)
	if object == nil {
		object = callee.ChildByFieldName("object")
	}
	if object == nil {
		return
	}
	if !named {
		// `table[key](..)` may run any function the object holds.
		for _, table := range q.values(m, object, 0) {
			names := q.memberNames(table, 0)
			if len(names) > nodeTableMemberCap {
				continue
			}
			for _, member := range names {
				f.reach(m, f.shapes.query().member(table, member, 0), call, fn)
			}
		}
		return
	}
	name = strings.TrimPrefix(name, "#")
	if f.reach(m, q.calleeValues(m, callee, 0), call, fn) {
		return
	}
	if object.Type() == "super" {
		for _, class := range q.thisValues(m, object, 0) {
			for _, base := range q.bases(class, 0) {
				f.reach(m, q.member(base, name, 0), call, fn)
			}
		}
		return
	}
}

// construct adds the edges of a `new` expression: to the constructor of a
// class or constructor function of the package, and to the functions its
// arguments hand over. A class of another package is keyed by the parser.
func (f *nodeValueFlow) construct(m *nodeShapeModule, n *sitter.Node, fn string) {
	if args := n.ChildByFieldName("arguments"); args != nil {
		nodeEachNamedChild(args, func(arg *sitter.Node) { f.handOver(m, arg, fn, nodeHandArgument) })
	}
	q := f.shapes.query()
	for _, instance := range q.values(m, n, 0) {
		if instance.external != nil {
			continue
		}
		f.reach(m, q.constructors(instance, 0, 0), n, fn)
		if instance.class() {
			// The class's field initialisers run with its constructor.
			if body := instance.n.ChildByFieldName("body"); body != nil {
				at := nodeDeclStart{file: filepath.Clean(instance.m.path), line: nodeLine(body), col: int(body.StartPoint().Column) + 1}
				if key := f.clinits[at]; key != "" {
					f.edge(fn, key, f.graph.Functions[key].ID, n, "")
				}
			}
		}
	}
}

// nodeHandOver says how an expression hands a function over.
type nodeHandOver int

const (
	// nodeHandArgument is a call argument: whoever is called may call it.
	nodeHandArgument nodeHandOver = iota
	// nodeHandReturn is a returned value: only a function the expression
	// itself creates counts. A function it merely names (`return verify`, a
	// re-export getter's `return impl.sign`) is reached by whoever calls
	// what comes back, not by returning it.
	nodeHandReturn
)

// handOver adds an edge from fn to each function the expression hands to
// whoever receives its value: a function it writes inline, alone or in an
// object or array literal, and, for an argument, a function it names
// (`on('x', onX)`, `promisify(client.getKey)`, `sign.bind(null, k)`).
func (f *nodeValueFlow) handOver(m *nodeShapeModule, expr *sitter.Node, fn string, how nodeHandOver) {
	f.handOverAt(m, expr, fn, how, 0)
}

func (f *nodeValueFlow) handOverAt(m *nodeShapeModule, expr *sitter.Node, fn string, how nodeHandOver, depth int) {
	expr = nodeUnwrapValue(expr)
	if expr == nil || depth > 3 {
		return
	}
	switch expr.Type() {
	case nodeFunctionExpression, nodeArrowFunction, nodeGeneratorFunction:
		if key := f.functionKey(m, expr); key != "" {
			f.edge(fn, key, f.graph.Functions[key].ID, expr, "")
		}
		return
	case "array", nodeSpreadElement:
		nodeEachNamedChild(expr, func(item *sitter.Node) { f.handOverAt(m, item, fn, how, depth+1) })
		return
	case nodeObjectLiteral:
		nodeEachNamedChild(expr, func(member *sitter.Node) {
			switch member.Type() {
			case nodeMethodDefinition:
				if key := f.functionKey(m, member); key != "" {
					f.edge(fn, key, f.graph.Functions[key].ID, member, "")
				}
			case nodePair:
				f.handOverAt(m, member.ChildByFieldName("value"), fn, how, depth+1)
			case nodeShorthandProperty, nodeSpreadElement:
				f.handOverAt(m, member, fn, how, depth+1)
			}
		})
		return
	case "ternary_expression":
		f.handOverAt(m, expr.ChildByFieldName("consequence"), fn, how, depth+1)
		f.handOverAt(m, expr.ChildByFieldName("alternative"), fn, how, depth+1)
		return
	case goNodeIdentifier, nodeShorthandProperty, nodeMemberExpression, nodeSubscriptExpression, nodeCallExpression:
		if how != nodeHandArgument {
			return
		}
	default:
		return
	}
	q := f.shapes.query()
	q.budget = nodeValueBudget / 8
	if expr.Type() == nodeCallExpression {
		// Only `f.bind(..)` hands a function over; any other call hands
		// over its result, which is not followed.
		callee := unwrapNodeCallee(expr.ChildByFieldName("function"))
		if callee == nil || callee.Type() != nodeMemberExpression {
			return
		}
		if property := callee.ChildByFieldName("property"); property == nil || property.Content(m.src) != "bind" {
			return
		}
		f.reach(m, q.values(m, callee.ChildByFieldName("object"), 0), expr, fn)
		return
	}
	f.reach(m, q.values(m, expr, 0), expr, fn)
}

// registersRoute reports a call that registers a route handler
// (`app.get('/x', handler)`), or a wrapper call written as one's argument
// (`app.get('/x', wrap(handler))`). The router calls the handler: it is an
// entry point (nodeEntryRefs), not something the registering code reaches.
func (f *nodeValueFlow) registersRoute(m *nodeShapeModule, call *sitter.Node) bool {
	bindings := f.bindings[m]
	if bindings == nil {
		bindings = make(nodeBindings)
		extractNodeImports(m.root, m.src, bindings)
		f.bindings[m] = bindings
	}
	if _, route := nodeRouteRegistration(call, m.src, bindings); route {
		return true
	}
	if outer := call.Parent(); outer != nil && outer.Type() == nodeArgumentsNode && outer.Parent() != nil {
		_, route := nodeRouteRegistration(outer.Parent(), m.src, bindings)
		return route
	}
	return false
}

// nodeTakesNoCallback reports a callee that is given functions and classes
// without ever calling them: the property and prototype helpers of the
// runtime (`Object.defineProperty(exports, 'x', { get })`,
// `Object.setPrototypeOf`, `Reflect.*`) and `inherits(Sub, Base)`.
func nodeTakesNoCallback(callee *sitter.Node, src []byte) bool {
	switch callee.Type() {
	case goNodeIdentifier:
		return callee.Content(src) == "inherits"
	case nodeMemberExpression:
		object, property := callee.ChildByFieldName("object"), callee.ChildByFieldName("property")
		if object == nil || property == nil {
			return false
		}
		switch object.Content(src) {
		case "Object", "Reflect":
			return true
		}
		return property.Content(src) == "inherits"
	}
	return false
}

// load adds an edge from fn to the top-level code of the module spec names:
// a module of the build by its <module> function, a package by the key its
// exports give its entry module's.
func (f *nodeValueFlow) load(m *nodeShapeModule, n *sitter.Node, spec string, fn string) {
	if spec == "" {
		return
	}
	if target := f.shapes.local(m, spec); target != nil {
		if key := f.moduleKey(target.path); key != "" {
			f.edge(fn, key, f.graph.Functions[key].ID, n, moduleInitMethodName)
		}
		return
	}
	if external := nodeExternalValue(spec); len(external) == 0 || external[0].external.runtime {
		return
	}
	id := FunctionID{Package: spec, Name: moduleInitMethodName}
	f.edge(fn, id.String(), id, n, moduleInitMethodName)
}
