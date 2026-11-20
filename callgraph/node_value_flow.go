// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	pathpkg "path"
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
	// pending lists the calls, constructions and loads whose callee the
	// first walk read a parameter for; see resolvePending.
	pending []nodePendingCall
	// recording is set during the first walk, which fills pending.
	recording bool
	// untyped holds the member calls the receiver's values named no function
	// for, by the caller's key; "" once a round resolved the call. See
	// node_untyped.go.
	untyped map[*FunctionCall]string
	// fieldCalls holds the resolved member calls whose receiver is a
	// property, and foreign the properties the package writes on another
	// object than this; see node_untyped.go.
	fieldCalls map[*FunctionCall]nodeFieldCall
	foreign    map[string]bool
}

// nodePendingCall is a call or `new` expression of the function fn whose
// callee depends on what a parameter holds.
type nodePendingCall struct {
	m  *nodeShapeModule
	n  *sitter.Node
	fn string
}

// nodeFlowRounds bounds how many times the calls left without a callee are
// read again: each round sees the call sites the round before recorded, so
// a value crosses one more function.
const nodeFlowRounds = 4

// linkNodeValueFlow adds the edges this file's comment lists to a Node graph.
// It returns the shapes it read, with the call sites it recorded, for the
// caller to close; nil for a graph of another ecosystem.
func (b *Builder) linkNodeValueFlow(graph *CallGraph) *NodeShapes {
	if b.ecosystem != ecosystemNode {
		return nil
	}
	f := &nodeValueFlow{
		b:          b,
		graph:      graph,
		shapes:     NewNodeShapes(),
		starts:     make(map[nodeDeclStart]string, len(graph.Functions)),
		clinits:    make(map[nodeDeclStart]string),
		callers:    make(map[string]map[string]bool),
		sites:      make(map[string]map[nodeCallSite]*FunctionCall),
		bindings:   make(map[*nodeShapeModule]nodeBindings),
		modules:    make(map[string]string),
		packages:   make(map[string]bool),
		untyped:    make(map[*FunctionCall]string),
		fieldCalls: make(map[*FunctionCall]nodeFieldCall),
		foreign:    make(map[string]bool),
	}
	f.shapes.sites = newNodeCallSites()
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
	f.addRequiredModules()
	files := make([]string, 0, len(f.modules))
	for file, module := range f.modules {
		files = append(files, file)
		f.packages[module] = true
	}
	sort.Strings(files)
	f.shapes.indexForeignWrites(files)
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
	f.recording = true
	for _, file := range files {
		if m := f.shapes.module(file); m != nil {
			f.walk(m, m.root, f.moduleKey(file))
		}
	}
	f.recording = false
	f.resolvePending()
	f.markUntyped()
	for _, key := range added {
		if len(graph.Functions[key].ImplicitCalls) == 0 {
			delete(graph.Functions, key)
			delete(graph.Callers, key)
		}
	}
	// The exports read with these shapes see every call site recorded.
	f.shapes.sites.round()
	f.shapes.sites.shared = true
	return f.shapes
}

// resolvePending reads again the calls whose callee the first walk read a
// parameter for, now that the call sites of each function are known: a
// callee that is a parameter, a member of one, or built from one holds what
// the function's callers pass (node_value_params.go). The first walk reads
// every parameter as holding nothing, so what one holds never depends on
// the order the files were walked in, and a call that read none has the
// edges it will ever have. A
// round that records no new call site, and in which no parameter held more
// than the round before, ends the rounds.
func (f *nodeValueFlow) resolvePending() {
	for round := 0; round < nodeFlowRounds && len(f.pending) > 0; round++ {
		f.shapes.sites.round()
		for _, p := range f.pending {
			if p.n.Type() == nodeNewExpression {
				f.constructed(p.m, p.n, p.fn)
				continue
			}
			f.callee(p.m, p.n, p.fn)
		}
		if f.shapes.sites.added == 0 && !f.shapes.sites.grew {
			break
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
	case nodeAssignmentExpression:
		f.noteWrite(m, n)
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

// invoke is reach for the callee of the call or `new` expression n: it also
// records n as a call site of each function of the package among values,
// for the function's parameters (node_value_params.go).
func (f *nodeValueFlow) invoke(m *nodeShapeModule, values []nodeShapeValue, n *sitter.Node, fn string, shift int) bool {
	called := values[:0:0]
	found := false
	for _, v := range values {
		if v.external == nil && v.callable() && !v.class() {
			f.shapes.sites.add(nodeFunctionStart(v.m, v.n), nodeCallRef{m: m, n: n, shift: shift})
		}
		if v.passed {
			// The caller that passed the function reaches it already.
			found = found || f.functionKey(v.m, v.n) != ""
			continue
		}
		if v.external != nil && len(v.external.steps) == 0 && !v.external.runtime {
			// Another package's module called as a function, under a name the
			// parser could not tie to its import (a parameter, a bound copy):
			// its default export, as the parser keys `require('m')(x)`.
			id := FunctionID{Package: v.external.module, Name: nodeDefaultKeyword}
			f.edge(fn, id.String(), id, n, n.Content(m.src))
			found = true
			continue
		}
		called = append(called, v)
	}
	return f.reach(m, called, n, fn) || found
}

// nodeCallSite is where a call expression is written.
type nodeCallSite struct {
	line, startCol, endCol int
}

// bound reports whether the parser, or a pass after it, already named the
// function the call at n runs: a function the graph declares, or one of
// another package (a call through an import, or on a receiver a contract
// typed). Such a call keeps the one target it has.
func (f *nodeValueFlow) bound(m *nodeShapeModule, n *sitter.Node, fn string) bool {
	call := f.parsedCall(n, fn)
	if call == nil {
		return false
	}
	if callee := f.graph.Functions[call.Callee.String()]; callee != nil {
		at := nodeDeclStart{file: filepath.Clean(callee.FilePath), line: callee.StartLine, col: callee.StartCol}
		f.shapes.sites.add(at, nodeCallRef{m: m, n: n})
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
	reads := f.shapes.sites.reads
	f.callee(m, call, fn)
	if f.recording && f.shapes.sites.reads != reads {
		f.pending = append(f.pending, nodePendingCall{m: m, n: call, fn: fn})
	}
}

// callee adds the edge from fn to what the call expression runs. It reports
// false for a call whose callee no value named, which resolvePending reads
// again.
func (f *nodeValueFlow) callee(m *nodeShapeModule, call *sitter.Node, fn string) bool {
	function, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
	if function == nil {
		return true
	}
	callee := unwrapNodeCallee(function)
	q := f.shapes.query()
	switch callee.Type() {
	case nodeFunctionExpression, nodeArrowFunction, nodeGeneratorFunction:
		// An immediately invoked function runs where it is written.
		if key := f.functionKey(m, callee); key != "" {
			f.shapes.sites.add(nodeFunctionStart(m, callee), nodeCallRef{m: m, n: call})
			f.edge(fn, key, f.graph.Functions[key].ID, call, "")
		}
		return true
	case goNodeIdentifier:
		if callee.Content(m.src) == nodeRequireFunction {
			return f.loads(m, q, call, args, fn)
		}
		// The name is resolved from where it is read even when the module
		// declares a function under the same key: a bundle's export getter
		// `sign: () => sign` is keyed sign too, and is not what `sign()` runs.
		return f.invoke(m, q.values(m, callee, 0), call, fn, 0)
	case "import":
		return f.loads(m, q, call, args, fn)
	case "super":
		found := false
		for _, class := range q.thisValues(m, callee, 0) {
			for _, base := range q.bases(class, 0) {
				found = f.invoke(m, q.constructors(base, 0, 0), call, fn, 0) || found
			}
		}
		return found
	case nodeMemberExpression, nodeSubscriptExpression:
		if nodeCallsThrough(callee, m.src) || !f.bound(m, call, fn) {
			found := f.memberCall(m, q, call, callee, fn)
			f.noteMemberCall(m, call, callee, fn, found)
			return found
		}
		return true
	}
	return f.invoke(m, q.values(m, callee, 0), call, fn, 0)
}

// loads adds the edge of a `require(x)` or `import(x)`: to the module the
// string names, or to each module a string constant x may hold names
// (`import(path)` in a function called with '@acme/push').
func (f *nodeValueFlow) loads(m *nodeShapeModule, q *nodeValueQuery, call, args *sitter.Node, fn string) bool {
	if args == nil || args.NamedChildCount() != 1 {
		return true
	}
	if spec := args.NamedChild(0); spec.Type() != nodeStringNode {
		specs := q.strings(m, spec, 0)
		for _, name := range specs {
			f.load(m, call, name, fn)
		}
		return len(specs) > 0
	}
	f.load(m, call, unquoteNodeString(args.NamedChild(0).Content(m.src)), fn)
	return true
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

// memberCall adds the edges of a call whose callee is a member of a value,
// and reports whether any value named the function called.
func (f *nodeValueFlow) memberCall(m *nodeShapeModule, q *nodeValueQuery, call, callee *sitter.Node, fn string) bool {
	object, name, named := nodeReadMember(callee, m.src)
	if object == nil {
		object = callee.ChildByFieldName("object")
	}
	if object == nil {
		return true
	}
	found := false
	if !named {
		// `table[key](..)` may run any function the object holds, and any
		// the module puts in it through a computed key. A member declared
		// under that very key (`[kResume]() {..}`) is the one it runs.
		tables := q.values(m, object, 0)
		if key := nodeComputedKey(callee, m.src); key != "" {
			declared := false
			for _, table := range tables {
				if values := q.member(table, key, 0); len(values) > 0 {
					declared = true
					found = f.invoke(m, values, call, fn, 0) || found
				}
			}
			if declared {
				return found
			}
		}
		for _, table := range tables {
			names := q.memberNames(table, 0)
			if len(names) > nodeTableMemberCap {
				continue
			}
			for _, member := range names {
				found = f.invoke(m, f.shapes.query().member(table, member, 0), call, fn, 0) || found
			}
		}
		if callee.Type() == nodeSubscriptExpression {
			found = f.invoke(m, f.shapes.query().elementValues(m, callee, 0), call, fn, 0) || found
		}
		return found
	}
	name = strings.TrimPrefix(name, "#")
	shift := 0
	if name == "bind" {
		shift = 1 // `f.bind(self, a)` passes a first; self is this
	}
	if nodeCallsThrough(callee, m.src) {
		if name != "call" {
			shift = nodeUnknownArguments // `f.apply(self, list)` spells no argument
		} else {
			shift = 1
		}
	}
	if f.invoke(m, q.calleeValues(m, callee, 0), call, fn, shift) {
		return true
	}
	if object.Type() == "super" {
		for _, class := range q.thisValues(m, object, 0) {
			for _, base := range q.bases(class, 0) {
				found = f.invoke(m, q.member(base, name, 0), call, fn, 0) || found
			}
		}
	}
	return found
}

// construct adds the edges of a `new` expression: to the constructor of a
// class or constructor function of the package, and to the functions its
// arguments hand over. A class of another package is keyed by the parser.
func (f *nodeValueFlow) construct(m *nodeShapeModule, n *sitter.Node, fn string) {
	if args := n.ChildByFieldName("arguments"); args != nil {
		nodeEachNamedChild(args, func(arg *sitter.Node) { f.handOver(m, arg, fn, nodeHandArgument) })
	}
	reads := f.shapes.sites.reads
	f.constructed(m, n, fn)
	if f.recording && f.shapes.sites.reads != reads {
		f.pending = append(f.pending, nodePendingCall{m: m, n: n, fn: fn})
	}
}

// constructed adds the edges from fn to what the `new` expression n runs.
// It reports false when no value named what is constructed.
func (f *nodeValueFlow) constructed(m *nodeShapeModule, n *sitter.Node, fn string) bool {
	q := f.shapes.query()
	instances := q.values(m, n, 0)
	for _, instance := range instances {
		if instance.external != nil {
			if !f.bound(m, n, fn) {
				// A class of another package the parser could not name: one
				// a parameter or a dynamic load holds.
				f.reach(m, []nodeShapeValue{instance}, n, fn)
			}
			continue
		}
		f.invoke(m, q.constructors(instance, 0, 0), n, fn, 0)
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
	return len(instances) > 0
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

// nodeRequiredModuleCap bounds the modules addRequiredModules adds.
const nodeRequiredModuleCap = 4096

// addRequiredModules adds to the modules the files the graph's modules load
// by a relative specifier and that declare no function, transitively: a
// module holding only data (`module.exports = { options: {} }`, node-forge's
// shared namespace that every other module writes its functions into) is
// still the receiver of the calls made through it, `forge.pkcs5.pbkdf2(..)`.
func (f *nodeValueFlow) addRequiredModules() {
	queue := make([]string, 0, len(f.modules))
	for file := range f.modules {
		queue = append(queue, file)
	}
	sort.Strings(queue)
	for len(queue) > 0 && len(f.modules) < nodeRequiredModuleCap {
		file := queue[0]
		queue = queue[1:]
		m := f.shapes.module(file)
		if m == nil {
			continue
		}
		module := f.modules[file]
		nodeWalk(m.root, func(n *sitter.Node) {
			spec := nodeRequireSource(n, m.src)
			if spec == "" && n.Type() == "import_statement" {
				if source := n.ChildByFieldName("source"); source != nil {
					spec = unquoteNodeString(source.Content(m.src))
				}
			}
			if !isNodeRelativeSpecifier(spec) {
				return
			}
			target := f.shapes.relative(m, spec)
			if target == nil {
				return
			}
			path := filepath.Clean(target.path)
			if _, known := f.modules[path]; known {
				return
			}
			dir := pathpkg.Dir(module)
			if rel, err := filepath.Rel(filepath.Dir(filepath.Clean(m.path)), filepath.Dir(path)); err == nil {
				dir = pathpkg.Join(dir, filepath.ToSlash(rel))
			}
			f.modules[path] = nodeModulePath(dir, path)
			queue = append(queue, path)
		})
	}
}
