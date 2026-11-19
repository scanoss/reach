// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// node_untyped.go tells the member calls of a Node graph that nothing typed:
//
//	function emit(sink, d) { return sink.write(d); }     // sink: what a caller outside the package passes
//	run() { return this.cipher.update(this.block); }     // this.cipher: assigned from a value no source builds
//	finish() { return this.compute(); }                  // compute: declared by no class this one extends
//
// The parser keys such a call in the caller's module (`app/m.write`), or by
// the bare name when the module declares a function of that name, a key no
// function has. The value flow then follows the receiver; when no value it
// holds names the method, which function runs depends on a value the source
// does not show. The call is then a name_only one (EdgeKindNameOnly), never
// an exact call of a function that does not exist: a consumer matches it by
// method name and reads what it may reach as unknown, never unreachable.
//
// A call the value flow did resolve is a name_only one too, beside the edges
// it has, when its receiver is a property the package also writes on another
// object than this (`this._cipher.allocPacket(n)` in a class whose
// constructor sets a null cipher, with `this._protocol._cipher =
// createCipher(c)` in another module): the values followed are those the
// receiver's own class assigns, and the write through the other object puts
// there a value they do not include.
//
// Only a call whose receiver is a value of the program is one: a call on a
// global the language defines (`JSON.parse`, `Object.keys(o).map`), on a
// literal (`'a,b'.split(',')`), through `call` or `apply`, or under a
// computed key names no method a value of the program could declare, or no
// name at all.

// NodeCallUntyped reports whether nothing typed the Node member call: the
// parser bound it to no import, class or contract, and the value flow found
// no function its receiver's values name.
func NodeCallUntyped(call *FunctionCall) bool {
	return call != nil && call.nodeUnresolved
}

// nodeStandardGlobals are the objects ECMAScript, Node and the browser
// define in every module. A member call on one that the module does not
// declare itself runs the platform's code.
var nodeStandardGlobals = func() map[string]bool {
	out := make(map[string]bool)
	for _, name := range []string{
		"Object", "Function", "Array", "String", "Number", "Boolean", "Symbol", "BigInt", "Math", "JSON", "Reflect",
		"Proxy", "Promise", "Date", "RegExp", "Error", "TypeError", "RangeError", "SyntaxError", "ReferenceError",
		"EvalError", "URIError", "AggregateError", "Map", "Set", "WeakMap", "WeakSet", "WeakRef", "ArrayBuffer",
		"SharedArrayBuffer", "DataView", "Int8Array", "Uint8Array", "Uint8ClampedArray", "Int16Array", "Uint16Array",
		"Int32Array", "Uint32Array", "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array", "Atomics",
		"Intl", "Iterator", "globalThis", "global", "window", "self", "document", "navigator", "console", "process",
		"Buffer", "URL", "URLSearchParams", "TextEncoder", "TextDecoder", "AbortController", "AbortSignal",
		"performance", "module", "exports", "require", "arguments",
	} {
		out[name] = true
	}
	return out
}()

// nodeProgramValue reports whether the receiver of a member call, object, is
// a value of the program: its chain starts at a name the module declares or
// receives, at this, or at an expression that yields one. A chain that
// starts at a literal or at a global the module does not declare is the
// platform's.
func nodeProgramValue(m *nodeShapeModule, object *sitter.Node) bool {
	head := nodeMemberChainHead(object)
	if head == nil {
		return false
	}
	switch head.Type() {
	case goNodeIdentifier:
		if _, declared := m.nameBinding(head); declared {
			return true
		}
		return !nodeStandardGlobals[head.Content(m.src)]
	case nodeStringNode, nodeTemplateString, "array", "regex", "number", nodeObjectLiteral, "true", "false", "null", "undefined",
		nodeFunctionExpression, nodeArrowFunction, nodeGeneratorFunction, "class":
		return false
	}
	return true
}

// parsedCall is the call the parser recorded for the call expression n of
// the function fn, nil when it recorded none there.
func (f *nodeValueFlow) parsedCall(n *sitter.Node, fn string) *FunctionCall {
	decl := f.graph.Functions[fn]
	if decl == nil {
		return nil
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
	return sites[nodeCallSite{nodeLine(n), int(n.StartPoint().Column) + 1, int(n.EndPoint().Column) + 1}]
}

// noteMemberCall records whether the values of the receiver named the
// function the member call at n runs. A call some round resolved stays
// resolved: the rounds only add edges.
func (f *nodeValueFlow) noteMemberCall(m *nodeShapeModule, n, callee *sitter.Node, fn string, found bool) {
	call := f.parsedCall(n, fn)
	if call == nil {
		return
	}
	if at, noted := f.untyped[call]; noted && (at == "" || !found) {
		return
	}
	object, _, named := nodeReadMember(callee, m.src)
	if !named || object == nil || nodeCallsThrough(callee, m.src) || !nodeProgramValue(m, object) {
		return
	}
	if f.graph.Functions[call.Callee.String()] != nil || (call.Callee.Package != "" && !f.packages[call.Callee.Package]) {
		return // a function of the graph, or of another package
	}
	if !found {
		f.untyped[call] = fn
		return
	}
	f.untyped[call] = ""
	if field := nodeWrittenProperty(object, m.src); field != "" && nodeThisField(object, m.src) != "" {
		f.fieldCalls[call] = nodeFieldCall{fn: fn, field: field}
	}
}

// nodeFieldCall is a resolved member call whose receiver is the property
// field of some object, made by the function fn.
type nodeFieldCall struct {
	fn, field string
}

// nodeWrittenProperty names the property a member expression reads or
// writes by a plain name (`_cipher` of `this._protocol._cipher`), "" for
// any other expression.
func nodeWrittenProperty(n *sitter.Node, src []byte) string {
	if n == nil || n.Type() != nodeMemberExpression {
		return ""
	}
	property := n.ChildByFieldName("property")
	if property == nil || property.Type() != nodePropertyIdentifier {
		return ""
	}
	return property.Content(src)
}

// noteWrite records the property an assignment writes on another object
// than this.
func (f *nodeValueFlow) noteWrite(m *nodeShapeModule, assignment *sitter.Node) {
	left := assignment.ChildByFieldName("left")
	if left == nil || left.Type() != nodeMemberExpression {
		return
	}
	if object := left.ChildByFieldName("object"); object == nil || object.Type() == nodeThisNode {
		return
	}
	if field := nodeWrittenProperty(left, m.src); field != "" {
		f.foreign[field] = true
	}
}

// markUntyped turns each member call the value flow left without a callee
// into a name_only call of its key.
func (f *nodeValueFlow) markUntyped() {
	for call, at := range f.fieldCalls {
		if f.foreign[at.field] {
			f.untyped[call] = at.fn
		}
	}
	for call, fn := range f.untyped {
		if fn == "" {
			continue
		}
		call.nodeUnresolved = true
		calleeKey := call.Callee.String()
		key := EdgeResolutionKey(fn, calleeKey, EdgeResolution{
			MethodName: BaseFunctionName(call.Callee.Name), Arity: functionArity(call.Callee.Name),
			CallSite: call.Line, StartCol: call.StartCol, EndCol: call.EndCol,
		})
		if res, ok := f.graph.EdgeResolutions[key]; ok && res.Kind == EdgeKindExact {
			res.Kind = EdgeKindNameOnly
			f.graph.EdgeResolutions[key] = res
		}
	}
}
