// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

// PythonCallUntyped reports whether nothing typed a Python call's target: a
// method on a receiver the parser could only key by its source text
// (`sink.write(..)` on a parameter, `self.hasher.update(..)`,
// `make().run(..)`) and no pass typed later, or a call of a value bound in
// the caller's scope (`fn(data)`). Such a call names no declaration; which
// function it reaches depends on the value at run time (duck typing), so it
// is resolved by method name only, never as an exact target.
//
// A receiver that names a class the graph declares (`Base.create()` in
// Base's module, `Outer.Inner.make()`) is a class object, not a value: the
// call is typed.
func PythonCallUntyped(graph *CallGraph, call *FunctionCall) bool {
	if call == nil || call.pythonUntyped == "" || call.Callee.String() != call.pythonUntyped {
		return false
	}
	if call.Callee.Type == "" {
		return true
	}
	_, isClass := graph.SourceSupertypes[call.Callee.Package+"."+call.Callee.Type]
	return !isClass
}
