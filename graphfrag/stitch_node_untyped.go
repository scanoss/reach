// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "strings"

// stitch_node_untyped.go gives a Node component's name_only calls their
// candidates. The producer marks a member call name_only when nothing typed
// its receiver (`sink.write(d)` on a parameter no caller it sees fills,
// `this.cipher.update(b)` on a field assigned from such a value): the
// function that runs depends on a value the source does not show. Its
// candidates are the functions of the called name in the component itself
// and in scope (the declared dependencies, or the whole closure under
// EnvironmentTargets). The edge stays name_only, so it never proves a
// finding reachable: a finding the root reaches only across one reads
// unknown (unresolved_dispatch), where it read unreachable.
//
// A method name of an ECMAScript built-in value (`push`, `slice`, `then`,
// `get`) has candidates in the component itself only. A value of another
// package is typed by the access it comes from (`dep.make().get()` is an
// exact call of `dep.(make()).get`), so what is left untyped under such a
// name is, nearly always, an array, a string, a map or a promise.
func nodeNameOnlyCandidates(resolve edgeResolver, self ComponentKey, byMethodArity map[string][]graphNode, scope map[ComponentKey]bool) edgeResolver {
	return func(e callEdge) edgeTargets {
		if e.resolution != ResolutionNameOnly || e.method == "" {
			return resolve(e)
		}
		others := !nodeBuiltinMethods[e.method]
		var targets edgeTargets
		for _, callee := range byMethodArity[arityFreeMethodKey(e.method)] {
			if callee.Component == self || (others && scope[callee.Component]) {
				targets.nodes = append(targets.nodes, callee)
			}
		}
		return targets
	}
}

// nodeBuiltinMethods are the methods of ECMAScript's built-in values:
// Object, Function, Array, String, Number, BigInt, Symbol, Map, Set, WeakMap,
// WeakSet, Promise, RegExp, Date, Error, ArrayBuffer, the typed arrays,
// DataView and the iterator protocol (ECMAScript 2024; Date's and DataView's
// accessors are spelled as families below).
var nodeBuiltinMethods = func() map[string]bool {
	out := make(map[string]bool)
	for _, m := range strings.Fields(`hasOwnProperty isPrototypeOf propertyIsEnumerable toLocaleString toString valueOf
		apply bind call
		at concat copyWithin entries every fill filter find findIndex findLast findLastIndex flat flatMap forEach
		includes indexOf join keys lastIndexOf map pop push reduce reduceRight reverse shift slice some sort splice
		toReversed toSorted toSpliced unshift values with
		anchor big blink bold charAt charCodeAt codePointAt endsWith fixed fontcolor fontsize isWellFormed italics
		link localeCompare match matchAll normalize padEnd padStart repeat replace replaceAll search small split
		startsWith strike sub substr substring sup toLocaleLowerCase toLocaleUpperCase toLowerCase toUpperCase
		toWellFormed trim trimEnd trimLeft trimRight trimStart
		toExponential toFixed toPrecision
		add clear delete get has set
		catch finally then
		compile exec test
		toDateString toISOString toJSON toLocaleDateString toLocaleTimeString toTimeString toUTCString toGMTString
		getTimezoneOffset getYear setYear
		resize transfer transferToFixedLength subarray
		next return throw`) {
		out[m] = true
	}
	for _, unit := range strings.Fields("Date Day FullYear Hours Milliseconds Minutes Month Seconds Time") {
		for _, prefix := range []string{"get", "set", "getUTC", "setUTC"} {
			out[prefix+unit] = true
		}
	}
	for _, kind := range strings.Fields("Int8 Uint8 Int16 Uint16 Int32 Uint32 Float32 Float64 BigInt64 BigUint64") {
		out["get"+kind], out["set"+kind] = true, true
	}
	return out
}()
