// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"net/url"
	"strings"
)

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

// nodeUnresolvedAsNameOnly wraps resolve for a Node component: an external
// exact call it leaves without a target, whose target names a dependency
// (`bcryptjs.hash` into a bundle whose exports the producer could not list,
// `pg.(Client).connect` on a class the package exports through a value it
// builds), runs some code of that dependency the fragments do not name. It
// takes as name_only candidates the functions of the called name in the
// dependencies in scope the target names, and the constructors of the class
// it names for a `new`, as Python's unresolved calls do
// (pythonUnresolvedAsNameOnly): a finding it may reach reads unknown, never
// reachable.
func nodeUnresolvedAsNameOnly(resolve edgeResolver, self ComponentKey, packages nodePackages, byMethodArity map[string][]graphNode, scope map[ComponentKey]bool) edgeResolver {
	return func(e callEdge) edgeTargets {
		targets := resolve(e)
		if len(targets.nodes) > 0 || e.internal || e.resolution != ResolutionExact || e.method == "" || e.method == pythonModuleInitName {
			return targets
		}
		owners := packages.owners(e.target, self, scope)
		if len(owners) == 0 {
			return targets
		}
		method, class := e.method, ""
		if e.method == pythonConstructorName {
			owner, _, ok := splitFunctionKey(e.target)
			if !ok {
				return targets
			}
			method, class = "constructor", pythonSimpleClass(owner)
		}
		var nodes []graphNode
		for _, n := range byMethodArity[arityFreeMethodKey(method)] {
			if !owners[n.Component] {
				continue
			}
			if owner, _, ok := splitFunctionKey(n.Function); class != "" && (!ok || pythonSimpleClass(owner) != class) {
				continue
			}
			nodes = append(nodes, n)
		}
		if len(nodes) == 0 {
			return targets
		}
		return edgeTargets{nodes: nodes, nameOnly: true}
	}
}

// nodePackages maps each Node package name of the closure (`pg`,
// `@azure/msal-node`) to the components that are a version of it.
type nodePackages map[string][]ComponentKey

func indexNodePackages(closure []ComponentKey, fragments map[ComponentKey]Fragment) nodePackages {
	out := make(nodePackages)
	for _, key := range closure {
		fragment := fragments[key]
		if fragmentEcosystem(fragment) != "node" {
			continue
		}
		name := fragment.Module
		if name == "" {
			name = nodePurlName(key.Purl)
		}
		if name != "" {
			out[name] = append(out[name], key)
		}
	}
	return out
}

// nodePurlName is the package name an npm purl names: `@azure/msal-node`
// for pkg:npm/%40azure/msal-node.
func nodePurlName(purl string) string {
	name, ok := strings.CutPrefix(purl, "pkg:npm/")
	if !ok {
		return ""
	}
	if at := strings.LastIndex(name, "@"); at > 0 {
		name = name[:at]
	}
	if unescaped, err := url.PathUnescape(name); err == nil {
		name = unescaped
	}
	return name
}

// owners returns, as a set, the components in scope of the package a call
// target names: the longest package name the target starts with, followed by
// a `.` or a `/` (`pg` for `pg/lib.(Client).connect`, `socket.io` for
// `socket.io.(Server).listen`). None for a target of self's own package or
// of no package of the closure (a module of the runtime).
func (p nodePackages) owners(target string, self ComponentKey, scope map[ComponentKey]bool) map[ComponentKey]bool {
	if open := strings.Index(target, ".("); open >= 0 {
		target = target[:open+1]
	}
	best := ""
	for i := 0; i < len(target); i++ {
		if target[i] != '.' && target[i] != '/' {
			continue
		}
		if _, ok := p[target[:i]]; ok {
			best = target[:i]
		}
	}
	if best == "" {
		return nil
	}
	out := make(map[ComponentKey]bool)
	for _, k := range p[best] {
		if k == self {
			return nil
		}
		if scope[k] {
			out[k] = true
		}
	}
	return out
}
