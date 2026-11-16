// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "strings"

// stitch_python_instantiated.go narrows the candidates of Python name_only
// calls. A name_only call (`alg.sign(..)` on a receiver nothing typed) has as
// candidates every method of that name in the environment, so one `.close()`
// or `.sign()` the client reaches makes every such method a maybe and nearly
// every finding unknown. Calling a method of class K needs an object of K or
// of a subclass, or K's class object: something must instantiate K, call
// through it (a typed call naming K), or hand the class around as a value
// (which the producer records as a `<class>` edge). A candidate method of a
// class nothing the root reaches does so is not callable and is dropped.
//
// What counts as reached is computed to a fixpoint over the typed, ambiguous
// and kept name_only edges, so code reached only through a kept guess still
// instantiates. Two cases keep every class: a component none of whose
// modules the root imports even over every name_only edge is loaded some
// other way when its code runs (a plugin named in configuration and loaded
// with importlib, matrix-synapse-ldap3's LdapAuthProvider), and classes are
// matched by simple name, so a namesake anywhere keeps them. Objects made
// natively, unpickled or built by `type(..)` are outside the model.

// pythonInstantiation indexes, for the closure's Python components, the
// classes each function instantiates, calls through or hands around (by
// simple class name) and the simple names of each class's supertypes.
type pythonInstantiation struct {
	byCaller map[graphNode][]string
	supers   map[string][]string
}

func indexPythonInstantiation(closure []ComponentKey, fragments map[ComponentKey]Fragment) pythonInstantiation {
	p := pythonInstantiation{byCaller: make(map[graphNode][]string), supers: make(map[string][]string)}
	// add records the class a typed call names: the owner of a method
	// target (`pkg.(K).m`: K's class object or an instance of it is in
	// play), else the target's last part (`pkg.K`, a class called without
	// an `__init__` of its own; a function name that is also a class name
	// only keeps more).
	add := func(key ComponentKey, caller, target string, resolution ResolutionKind) {
		if resolution == ResolutionNameOnly && !strings.HasSuffix(target, "."+pythonClassValueName) {
			return // a guess by method name names no class; a class read as a value does
		}
		class := ""
		if owner, _, ok := splitFunctionKey(target); ok {
			class = pythonSimpleClass(owner)
		} else {
			class = target[strings.LastIndex(target, ".")+1:]
		}
		if class == "" {
			return
		}
		n := graphNode{Component: key, Function: caller}
		p.byCaller[n] = append(p.byCaller[n], class)
	}
	for _, key := range closure {
		fragment := fragments[key]
		if fragmentEcosystem(fragment) != "python" {
			continue
		}
		for i := range fragment.InternalEdges {
			e := &fragment.InternalEdges[i]
			add(key, e.Caller, e.Callee, e.Resolution)
		}
		for i := range fragment.ExternalCalls {
			c := &fragment.ExternalCalls[i]
			add(key, c.Caller, c.TargetSignature, c.Resolution)
		}
		for typ, bases := range fragment.Supertypes {
			s := pythonSimpleClass(typ)
			for _, b := range bases {
				for _, alt := range strings.Split(b, "|") {
					p.supers[s] = append(p.supers[s], pythonSimpleClass(alt))
				}
			}
		}
	}
	return p
}

// pythonModuleInitName is the function holding a Python module's top level.
const pythonModuleInitName = "<module>"

// pythonSimpleClass is the last dotted part of a class spelling, without
// the parentheses of a function key's owner (`jwt.algorithms.(RSAAlgorithm)`).
func pythonSimpleClass(s string) string {
	s = strings.TrimSuffix(strings.TrimPrefix(s[strings.LastIndex(s, ".")+1:], "("), ")")
	if i := strings.LastIndex(s, "("); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// narrowPythonNameOnly keeps a Python name_only candidate that is a method
// only when its class, or a subclass of it, is instantiated by code the
// root reaches over the traversed, ambiguous and kept name_only edges, to a
// fixpoint. Edges of other ecosystems and candidates that are no method keep.
func narrowPythonNameOnly(root ComponentKey, rootFragment Fragment, fragments map[ComponentKey]Fragment, inst pythonInstantiation, adjacency, ambiguous, nameOnly map[graphNode][]adjacencyEdge) map[graphNode][]adjacencyEdge {
	seeds := make(map[graphNode]bool, len(rootFragment.Functions))
	for i := range rootFragment.Functions {
		seeds[graphNode{Component: root, Function: rootFragment.Functions[i].Signature}] = true
	}
	live := make(map[string]bool)
	var mark func(string)
	mark = func(c string) {
		if live[c] {
			return
		}
		live[c] = true
		for _, s := range inst.supers[c] {
			mark(s)
		}
	}
	kept := func() map[graphNode][]adjacencyEdge {
		out := make(map[graphNode][]adjacencyEdge, len(nameOnly))
		for from, edges := range nameOnly {
			if fragmentEcosystem(fragments[from.Component]) != "python" {
				out[from] = edges
				continue
			}
			for _, e := range edges {
				owner, _, ok := splitFunctionKey(e.target.Function)
				if !ok || live[pythonSimpleClass(owner)] {
					out[from] = append(out[from], e)
				}
			}
		}
		return out
	}
	// A component none of whose modules the root imports, even over every
	// name_only edge, is loaded some other way when its code runs (by
	// name, from configuration: a plugin) or not at all: every class it
	// declares counts as instantiated.
	imported := make(map[ComponentKey]bool)
	for n := range forwardReachableSetOver(seeds, adjacency, ambiguous, nameOnly) {
		if strings.HasSuffix(n.Function, "."+pythonModuleInitName) {
			imported[n.Component] = true
		}
	}
	for key, fragment := range fragments {
		if key == root || imported[key] || fragmentEcosystem(fragment) != "python" {
			continue
		}
		for i := range fragment.Functions {
			if owner, _, ok := splitFunctionKey(fragment.Functions[i].Signature); ok {
				mark(pythonSimpleClass(owner))
			}
		}
	}
	for {
		before := len(live)
		filtered := kept()
		for n := range forwardReachableSetOver(seeds, adjacency, ambiguous, filtered) {
			for _, c := range inst.byCaller[n] {
				mark(c)
			}
			if owner, local, ok := splitFunctionKey(n.Function); ok && local == pythonConstructorName {
				mark(pythonSimpleClass(owner))
			}
		}
		if len(live) == before {
			return filtered
		}
	}
}
