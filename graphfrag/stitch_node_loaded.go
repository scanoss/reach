// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "strings"

// stitch_node_loaded.go drops the candidates of Node name_only calls that
// live in a module nothing loads. A name_only call (`signer.sign(d)` on a
// receiver nothing typed) has as candidates every function of that name in
// scope, so one `.create()` or `.connect()` the root reaches makes every
// such function a maybe. A JavaScript function exists only once its module
// has been evaluated: a method of a class, a member of an object literal or
// a plain function of a module no `require` or `import` ever loaded is no
// value any receiver can hold, whatever its name. A candidate in such a
// module is not callable and is dropped; the finding it led to reads
// unreachable again, as it did before the call was exported name_only.
//
// A module counts as loaded when the root reaches any function of it, its
// top-level code (`<module>`) included, over the traversed and ambiguous
// edges and the name_only edges kept so far, to a fixpoint: code reached
// only through a kept guess still loads what it requires. The fixpoint is
// the least one, so a guess into a module is never what loads that module;
// in a run, the load comes before the call.
//
// Two kinds of module always count as loaded: one the fragment gives no
// `<module>` function (a file with no call and no import at its top level:
// loading it leaves no edge to follow), and one of a fragment that records
// no file for the function. A load the producer cannot name (`require(x)`
// with x no constant the source shows) loads nothing here, as it loads
// nothing for the traversed edges.

// nodeModuleID names one source file of one component.
type nodeModuleID struct {
	component ComponentKey
	file      string
}

// nodeModuleIndex maps each function of the closure's Node components to its
// module, for the modules that have a `<module>` function.
type nodeModuleIndex map[graphNode]nodeModuleID

func indexNodeModules(closure []ComponentKey, fragments map[ComponentKey]Fragment) nodeModuleIndex {
	out := make(nodeModuleIndex)
	for _, key := range closure {
		fragment := fragments[key]
		if fragmentEcosystem(fragment) != "node" {
			continue
		}
		tracked := make(map[string]bool)
		for i := range fragment.Functions {
			if f := &fragment.Functions[i]; f.FilePath != "" && strings.HasSuffix(f.Signature, "."+pythonModuleInitName) {
				tracked[f.FilePath] = true
			}
		}
		for i := range fragment.Functions {
			if f := &fragment.Functions[i]; tracked[f.FilePath] {
				out[graphNode{Component: key, Function: f.Signature}] = nodeModuleID{component: key, file: f.FilePath}
			}
		}
	}
	return out
}

// narrowNodeNameOnly keeps a name_only edge into a function of a tracked
// Node module only when the root loads that module (see the file comment).
// Edges into other ecosystems and into untracked modules keep.
func narrowNodeNameOnly(root ComponentKey, rootFragment Fragment, modules nodeModuleIndex, adjacency, ambiguous, nameOnly map[graphNode][]adjacencyEdge) map[graphNode][]adjacencyEdge {
	if len(modules) == 0 || len(nameOnly) == 0 {
		return nameOnly
	}
	loaded := make(map[nodeModuleID]bool)
	parked := make(map[nodeModuleID][]graphNode)
	seen := make(map[graphNode]bool, len(rootFragment.Functions))
	var queue []graphNode
	visit := func(n graphNode) {
		if seen[n] {
			return
		}
		seen[n] = true
		queue = append(queue, n)
	}
	for i := range rootFragment.Functions {
		visit(graphNode{Component: root, Function: rootFragment.Functions[i].Signature})
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if module, tracked := modules[n]; tracked && !loaded[module] {
			loaded[module] = true
			for _, waiting := range parked[module] {
				visit(waiting)
			}
			delete(parked, module)
		}
		for _, edge := range adjacency[n] {
			visit(edge.target)
		}
		for _, edge := range ambiguous[n] {
			visit(edge.target)
		}
		for _, edge := range nameOnly[n] {
			if module, tracked := modules[edge.target]; tracked && !loaded[module] {
				parked[module] = append(parked[module], edge.target)
				continue
			}
			visit(edge.target)
		}
	}
	out := make(map[graphNode][]adjacencyEdge, len(nameOnly))
	for from, edges := range nameOnly {
		for _, edge := range edges {
			if module, tracked := modules[edge.target]; tracked && !loaded[module] {
				continue
			}
			out[from] = append(out[from], edge)
		}
	}
	return out
}
