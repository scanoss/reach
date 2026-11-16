// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "strings"

// stitch_python_exports.go joins a client's call spelled with a Python
// dependency's public names to the declaration the dependency makes: the
// client calls `jwt.encode(..)`, pyjwt declares `jwt.api_jwt.(PyJWT).encode`
// and says so in its fragment's `exports`. A class reached by a public path
// joins its methods (`urllib3.(Retry).increment` is
// `urllib3.util.retry.(Retry).increment`) and its instantiation
// (`requests.Session(..)` runs `requests.sessions.(Session).<init>`). A
// Python class is also public at its own path, so its instantiation joins
// its `__init__` (`nacl.public.PublicKey(..)`).

// pythonConstructorName is the method an instantiation runs (`__init__`).
const pythonConstructorName = "<init>"

// pythonPublicDecl is the declaration a dependency's public path names.
type pythonPublicDecl struct {
	component ComponentKey
	decl      string
}

// pythonPublicNames indexes the closure's Python public paths.
type pythonPublicNames map[string][]pythonPublicDecl

// indexPythonPublicNames reads the closure's exports, and the classes of its
// Python components at their own paths.
func indexPythonPublicNames(closure []ComponentKey, fragments map[ComponentKey]Fragment) pythonPublicNames {
	out := make(pythonPublicNames)
	for _, key := range closure {
		fragment := fragments[key]
		for public, decl := range fragment.Exports {
			out[public] = append(out[public], pythonPublicDecl{component: key, decl: decl})
		}
		if !strings.HasPrefix(fragment.GraphAlgoVersion, pythonGraphAlgoPrefix) {
			continue
		}
		classes := make(map[string]bool)
		addClass := func(owner, class string) {
			if !classes[class] {
				classes[class] = true
				out[owner] = append(out[owner], pythonPublicDecl{component: key, decl: class})
			}
		}
		for i := range fragment.Functions {
			signature := fragment.Functions[i].Signature
			if owner, local, ok := splitFunctionKey(signature); ok {
				addClass(owner, strings.TrimSuffix(signature, "."+local))
			}
		}
		// A class that declares no method of its own (its `__init__` is a
		// base's) is public at its own path too.
		for typ := range fragment.Supertypes {
			if dot := strings.LastIndex(typ, "."); dot > 0 {
				addClass(typ, typ[:dot]+".("+typ[dot+1:]+")")
			}
		}
	}
	return out
}

// targets is what an exact call target names through the public paths of
// the components in deps: the declaration at a public path (a class's
// `__init__` when the path names a class), and a method of a class at a
// public path. A method or `__init__` the class only inherits is found
// through the hierarchy.
//
// self is the calling component: its own classes count too, for an
// instantiation the producer could not link because the `__init__` it runs
// is a dependency base's (`class GithubRetry(urllib3.Retry)` with no
// `__init__` of its own).
func (p pythonPublicNames) targets(target string, self ComponentKey, deps map[ComponentKey]bool, functionsBySignature map[string][]graphNode, hierarchy *typeHierarchy) []graphNode {
	var nodes []graphNode
	for _, d := range p[target] {
		if !deps[d.component] && d.component != self {
			continue
		}
		key := d.decl
		if strings.HasSuffix(key, ")") {
			key += "." + pythonConstructorName
		}
		nodes = append(nodes, declarationNodes(key, d.component, functionsBySignature, hierarchy)...)
	}
	if owner, local, ok := splitFunctionKey(target); ok {
		for _, d := range p[owner] {
			if deps[d.component] {
				nodes = append(nodes, declarationNodes(d.decl+"."+local, d.component, functionsBySignature, hierarchy)...)
			}
		}
	}
	return nodes
}

// declarationNodes is the function key names in component, else the
// declaration it inherits.
func declarationNodes(key string, component ComponentKey, functionsBySignature map[string][]graphNode, hierarchy *typeHierarchy) []graphNode {
	var nodes []graphNode
	for _, node := range functionsBySignature[key] {
		if node.Component == component {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 && hierarchy != nil {
		nodes = hierarchy.inheritedTargets(key)
	}
	return nodes
}
