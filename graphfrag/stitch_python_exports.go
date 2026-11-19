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
// its `__init__` (`nacl.public.PublicKey(..)`). A Node fragment's exports
// join the same way: a call through a package specifier (`acme-sign.sign`)
// reaches the function the package declares in its entry module
// (`acme-sign/index.sign`).

// pythonConstructorName is the method an instantiation runs (`__init__`).
const pythonConstructorName = "<init>"

// pythonPublicDecl is the declaration a dependency's public path names.
type pythonPublicDecl struct {
	component ComponentKey
	decl      string
	// rust marks a Rust crate's export, whose declaration may be another
	// crate's (declared).
	rust bool
}

// pythonPublicNames indexes the closure's Python public paths.
type pythonPublicNames map[string][]pythonPublicDecl

// indexPythonPublicNames reads the closure's exports, and the classes of its
// Python components at their own paths.
func indexPythonPublicNames(closure []ComponentKey, fragments map[ComponentKey]Fragment) pythonPublicNames {
	out := make(pythonPublicNames)
	for _, key := range closure {
		fragment := fragments[key]
		rust := strings.HasPrefix(fragment.GraphAlgoVersion, rustGraphAlgoPrefix)
		for public, decl := range fragment.Exports {
			out[public] = append(out[public], pythonPublicDecl{component: key, decl: decl, rust: rust})
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
	// A public name carries no arity: a caller writes `JWT.encode`, not a
	// count. A Ruby call target does carry one, because the cards matcher
	// reads a site through a key that must end in "#N", so it is dropped
	// here. A target with no "#" is unchanged, which is every Python one.
	target = trimArity(target)
	for _, d := range p[target] {
		if !deps[d.component] && d.component != self {
			continue
		}
		key := d.decl
		if strings.HasSuffix(key, ")") {
			key += "." + pythonConstructorName
		}
		nodes = append(nodes, p.declared(key, d, functionsBySignature, hierarchy, 0)...)
	}
	if owner, local, ok := splitFunctionKey(target); ok {
		for _, d := range p[owner] {
			if deps[d.component] {
				nodes = append(nodes, p.declared(d.decl+"."+local, d, functionsBySignature, hierarchy, 0)...)
			}
		}
	}
	return nodes
}

// maxForeignExportHops bounds how many components' exports one public path
// may pass through (a crate re-exporting a crate that re-exports another).
const maxForeignExportHops = 3

// declared is the function key names in the component that exports it, else
// the declaration it inherits. A Rust crate may name another crate's item: it
// re-exports a dependency's type (`pub use rand_core::OsRng;` in rand) under
// the key that dependency gives it, so a key its own crate does not declare is
// looked up in the closure, directly or through the exports of the crate that
// declares it. Python and Node exports always name their own component's
// declarations, and stay there.
func (p pythonPublicNames) declared(key string, from pythonPublicDecl, functionsBySignature map[string][]graphNode, hierarchy *typeHierarchy, hops int) []graphNode {
	nodes := declarationNodes(key, from.component, functionsBySignature, hierarchy)
	if len(nodes) > 0 || !from.rust || hops >= maxForeignExportHops {
		return nodes
	}
	for _, node := range functionsBySignature[key] {
		if node.Component != from.component {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) > 0 {
		return nodes
	}
	owner, local, ok := splitFunctionKey(key)
	if !ok {
		return nil
	}
	for _, d := range p[owner] {
		if d.rust && d.component != from.component {
			nodes = append(nodes, p.declared(d.decl+"."+local, d, functionsBySignature, hierarchy, hops+1)...)
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

// trimArity drops a key's "#N" suffix. A key without one is returned as it
// is, so a Python target, which never carries an arity, does not move.
func trimArity(key string) string {
	i := strings.LastIndex(key, "#")
	if i < 0 {
		return key
	}
	for _, c := range key[i+1:] {
		if c < '0' || c > '9' {
			return key
		}
	}
	if i == len(key)-1 {
		return key
	}
	return key[:i]
}
