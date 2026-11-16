// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"sort"
	"strings"
)

// stitch_supertypes.go uses the fragments' supertypes (graph-fragment
// `supertypes`, additive) to join what a component mined alone cannot: a call
// on a type that only inherits the method (ConfigurableJWTProcessor.process,
// declared in JWTProcessor), and an implementation whose hierarchy lives in
// another component, or that the producer could not prove (DefaultJWTProcessor
// implementing a generic interface). Enabled by StitchOptions.HierarchyFromSupertypes.

// typeHierarchy indexes the closure's types: their supertypes, and their
// functions by local key (`name#arity$params`, the part after `(Type).`).
type typeHierarchy struct {
	supers  map[string][]string
	methods map[string]map[string][]graphNode
	// inherited memoizes inheritedTargets: a closure's calls name the same
	// inherited targets again and again.
	inherited map[string][]graphNode
}

// splitFunctionKey splits `pkg.(Type).local` into the owner type's qualified
// name and the local key. ok is false for a key with no owner type.
func splitFunctionKey(key string) (owner, local string, ok bool) {
	open := strings.Index(key, ".(")
	if open < 0 {
		return "", "", false
	}
	rest := key[open+2:]
	closeIdx := strings.Index(rest, ").")
	if closeIdx < 0 {
		return "", "", false
	}
	return key[:open] + "." + rest[:closeIdx], rest[closeIdx+2:], true
}

// typeNames is a type's spellings: nested types appear as Outer$Inner in
// function keys and as Outer.Inner in supertype clauses.
func typeNames(t string) []string {
	if dot := strings.LastIndex(t, "."); dot >= 0 && strings.Contains(t[dot+1:], "$") {
		return []string{t, t[:dot+1] + strings.ReplaceAll(t[dot+1:], "$", ".")}
	}
	return []string{t}
}

func indexTypeHierarchy(closure []ComponentKey, fragments map[ComponentKey]Fragment) typeHierarchy {
	h := typeHierarchy{supers: make(map[string][]string), methods: make(map[string]map[string][]graphNode), inherited: make(map[string][]graphNode)}
	for _, key := range closure {
		fragment := fragments[key]
		for i := range fragment.Functions {
			owner, local, ok := splitFunctionKey(fragment.Functions[i].Signature)
			if !ok {
				continue
			}
			for _, name := range typeNames(owner) {
				if h.methods[name] == nil {
					h.methods[name] = make(map[string][]graphNode)
				}
				h.methods[name][local] = append(h.methods[name][local], graphNode{Component: key, Function: fragment.Functions[i].Signature})
			}
		}
	}
	known := func(t string) bool {
		_, ok := h.methods[t]
		return ok
	}
	publicClasses := pythonPublicClasses(closure, fragments)
	for _, key := range closure {
		for typ, supers := range fragments[key].Supertypes {
			for _, clause := range supers {
				// An unresolved base keeps its candidates joined by `|`; keep the
				// ones the closure declares.
				for _, candidate := range strings.Split(clause, "|") {
					candidate = strings.TrimSpace(candidate)
					if !known(candidate) && !fragmentsDeclareSupertypes(fragments, closure, candidate) {
						// A Python base named by a dependency's public path
						// (`urllib3.Retry`) is the class that path exports
						// (`urllib3.util.retry.Retry`).
						if declared, ok := publicClasses[candidate]; ok {
							candidate = declared
						}
					}
					if candidate != "" && candidate != typ && (known(candidate) || fragmentsDeclareSupertypes(fragments, closure, candidate)) {
						h.supers[typ] = append(h.supers[typ], candidate)
					}
				}
			}
		}
	}
	return h
}

// pythonPublicClasses maps each public path the closure's exports give a class
// (`urllib3.Retry` -> `urllib3.util.retry.(Retry)`) to the class's type name
// (`urllib3.util.retry.Retry`). A path two components export differently is
// left out.
func pythonPublicClasses(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[string]string {
	out := make(map[string]string)
	conflict := make(map[string]bool)
	for _, key := range closure {
		for public, decl := range fragments[key].Exports {
			open := strings.LastIndex(decl, ".(")
			if open < 0 || !strings.HasSuffix(decl, ")") {
				continue
			}
			typ := decl[:open] + "." + decl[open+2:len(decl)-1]
			if prev, ok := out[public]; ok && prev != typ {
				conflict[public] = true
			}
			out[public] = typ
		}
	}
	for public := range conflict {
		delete(out, public)
	}
	return out
}

func fragmentsDeclareSupertypes(fragments map[ComponentKey]Fragment, closure []ComponentKey, typ string) bool {
	for _, key := range closure {
		if _, ok := fragments[key].Supertypes[typ]; ok {
			return true
		}
	}
	return false
}

// ancestors returns typ's transitive supertypes, nearest first.
func (h typeHierarchy) ancestors(typ string) []string {
	var out []string
	seen := map[string]bool{typ: true}
	queue := []string{typ}
	for len(queue) > 0 {
		t := queue[0]
		queue = queue[1:]
		for _, name := range typeNames(t) {
			for _, s := range h.supers[name] {
				if !seen[s] {
					seen[s] = true
					out = append(out, s)
					queue = append(queue, s)
				}
			}
		}
	}
	return out
}

// inheritedTargets resolves a call target `pkg.(T).local` that no function
// declares to the nearest supertype of T declaring that method (the exact
// overload, or every overload of the name and arity when the call carries
// none). Every overload is listed in node order. The result is shared: a
// caller must not modify it.
func (h typeHierarchy) inheritedTargets(target string) []graphNode {
	if nodes, ok := h.inherited[target]; ok {
		return nodes
	}
	nodes := h.resolveInherited(target)
	if h.inherited != nil {
		h.inherited[target] = nodes
	}
	return nodes
}

func (h typeHierarchy) resolveInherited(target string) []graphNode {
	owner, local, ok := splitFunctionKey(target)
	if !ok {
		return nil
	}
	unsuffixed := local
	if i := strings.Index(local, "$"); i >= 0 {
		unsuffixed = local[:i]
	}
	overload := unsuffixed + "$"
	for _, s := range h.ancestors(owner) {
		methods := h.methods[s]
		if nodes := methods[local]; len(nodes) > 0 {
			return nodes
		}
		var out []graphNode
		for l, nodes := range methods {
			if l == unsuffixed || strings.HasPrefix(l, overload) {
				out = append(out, nodes...)
			}
		}
		if len(out) > 0 {
			sort.Slice(out, func(i, j int) bool { return nodeLess(out[i], out[j]) })
			return out
		}
	}
	return nil
}

// addSupertypeCompatibility marks each function as an implementation of the
// same method (same local key) declared by any supertype of its type, by
// adding that declaration's canonical signature to its
// CompatibleCanonicalSignatures. indexFunctions then builds the dispatch
// surface from it.
func addSupertypeCompatibility(closure []ComponentKey, fragments map[ComponentKey]Fragment, h typeHierarchy) {
	canonical := make(map[graphNode]string)
	for _, key := range closure {
		for i := range fragments[key].Functions {
			fn := fragments[key].Functions[i]
			canonical[graphNode{Component: key, Function: fn.Signature}] = fn.CanonicalSignature
		}
	}
	for _, key := range closure {
		fragment := fragments[key]
		changed := false
		functions := fragment.Functions
		for i := range functions {
			owner, local, ok := splitFunctionKey(functions[i].Signature)
			if !ok || strings.HasPrefix(local, "<init>") || strings.HasPrefix(local, "<clinit>") {
				continue
			}
			for _, s := range h.ancestors(owner) {
				for _, parent := range h.methods[s][local] {
					sig := canonical[parent]
					if sig == "" || containsString(functions[i].CompatibleCanonicalSignatures, sig) {
						continue
					}
					if !changed {
						functions = append([]Function(nil), functions...)
						changed = true
					}
					functions[i].CompatibleCanonicalSignatures = append(append([]string(nil), functions[i].CompatibleCanonicalSignatures...), sig)
				}
			}
		}
		if changed {
			fragment.Functions = functions
			fragments[key] = fragment
		}
	}
}

func containsString(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}
