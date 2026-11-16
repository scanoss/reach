// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"sort"
	"strings"
)

// stitch_service_providers.go joins what java.util.ServiceLoader does at run
// time: it instantiates, by name, the classes a JAR lists in
// META-INF/services/<service type>, and code calls them through the service
// type (Tika's CompositeParser calls Parser.parse on the parsers tika-parsers
// registers). No call graph edge records that, and a fragment mined alone
// cannot prove the hierarchy when the service type lives in another
// component. The fragments' service_providers (graph-fragment-1.25) name the
// registrations, so the stitch marks each registered class's implementation
// of a service type method as an implementation of that method: a call on the
// service type then dispatches to it under the standard dispatch policy.
// Only classes the closure declares join, and only through registrations
// some closure component (or the project) makes, never "any subtype".
// Enabled by StitchOptions.ServiceProviderDispatch.

// closureServiceProviders merges the closure's registrations: each service
// type to the registered classes, deduplicated, in sorted order.
func closureServiceProviders(closure []ComponentKey, fragments map[ComponentKey]Fragment) map[string][]string {
	var out map[string][]string
	for _, key := range closure {
		for service, providers := range fragments[key].ServiceProviders {
			if out == nil {
				out = make(map[string][]string)
			}
			out[service] = append(out[service], providers...)
		}
	}
	for service, providers := range out {
		sort.Strings(providers)
		out[service] = compactStrings(providers)
	}
	return out
}

func compactStrings(sorted []string) []string {
	out := sorted[:0]
	for i, s := range sorted {
		if i == 0 || s != sorted[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// declaredTypeName returns the spelling of a binary class name the closure
// indexes methods under (a nested class's `$` reads as `.` in function keys),
// or "" when the closure declares no method of it.
func (h typeHierarchy) declaredTypeName(binary string) string {
	for _, name := range []string{binary, strings.ReplaceAll(binary, "$", ".")} {
		if _, ok := h.methods[name]; ok {
			return name
		}
	}
	return ""
}

// serviceMethod is one method a service type declares (or inherits from a
// supertype the closure declares): its local key and its declarations.
type serviceMethod struct {
	local string
	nodes []graphNode
}

func (h typeHierarchy) serviceMethods(service string) []serviceMethod {
	var out []serviceMethod
	seen := make(map[string]bool)
	for _, t := range append([]string{service}, h.ancestors(service)...) {
		locals := make([]string, 0, len(h.methods[t]))
		for local := range h.methods[t] {
			locals = append(locals, local)
		}
		sort.Strings(locals)
		for _, local := range locals {
			if seen[local] || strings.HasPrefix(local, "<init>") || strings.HasPrefix(local, "<clinit>") {
				continue
			}
			seen[local] = true
			out = append(out, serviceMethod{local: local, nodes: h.methods[t][local]})
		}
	}
	return out
}

// implementationOf returns the declarations a call of local on an instance
// of impl runs: the nearest type of impl's hierarchy (impl first) declaring
// a method body of that name and parameters. parentSignature narrows the
// overloads of a key the service spells without its parameter suffix.
func (h typeHierarchy) implementationOf(impl, local, parentSignature string, hasBody func(graphNode) bool) []graphNode {
	unsuffixed := local
	if i := strings.Index(local, "$"); i >= 0 {
		unsuffixed = local[:i]
	}
	for _, t := range append([]string{impl}, h.ancestors(impl)...) {
		methods := h.methods[t]
		nodes := methods[local]
		if len(nodes) == 0 {
			var overloads []graphNode
			for l, candidates := range methods {
				if l == unsuffixed || strings.HasPrefix(l, unsuffixed+"$") {
					overloads = append(overloads, candidates...)
				}
			}
			sort.Slice(overloads, func(i, j int) bool { return nodeLess(overloads[i], overloads[j]) })
			nodes = filterOverloadCandidates(overloads, parentSignature)
		}
		var bodies []graphNode
		for _, n := range nodes {
			if hasBody(n) {
				bodies = append(bodies, n)
			}
		}
		if len(bodies) > 0 {
			return bodies
		}
	}
	return nil
}

// addServiceProviderCompatibility adds, to each registered class's
// implementation of a service type method, that method's canonical signature
// as a compatible signature, so indexFunctions builds the dispatch surface
// from it. A registration whose class or service type the closure does not
// declare adds nothing.
func addServiceProviderCompatibility(closure []ComponentKey, fragments map[ComponentKey]Fragment, h typeHierarchy) {
	registrations := closureServiceProviders(closure, fragments)
	if len(registrations) == 0 {
		return
	}
	functions := make(map[graphNode]*Function)
	for _, key := range closure {
		for i := range fragments[key].Functions {
			fn := &fragments[key].Functions[i]
			functions[graphNode{Component: key, Function: fn.Signature}] = fn
		}
	}
	hasBody := func(n graphNode) bool {
		fn := functions[n]
		return fn != nil && !(fn.Abstract && fragments[n.Component].AbstractMethods)
	}
	added := make(map[graphNode][]string)
	services := make([]string, 0, len(registrations))
	for service := range registrations {
		services = append(services, service)
	}
	sort.Strings(services)
	for _, service := range services {
		declared := h.declaredTypeName(service)
		if declared == "" {
			continue
		}
		methods := h.serviceMethods(declared)
		for _, provider := range registrations[service] {
			impl := h.declaredTypeName(provider)
			if impl == "" || impl == declared {
				continue
			}
			for _, m := range methods {
				for _, parent := range m.nodes {
					sig := functions[parent].CanonicalSignature
					if sig == "" {
						continue
					}
					for _, target := range h.implementationOf(impl, m.local, sig, hasBody) {
						if target != parent && !containsString(added[target], sig) && !containsString(functions[target].CompatibleCanonicalSignatures, sig) {
							added[target] = append(added[target], sig)
						}
					}
				}
			}
		}
	}
	if len(added) == 0 {
		return
	}
	for _, key := range closure {
		fragment := fragments[key]
		var copied []Function
		for i := range fragment.Functions {
			sigs := added[graphNode{Component: key, Function: fragment.Functions[i].Signature}]
			if len(sigs) == 0 {
				continue
			}
			if copied == nil {
				copied = append([]Function(nil), fragment.Functions...)
			}
			copied[i].CompatibleCanonicalSignatures = append(append([]string(nil), copied[i].CompatibleCanonicalSignatures...), sigs...)
		}
		if copied != nil {
			fragment.Functions = copied
			fragments[key] = fragment
		}
	}
}
