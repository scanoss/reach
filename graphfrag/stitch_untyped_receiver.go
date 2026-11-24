// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "strings"

// stitch_untyped_receiver.go keeps two calls on a value a dependency
// returned from reading unreachable, in a project whose graph does not hold
// the dependency's source and so cannot name the method that runs:
//
//	h := liba.Standard()            // Go:   func Standard() Hasher
//	h.Sum(data)
//
//	let h = liba::standard();       // Rust: fn standard() -> Box<dyn Hasher>
//	h.sum(data);
//
// Each joins the dependencies' methods of the called name as a name_only
// call does: a finding one of them may reach reads unknown
// (unresolved_dispatch), never reachable.

// goInterfaceCandidates wraps resolve for a Go component. A Go producer
// exports a call on an interface type name_only, with the interface as its
// declared type, and keys it by the interface's own method. When a component
// of the closure declares that interface, the key finds the method's
// declaration, which has no body, and the call stopped there. Its candidates
// are the methods of that name in scope as well, the ones it has when no
// component declares the interface (`aead.Seal` on a crypto/cipher.AEAD).
func goInterfaceCandidates(resolve edgeResolver, byMethodArity map[string][]graphNode, scope map[ComponentKey]bool) edgeResolver {
	return func(e callEdge) edgeTargets {
		targets := resolve(e)
		if e.internal || e.resolution != ResolutionNameOnly || e.declaredType == "" || e.method == "" || len(targets.nodes) == 0 {
			return targets
		}
		found := make(map[graphNode]bool, len(targets.nodes))
		for _, n := range targets.nodes {
			found[n] = true
		}
		for _, callee := range byMethodArity[nameOnlyLookupKey(e)] {
			if scope[callee.Component] && !found[callee] {
				targets.nodes = append(targets.nodes, callee)
			}
		}
		return targets
	}
}

// rustUntypedCandidates wraps resolve for a Rust component. A Rust producer
// that cannot type a method call's receiver keys the call in the caller's own
// module, as a function nothing declares, so it joined nothing. When the
// receiver is a local the caller binds to the result of a call into another
// component, the method is one of that component's world: its candidates are
// the methods of that name in scope, name_only. A call on any other untyped
// value (a parameter, a std value: `bytes.iter()`) keeps no target.
func rustUntypedCandidates(resolve edgeResolver, self ComponentKey, fragment Fragment, byMethodArity map[string][]graphNode, scope map[ComponentKey]bool) edgeResolver {
	dependencyValues := make(map[string]bool)
	for i := range fragment.ExternalCalls {
		c := &fragment.ExternalCalls[i]
		if c.AssignedVar == "" || c.Resolution != ResolutionExact {
			continue
		}
		for _, n := range resolve(callEdge{caller: c.Caller, target: c.TargetSignature, targetCanonicalSignature: c.TargetCanonicalSignature, resolution: c.Resolution, method: c.MethodName}).nodes {
			if n.Component != self {
				dependencyValues[c.Caller+"\x00"+c.AssignedVar] = true
				break
			}
		}
	}
	return func(e callEdge) edgeTargets {
		targets := resolve(e)
		if len(targets.nodes) > 0 || e.internal || e.resolution != ResolutionExact || e.method == "" || e.receiverVar == "" {
			return targets
		}
		if e.target != functionKeyPackage(e.caller)+"."+e.method || !dependencyValues[e.caller+"\x00"+e.receiverVar] {
			return targets
		}
		var nodes []graphNode
		for _, callee := range byMethodArity[arityFreeMethodKey(e.method)] {
			if _, _, method := splitFunctionKey(callee.Function); method && scope[callee.Component] {
				nodes = append(nodes, callee)
			}
		}
		if len(nodes) == 0 {
			return targets
		}
		return edgeTargets{nodes: nodes, nameOnly: true}
	}
}

// functionKeyPackage is the package (a Rust module path) of a function key:
// `app.util` for `app.util.(Type).method` and for `app.util.function`.
func functionKeyPackage(key string) string {
	if open := strings.Index(key, ".("); open >= 0 {
		return key[:open]
	}
	if dot := strings.LastIndex(key, "."); dot >= 0 {
		return key[:dot]
	}
	return ""
}
