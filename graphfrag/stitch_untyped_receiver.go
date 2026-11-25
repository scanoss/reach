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
// Each takes name_only candidates among the dependencies' methods of the
// called name: a finding one of them may reach reads unknown
// (unresolved_dispatch), never reachable.

// goInterfaceCandidates wraps resolve for a Go component. A Go producer
// exports a call on an interface type name_only, with the interface as its
// declared type, and keys it by the interface's own method. When a component
// of the closure declares that interface, the key finds the method's
// declaration, which has no body, and the call stopped there. Its candidates
// are the methods of that name in scope as well, as when no component
// declares the interface (`aead.Seal` on a crypto/cipher.AEAD).
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
			if _, _, method := splitFunctionKey(callee.Function); method && scope[callee.Component] && !found[callee] {
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
// component, that function's declared return type says what the value is:
// the call's name_only candidates are the methods of the called name on that
// type and on the types implementing it as a trait. A return type that names
// no type (a type parameter, a tuple) gives none, and a call on any other
// untyped value (a parameter, a std value: `bytes.iter()`) keeps no target.
func rustUntypedCandidates(
	resolve edgeResolver,
	self ComponentKey,
	fragments map[ComponentKey]Fragment,
	functionsByNode map[graphNode]*Function,
	byMethodArity map[string][]graphNode,
	scope map[ComponentKey]bool,
) edgeResolver {
	// The types the dependency functions bound to each local return, by
	// caller and variable. An unreadable one withdraws the variable.
	returned := make(map[string]map[string]bool)
	fragment := fragments[self]
	for i := range fragment.ExternalCalls {
		c := &fragment.ExternalCalls[i]
		if c.AssignedVar == "" || c.Resolution != ResolutionExact {
			continue
		}
		local := c.Caller + "\x00" + c.AssignedVar
		for _, producer := range resolve(callEdge{caller: c.Caller, target: c.TargetSignature, targetCanonicalSignature: c.TargetCanonicalSignature, resolution: c.Resolution, method: c.MethodName}).nodes {
			if producer.Component == self {
				continue
			}
			typ := ""
			if fn := functionsByNode[producer]; fn != nil {
				owner, _, _ := splitFunctionKey(producer.Function)
				typ = rustReturnedTypeName(fn.ReturnType, owner)
			}
			if _, seen := returned[local]; !seen {
				returned[local] = make(map[string]bool)
			}
			returned[local][typ] = true
		}
	}
	return func(e callEdge) edgeTargets {
		targets := resolve(e)
		if len(targets.nodes) > 0 || e.internal || e.resolution != ResolutionExact || e.method == "" || e.receiverVar == "" {
			return targets
		}
		types := returned[e.caller+"\x00"+e.receiverVar]
		if len(types) == 0 || types[""] || e.target != functionKeyPackage(e.caller)+"."+e.method {
			return targets
		}
		var nodes []graphNode
		for _, callee := range byMethodArity[arityFreeMethodKey(e.method)] {
			owner, _, method := splitFunctionKey(callee.Function)
			if method && scope[callee.Component] && rustTypeIsOrImplements(owner, types, fragments[callee.Component].Supertypes) {
				nodes = append(nodes, callee)
			}
		}
		if len(nodes) == 0 {
			return targets
		}
		return edgeTargets{nodes: nodes, nameOnly: true}
	}
}

// rustTypeIsOrImplements reports whether owner, a type as `module.Type`, is
// one of types by its simple name or implements one of them as a trait.
func rustTypeIsOrImplements(owner string, types map[string]bool, supertypes map[string][]string) bool {
	if types[simpleTypeName(owner)] {
		return true
	}
	for _, super := range supertypes[owner] {
		if types[simpleTypeName(super)] {
			return true
		}
	}
	return false
}

// rustReturnWrappers are the std types a function returns its value in.
var rustReturnWrappers = map[string]bool{"Box": true, "Arc": true, "Rc": true, "Pin": true, "Option": true, "Result": true}

// rustReturnedTypeName is the simple name of the type a Rust function
// returns, read from its return type as written: through references, `dyn`,
// `impl`, a path and the std wrappers (`Result<Client, Error>` returns a
// Client). `Self` is the simple name of owner, the function's own type. ""
// when the text names no type: a type parameter, a tuple, a primitive.
func rustReturnedTypeName(returned, owner string) string {
	text := strings.TrimSpace(returned)
	for {
		text = strings.TrimLeft(text, "& ")
		switch {
		case strings.HasPrefix(text, "'"):
			_, text, _ = strings.Cut(text, " ")
			continue
		case strings.HasPrefix(text, "mut "), strings.HasPrefix(text, "dyn "):
			text = text[4:]
			continue
		case strings.HasPrefix(text, "impl "):
			text = text[5:]
			continue
		}
		name, arguments, generic := strings.Cut(text, "<")
		name, _, _ = strings.Cut(name, " ")
		name = name[strings.LastIndex(name, ":")+1:]
		if generic && rustReturnWrappers[name] {
			text = rustFirstTypeArgument(arguments)
			continue
		}
		if name == "Self" {
			name = simpleTypeName(owner)
		}
		// A type is CamelCase; one capital alone is a type parameter.
		if len(name) < 2 || name[0] < 'A' || name[0] > 'Z' || strings.ContainsAny(name, "()[];,") {
			return ""
		}
		return name
	}
}

// rustFirstTypeArgument is the first argument of a generic argument list
// given without its opening bracket: `Client, Error>` gives `Client`.
func rustFirstTypeArgument(arguments string) string {
	depth := 0
	for i, r := range arguments {
		switch r {
		case '<', '(', '[':
			depth++
		case '>', ')', ']':
			if depth == 0 {
				return arguments[:i]
			}
			depth--
		case ',':
			if depth == 0 {
				return arguments[:i]
			}
		}
	}
	return arguments
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
