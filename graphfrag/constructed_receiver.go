// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "strings"

// A call on the result of a factory is written against what the factory
// declares, an interface or a base class, and the caller's graph cannot say
// which class the object is when the factory lives in another component:
//
//	Hasher h = Hashers.standard();   // a dependency: `return new Standard();`
//	h.sum(data);                     // Standard.sum, not every Hasher
//
// The two halves of the answer sit in two fragments. The caller's says the
// receiver is the result of that one call (ExternalCall.ReceiverProducer),
// the factory's what every return of it builds (Function.Constructs, read
// from the fragment's constructs, graph-fragment-1.39). The
// stitch holds both, so it types the receiver there, and the dispatch policy
// narrows the call's candidates by that type as it does for a receiver the
// producer typed itself (disambiguateByReceiverType). An object built with
// `new T(...)` is a T and no subclass of it, so no other override can run.
//
// It only ever narrows: without one of the two facts the call keeps the
// candidates, and the verdict, it has without this rule.

// constructsRecorded reports whether a fragment's constructs fields can be
// read, which only a Java fragment's can: the producer writes them for Java
// functions only, where `new T(...)` builds a T and nothing else.
func constructsRecorded(ecosystem string, component ComponentKey) bool {
	if ecosystem == "" {
		ecosystem = EcosystemForPurl(component.Purl)
	}
	return ecosystem == "java"
}

// ClassKey is the `package.(Type)` key of a class, the form of
// GraphFragmentFunction.Constructs: the owner of its constructor's function
// key.
func ClassKey(pkg, typ string) string {
	if pkg == "" {
		return "(" + typ + ")"
	}
	return pkg + ".(" + typ + ")"
}

// classKeyParts splits a `package.(Type)` class key.
func classKeyParts(class string) (pkg, typ string) {
	open := strings.LastIndex(class, "(")
	if open < 0 || !strings.HasSuffix(class, ")") {
		return "", ""
	}
	return strings.TrimSuffix(class[:open], "."), class[open+1 : len(class)-1]
}

// typeConstructedReceivers gives each call whose receiver its producer left
// untyped the class its ReceiverProducer constructs. The producer is resolved
// as a call to it from the same caller would be, and must be one function.
func typeConstructedReceivers(edges []callEdge, resolve edgeResolver, functionsByNode map[graphNode]*Function) {
	for i := range edges {
		e := &edges[i]
		if e.receiverProducer == "" || e.resolvedReceiverType != "" {
			continue
		}
		targets := resolve(callEdge{caller: e.caller, target: e.receiverProducer, resolution: ResolutionExact})
		if len(targets.nodes) != 1 || targets.compatibility || targets.nameOnly {
			continue
		}
		fn := functionsByNode[targets.nodes[0]]
		if fn == nil || fn.Constructs == "" {
			continue
		}
		e.receiverPackage, e.resolvedReceiverType = classKeyParts(fn.Constructs)
		e.receiverConstructed = true
	}
}

// declaredIn reports whether owner, a fully qualified type, is declared in
// pkg: directly, or nested in a type of it (`pkg.Outer.Type`, which a
// constructor call inside Outer keys as `pkg.(Type)`).
func declaredIn(owner, pkg string) bool {
	if pkg == "" {
		return !strings.Contains(owner, ".")
	}
	return strings.HasPrefix(owner, pkg+".")
}
