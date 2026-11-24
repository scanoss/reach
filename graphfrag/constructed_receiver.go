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
// the factory's what every return of it builds (Function.Constructs). The
// stitch holds both, so it types the receiver there, and the dispatch policy
// narrows the call's candidates by that type as it does for a receiver the
// producer typed itself (disambiguateByReceiverType). An object built with
// `new T(...)` is a T and no subclass of it, so no other override can run.
//
// It only ever narrows: without one of the two facts the call keeps the
// candidates, and the verdict, it has without this rule.

// constructsRecorded reports whether a fragment's return provenance tells an
// instantiation from any other call, which only a Java fragment's does: its
// constructors are keyed `<init>`.
func constructsRecorded(ecosystem string, component ComponentKey) bool {
	if ecosystem == "" {
		ecosystem = EcosystemForPurl(component.Purl)
	}
	return ecosystem == "java"
}

const constructorKeyName = "<init>"

// constructedClass is the one class every return of a function builds with
// `new`, as `package.(Type)`, read from its return provenance; "" when the
// returns do not single one out. A return of null yields no object and is
// passed over. `new T() { ... }` builds an anonymous subclass of T, not a T.
func constructedClass(returns []GraphFragmentRawSource) string {
	class := ""
	for i := range returns {
		source := &returns[i]
		if source.Type == "VALUE" && source.Value == "null" {
			continue
		}
		built := instantiatedClass(source)
		if built == "" || (class != "" && built != class) {
			return ""
		}
		class = built
	}
	return class
}

func instantiatedClass(source *GraphFragmentRawSource) string {
	if source.Type != "CALL_RESULT" || !strings.HasPrefix(source.Value, "new ") || !strings.HasSuffix(source.Value, ")") {
		return ""
	}
	pkg, typ, name, ok := functionKeyParts(source.CallTarget)
	if !ok || !strings.HasPrefix(name, constructorKeyName+"#") {
		return ""
	}
	return classKey(pkg, typ)
}

func classKey(pkg, typ string) string {
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
