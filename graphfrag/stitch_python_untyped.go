// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"slices"
	"strings"
)

// stitch_python_untyped.go keeps a Python call into a dependency that the
// stitch cannot resolve from reading unreachable. A typed call that names a
// dependency's module (`urllib3.Retry.DEFAULT_ALLOWED_METHODS.union`,
// `cryptography.hazmat.backends.backend.x(..)`, a name the dependency
// re-exports from another one) but no declaration of it reaches some code of
// that dependency the fragments do not name: it joins the dependency's
// functions of the called name, as a name_only call does, so a finding it
// may reach reads unknown, never reachable.

// pythonModules maps each module path (and package) the closure's Python
// components declare functions in, or export public names from, to the
// components that do.
type pythonModules struct {
	owners map[string][]ComponentKey
	// inits are the `__init__` nodes of the closure's classes by simple
	// class name: what calling a class of that name runs.
	inits map[string][]graphNode
}

func indexPythonModules(closure []ComponentKey, fragments map[ComponentKey]Fragment) pythonModules {
	m := pythonModules{owners: make(map[string][]ComponentKey), inits: make(map[string][]graphNode)}
	// A module's packages are the component's too (`jwt` for `jwt.algorithms`).
	add := func(module string, key ComponentKey) {
		for module != "" {
			if !slices.Contains(m.owners[module], key) {
				m.owners[module] = append(m.owners[module], key)
			}
			dot := strings.LastIndex(module, ".")
			if dot < 0 {
				return
			}
			module = module[:dot]
		}
	}
	for _, key := range closure {
		fragment := fragments[key]
		if fragmentEcosystem(fragment) != "python" {
			continue
		}
		for i := range fragment.Functions {
			signature := fragment.Functions[i].Signature
			add(pythonKeyModule(signature), key)
			if owner, local, ok := splitFunctionKey(signature); ok && local == pythonConstructorName {
				name := owner[strings.LastIndex(owner, ".")+1:]
				m.inits[name] = append(m.inits[name], graphNode{Component: key, Function: signature})
			}
		}
		for public := range fragment.Exports {
			if dot := strings.LastIndex(public, "."); dot > 0 {
				add(public[:dot], key)
			}
		}
	}
	return m
}

// pythonKeyModule is the module a Python function key is declared in:
// `jwt.api_jwt` for `jwt.api_jwt.(PyJWT).encode` and `jwt.api_jwt.encode`.
func pythonKeyModule(key string) string {
	if open := strings.Index(key, ".("); open >= 0 {
		return key[:open]
	}
	if dot := strings.LastIndex(key, "."); dot >= 0 {
		return key[:dot]
	}
	return key
}

// dependencyOwners returns the components other than self whose module a
// call target names: the owners of its longest dotted prefix any component
// declares. A target in a module of self's own (an instantiation spelled at
// the class's path, which the producer also links internally) is not a call
// into a dependency, nor is one no component declares (the standard library).
func (m pythonModules) dependencyOwners(target string, self ComponentKey) []ComponentKey {
	if open := strings.Index(target, ".("); open >= 0 {
		target = target[:open]
	}
	for prefix := target; prefix != ""; {
		if owners, ok := m.owners[prefix]; ok {
			var out []ComponentKey
			for _, k := range owners {
				if k == self {
					return nil
				}
				out = append(out, k)
			}
			return out
		}
		dot := strings.LastIndex(prefix, ".")
		if dot < 0 {
			break
		}
		prefix = prefix[:dot]
	}
	return nil
}

// unresolvedInto is the name_only reading of an exact call of self the
// resolver left without a target: the functions of the called name, and the
// `__init__` of the classes of that name, in the components whose module the
// target names. Nil when the target names no dependency module.
func (m pythonModules) unresolvedInto(e callEdge, self ComponentKey, byMethodArity map[string][]graphNode) ([]graphNode, bool) {
	owners := m.dependencyOwners(e.target, self)
	if len(owners) == 0 || e.method == "" || pythonImportTimeMethod(e.method) {
		return nil, false
	}
	in := make(map[ComponentKey]bool, len(owners))
	for _, k := range owners {
		in[k] = true
	}
	var nodes []graphNode
	for _, list := range [][]graphNode{byMethodArity[arityFreeMethodKey(e.method)], m.inits[e.method]} {
		for _, n := range list {
			if in[n.Component] {
				nodes = append(nodes, n)
			}
		}
	}
	if len(nodes) == 0 {
		// A class the dependency re-exports from another component
		// (`requests.adapters.Retry` is urllib3's) is named by its module
		// but declared elsewhere: the `__init__` of a class of that name
		// anywhere but in self.
		for _, n := range m.inits[e.method] {
			if n.Component != self {
				nodes = append(nodes, n)
			}
		}
	}
	return nodes, true
}

// pythonImportTimeMethod reports the method of an import-time edge, an
// importer's `<module>` into the imported module's, or `<module>` into a
// class body's `<clinit>`: one the dependency does not declare runs no code
// (a module without top-level code, a from-imported name that is no module),
// so it has no name_only reading.
func pythonImportTimeMethod(method string) bool {
	return method == "<module>" || method == "<clinit>"
}

// pythonUnresolvedAsNameOnly wraps resolve for a Python component: an
// external exact call it leaves without a target, whose target names a
// dependency's module, takes the name_only candidates of unresolvedInto.
func pythonUnresolvedAsNameOnly(resolve edgeResolver, self ComponentKey, modules pythonModules, byMethodArity map[string][]graphNode) edgeResolver {
	return func(e callEdge) edgeTargets {
		targets := resolve(e)
		if len(targets.nodes) > 0 || e.internal || e.resolution != ResolutionExact {
			return targets
		}
		if nodes, into := modules.unresolvedInto(e, self, byMethodArity); into {
			return edgeTargets{nodes: nodes, nameOnly: true}
		}
		return targets
	}
}

// pythonBuiltinMethods are the methods of Python's builtin value types (str,
// bytes, bytearray, dict, list, set, frozenset, tuple, int, float, complex,
// memoryview; Python 3.12, dunders left out).
var pythonBuiltinMethods = func() map[string]bool {
	out := make(map[string]bool)
	for _, m := range strings.Fields(`add append as_integer_ratio bit_count bit_length capitalize casefold cast
		center clear conjugate copy count decode difference difference_update discard encode endswith
		expandtabs extend find format format_map from_bytes fromhex fromkeys get hex index insert
		intersection intersection_update is_integer isalnum isalpha isascii isdecimal isdigit isdisjoint
		isidentifier islower isnumeric isprintable isspace issubset issuperset istitle isupper items join
		keys ljust lower lstrip maketrans partition pop popitem release remove removeprefix removesuffix
		replace reverse rfind rindex rjust rpartition rsplit rstrip setdefault sort split splitlines
		startswith strip swapcase symmetric_difference symmetric_difference_update title to_bytes tobytes
		tolist toreadonly translate union update upper values zfill`) {
		out[m] = true
	}
	return out
}()

// pythonNameOnlyCandidates gives a Python component's name_only calls their
// candidates: the functions of the called name in the component itself (the
// producer links an untyped call to nothing, not even to its own methods:
// pyjwt's `self._jws.encode(..)` runs its own `PyJWS.encode`) and in scope
// (the declared dependencies, or the whole environment under
// EnvironmentTargets: a value whose type the caller cannot name may come
// from any installed package).
//
// A method name of a builtin value type (`get`, `items`, `update`, `encode`,
// `decode`, `copy`) has candidates in other components only when the
// receiver is a dependency value: a local the caller assigns from a call into
// a dependency's module, a field of the caller's class some method assigns
// so, or the result of such a call earlier in the same chain. Measured on
// PyGithub and matrix-synapse, such names are 85% and 80% of the name_only
// calls with a candidate in a dependency, and every one read on a parameter,
// a self field, a literal-bound local or a builtin's result was a dict, str
// or bytes; so `params.update(..)` no longer reads cryptography's padding
// contexts as unknown, while `h = cryptography...Hash(..); h.update(..)`
// keeps them. "Earlier in the same chain" is a link the call's receiver
// holds (its span starts with the call's and ends inside it): the producer
// gives every call on a chain's line the chain's id, so a dependency call
// that takes the chain as an argument (`glob_to_regex(entry.encode().decode())`)
// shares it without being its receiver.
func pythonNameOnlyCandidates(resolve edgeResolver, self ComponentKey, fragment Fragment, modules pythonModules, byMethodArity map[string][]graphNode, scope map[ComponentKey]bool) edgeResolver {
	dependencyValues := make(map[string]bool)
	chainLinks := make(map[string][]callSpan)
	for i := range fragment.ExternalCalls {
		c := &fragment.ExternalCalls[i]
		if len(modules.dependencyOwners(c.TargetSignature, self)) == 0 {
			continue
		}
		if field, ok := strings.CutPrefix(c.AssignedVar, "self."); ok {
			dependencyValues[pythonCallerClass(c.Caller)+"\x00self\x00"+field] = true
		} else if c.AssignedVar != "" {
			dependencyValues[c.Caller+"\x00var\x00"+c.AssignedVar] = true
		}
		if c.ChainID != "" {
			k := c.Caller + "\x00" + c.ChainID
			chainLinks[k] = append(chainLinks[k], callSpan{line: c.CallSite, start: c.StartCol, end: c.EndCol})
		}
	}
	dependencyValue := func(e callEdge) bool {
		if field, ok := strings.CutPrefix(e.receiverVar, "self."); ok && dependencyValues[pythonCallerClass(e.caller)+"\x00self\x00"+field] {
			return true
		}
		if e.receiverVar != "" && dependencyValues[e.caller+"\x00var\x00"+e.receiverVar] {
			return true
		}
		if e.chainID == "" {
			return false
		}
		for _, link := range chainLinks[e.caller+"\x00"+e.chainID] {
			if link.receiverOf(e) {
				return true
			}
		}
		return false
	}
	return func(e callEdge) edgeTargets {
		if e.internal || e.resolution != ResolutionNameOnly || e.method == "" {
			return resolve(e)
		}
		if e.method == pythonClassValueName {
			return modules.classValueTargets(e, self, resolve)
		}
		others := !pythonBuiltinMethods[e.method] || dependencyValue(e)
		var targets edgeTargets
		for _, callee := range byMethodArity[nameOnlyLookupKey(e)] {
			if callee.Component == self || (others && scope[callee.Component]) {
				targets.nodes = append(targets.nodes, callee)
			}
		}
		return targets
	}
}

// pythonClassValueName is the method of the producer's class-value edges
// (`pkg.(K).<class>`): the class object K, read as a value where it is handed
// around (stored in a table, passed, returned), so it may be instantiated
// there through whatever holds it.
const pythonClassValueName = "<class>"

// classValueTargets are the candidates of a class-value edge: the `__init__`
// a call of K would run, as an exact call resolves it (K's own, or the one
// it inherits), else that of a class of K's name in the component the target
// names (self when it names self's module). Never the `__init__` of every
// class.
func (m pythonModules) classValueTargets(e callEdge, self ComponentKey, resolve edgeResolver) edgeTargets {
	exact := e
	exact.resolution, exact.method = ResolutionExact, pythonConstructorName
	exact.target = strings.TrimSuffix(e.target, pythonClassValueName) + pythonConstructorName
	if targets := resolve(exact); len(targets.nodes) > 0 && !targets.nameOnly {
		return edgeTargets{nodes: targets.nodes, nameOnly: true}
	}
	owner, _, ok := splitFunctionKey(e.target)
	if !ok {
		return edgeTargets{nameOnly: true}
	}
	class := owner[strings.LastIndex(owner, ".")+1:]
	in := map[ComponentKey]bool{self: true}
	if owners := m.dependencyOwners(e.target, self); len(owners) > 0 {
		in = make(map[ComponentKey]bool, len(owners))
		for _, k := range owners {
			in[k] = true
		}
	}
	var nodes []graphNode
	for _, n := range m.inits[class] {
		if in[n.Component] {
			nodes = append(nodes, n)
		}
	}
	return edgeTargets{nodes: nodes, nameOnly: true}
}

// pythonCallerClass is the class of a method key (`pkg.(C)` for
// `pkg.(C).m`), else the key itself.
func pythonCallerClass(caller string) string {
	if owner, local, ok := splitFunctionKey(caller); ok && owner != "" {
		return strings.TrimSuffix(caller, "."+local)
	}
	return caller
}

// callSpan is where a call expression sits: its line and 1-based columns.
type callSpan struct{ line, start, end int }

// receiverOf reports whether the call at s can be the receiver of e, a link
// earlier in e's chain: `dep.f(x)` of `dep.f(x).update(y)` starts where e
// starts and ends inside it. Without columns on either side it cannot tell,
// and keeps the chain's reading.
func (s callSpan) receiverOf(e callEdge) bool {
	if s.start == 0 || s.end == 0 || e.startCol == 0 || e.endCol == 0 {
		return true
	}
	return s.line == e.callSite && s.start >= e.startCol && s.end < e.endCol
}
