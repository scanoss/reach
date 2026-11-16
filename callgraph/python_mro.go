// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// pythonClassIndex answers which declaration a method name reaches on a
// Python class, through the class's method resolution order over the bases
// the parser recorded (SourceSupertypes, python_supertypes.go). Only the
// classes of this graph declare methods; a base outside it (a dependency, the
// standard library, builtins) ends its branch of the order.
type pythonClassIndex struct {
	bases map[string][]string
	// methods maps a class (declOwnerFQN) to its declarations by name.
	methods map[string]map[string]string
	// ids maps a class to the Package and Type its declarations are keyed by.
	ids    map[string]FunctionID
	orders map[string][]string
}

func newPythonClassIndex(graph *CallGraph) *pythonClassIndex {
	idx := &pythonClassIndex{
		bases:   graph.SourceSupertypes,
		methods: make(map[string]map[string]string),
		ids:     make(map[string]FunctionID),
		orders:  make(map[string][]string),
	}
	for key, fn := range graph.Functions {
		if fn == nil || fn.ID.Type == "" || fn.OwnerType != ownerTypeClass {
			continue
		}
		owner := declOwnerFQN(fn.ID)
		if idx.methods[owner] == nil {
			idx.methods[owner] = make(map[string]string)
			idx.ids[owner] = FunctionID{Package: fn.ID.Package, Type: fn.ID.Type}
		}
		idx.methods[owner][fn.ID.Name] = key
	}
	return idx
}

// order is the class's method resolution order: C3 linearization of its
// bases' orders, the class first. Python refuses to create a class whose
// bases have no consistent order; for such input (or a cycle) the order falls
// back to a depth-first, left-to-right walk without repeats.
func (idx *pythonClassIndex) order(class string) []string {
	return idx.orderVisiting(class, map[string]bool{})
}

func (idx *pythonClassIndex) orderVisiting(class string, visiting map[string]bool) []string {
	if order, ok := idx.orders[class]; ok {
		return order
	}
	if visiting[class] {
		return []string{class}
	}
	visiting[class] = true
	bases := idx.bases[class]
	sequences := make([][]string, 0, len(bases)+1)
	for _, base := range bases {
		sequences = append(sequences, append([]string(nil), idx.orderVisiting(base, visiting)...))
	}
	sequences = append(sequences, append([]string(nil), bases...))
	merged, ok := pythonC3Merge(sequences)
	if !ok {
		merged = pythonDepthFirstOrder(sequences)
	}
	order := append([]string{class}, merged...)
	delete(visiting, class)
	idx.orders[class] = order
	return order
}

// pythonC3Merge merges linearizations the way CPython does: repeatedly take
// the first head that is in no other sequence's tail.
func pythonC3Merge(sequences [][]string) ([]string, bool) {
	var out []string
	for {
		live := sequences[:0]
		for _, seq := range sequences {
			if len(seq) > 0 {
				live = append(live, seq)
			}
		}
		sequences = live
		if len(sequences) == 0 {
			return out, true
		}
		head := ""
		for _, seq := range sequences {
			if !pythonInAnyTail(seq[0], sequences) {
				head = seq[0]
				break
			}
		}
		if head == "" {
			return nil, false
		}
		out = append(out, head)
		for i, seq := range sequences {
			if seq[0] == head {
				sequences[i] = seq[1:]
			}
		}
	}
}

func pythonInAnyTail(class string, sequences [][]string) bool {
	for _, seq := range sequences {
		for _, c := range seq[1:] {
			if c == class {
				return true
			}
		}
	}
	return false
}

func pythonDepthFirstOrder(sequences [][]string) []string {
	seen := make(map[string]bool)
	var out []string
	for _, seq := range sequences {
		for _, class := range seq {
			if !seen[class] {
				seen[class] = true
				out = append(out, class)
			}
		}
	}
	return out
}

// declaration returns the key of the declaration method reaches on class:
// the first class of its order that declares it, after class itself when
// fromSuper (`super().m()`).
func (idx *pythonClassIndex) declaration(class, method string, fromSuper bool) (string, bool) {
	for i, c := range idx.order(class) {
		if i == 0 && fromSuper {
			continue
		}
		if key, ok := idx.methods[c][method]; ok {
			return key, true
		}
	}
	return "", false
}

// classID returns the Package and Type a class is keyed by: from its
// declarations, else (a class this graph declares no method of, or does not
// declare) split at its last dot.
func (idx *pythonClassIndex) classID(class string) FunctionID {
	if id, ok := idx.ids[class]; ok {
		return id
	}
	cut := strings.LastIndex(class, ".")
	if cut <= 0 {
		return FunctionID{Type: class}
	}
	return FunctionID{Package: class[:cut], Type: class[cut+1:]}
}

// resolvePythonOwnClassCalls points each call on the caller's own class
// (FunctionCall.pythonOwner) at the declaration the method resolution order
// gives: `self._check()` in a subclass reaches the base class's _check, and
// `cls(...)` the nearest __init__. A method no class of the graph declares
// keeps the caller's class as its type (`(Leaf).m`), the receiver the call
// is made on, for dispatch and the stitch's hierarchy to settle; a super()
// call names the class's first base instead.
func resolvePythonOwnClassCalls(graph *CallGraph, idx *pythonClassIndex) {
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if call.pythonOwner == "" {
				continue
			}
			owner := call.Callee.Package + "." + call.pythonOwner
			if key, ok := idx.declaration(owner, call.Callee.Name, call.pythonSuper); ok {
				call.Callee = graph.Functions[key].ID
				continue
			}
			if call.pythonSuper {
				if bases := idx.bases[owner]; len(bases) > 0 {
					base := idx.classID(bases[0])
					call.Callee.Package, call.Callee.Type = base.Package, base.Type
				}
			}
		}
	}
}

// classMemberDeclaration returns the method a call on a class object reaches
// when the callee names no declaration itself: `Signer.default()` after
// `from m import Signer` is keyed `m.Signer.default` (the import's path is
// the callee's package), and `mod.Signer.default()` the same way. The class
// may be reached through a package's re-export; the method is the first of
// the class's method resolution order that declares it. The callee keeps its
// spelling.
func (idx *pythonClassIndex) classMemberDeclaration(graph *CallGraph, callee FunctionID, calleeKey string) (string, bool) {
	if idx == nil || callee.Type != "" || callee.Package == "" || callee.Name == constructorMethodName {
		return "", false
	}
	if _, declared := graph.Functions[calleeKey]; declared {
		return "", false
	}
	class, ok := idx.knownClass(graph, callee.Package)
	if !ok {
		return "", false
	}
	return idx.declaration(class, callee.Name, false)
}

// typedMethodDeclaration returns the method a call typed with a class reaches
// when the callee names no declaration itself: the class inherits the method,
// or the graph knows the class under another module's name (`remote.fetch()`
// on `remote: Remote` after `from app.other import Remote`, Remote declared
// in app.remote, is keyed `app.other.(Remote).fetch`). The method is the
// first of the class's method resolution order that declares it. The callee
// keeps its spelling.
func (idx *pythonClassIndex) typedMethodDeclaration(graph *CallGraph, callee FunctionID, calleeKey string) (string, bool) {
	if idx == nil || callee.Type == "" || callee.Package == "" || callee.Name == constructorMethodName {
		return "", false
	}
	if _, declared := graph.Functions[calleeKey]; declared {
		return "", false
	}
	class, ok := idx.knownClass(graph, callee.Package+"."+callee.Type)
	if !ok {
		return "", false
	}
	return idx.declaration(class, callee.Name, false)
}

// knownClass returns the class a dotted path names: the class itself, or the
// one a package's `__init__.py` or another module imports under that path.
func (idx *pythonClassIndex) knownClass(graph *CallGraph, path string) (string, bool) {
	if _, known := idx.bases[path]; known {
		return path, true
	}
	class, ok := pythonImportedPath(graph, path)
	if _, known := idx.bases[class]; !ok || !known {
		return "", false
	}
	return class, true
}

// pythonImportedPath returns the declaration a dotted path names through an
// import: a package's public path, else another module's from-import.
func pythonImportedPath(graph *CallGraph, path string) (string, bool) {
	if target, ok := graph.PythonPublicPaths[path]; ok {
		return target, true
	}
	target, ok := graph.pythonImportedNames[path]
	return target, ok
}

// constructorDeclaration returns the __init__ a class instantiation reaches
// when the callee names no declaration itself: `Leaf(..)` keyed by its module
// (`m.Leaf`), a nested `Outer.Inner(..)` (`m.(Outer).Inner`), a class
// reached through a package's re-export, and a typed constructor
// `m.(Leaf).<init>` of a class that inherits its __init__. The callee keeps
// its own spelling, the one contracts key on; the edge goes to the nearest
// __init__ of the class's method resolution order.
func (idx *pythonClassIndex) constructorDeclaration(graph *CallGraph, callee FunctionID, calleeKey string) (string, bool) {
	if idx == nil || callee.Package == "" {
		return "", false
	}
	if _, declared := graph.Functions[calleeKey]; declared {
		return "", false
	}
	var class string
	switch {
	case callee.Name == constructorMethodName:
		class = callee.Package + "." + callee.Type
	case callee.Type == "":
		class = callee.Package + "." + callee.Name
	default:
		class = callee.Package + "." + callee.Type + "." + callee.Name
	}
	class, ok := idx.knownClass(graph, class)
	if !ok {
		return "", false
	}
	return idx.declaration(class, constructorMethodName, false)
}

// pythonBindsStatically reports whether a Python call binds the one
// declaration its callee names, with no override in a subclass as a target:
// `super().m()` reaches the next class of the method resolution order that
// declares m whatever self's class, and `C(..)` runs the __init__ of C's own
// order, never a subclass's. `cls(..)` and `self.m()` may reach a subclass
// and keep their dispatch.
func pythonBindsStatically(call *FunctionCall) bool {
	return call.pythonSuper || (call.pythonOwner == "" && BaseFunctionName(call.Callee.Name) == constructorMethodName)
}
