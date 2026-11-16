// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	"github.com/scanoss/reach/callgraph/contracts"
)

// pythonFieldTypingRounds bounds the passes typePythonSelfFieldReceivers
// makes: a field assigned from a call on another field (`self.b =
// self.a.make()`) is typed one pass after that field.
const pythonFieldTypingRounds = 4

// pythonInertBaseModules are the modules whose classes, as bases, write no
// attribute a subclass's code could also use: builtins, the abc and typing
// machinery, enum (whose own attributes are sunder and dunder names).
var pythonInertBaseModules = []string{pythonBuiltinsModule, "abc", "enum", "typing", "typing_extensions", "collections.abc"}

// typePythonSelfFieldReceivers types the calls on `self.<field>` receivers
// (`self._session.get(..)`, keyed by the receiver's text) with the class the
// field holds, when every write of the field that can reach self says the
// same class:
//
//   - the writes are those of the attribute on the instances of the caller's
//     class K: in K's methods and body, and in those of every class of the
//     method resolution order of K and of each subclass of K (self may be an
//     instance of any of them);
//   - the field's own annotation (`x: C` in the body, `self.x: C = ..`, a
//     property's return annotation) decides, when they all name one class;
//   - a module statement's write on a module-level object (`_obj.f = v`
//     after `_obj = K()`, the module binding _obj once, to that call) is a
//     write on K's instances too;
//   - otherwise each write tells its class: a typed parameter or local
//     stored as is, a call whose result the graph knows (`C(..)`, a function
//     annotated to return C, a contract's return type, `cast(C, v)`), self,
//     a module-level object (its call's class), an attribute read off any of
//     those whose class the field typing knows; None tells nothing;
//   - the field is not typed when a write tells no class, when two writes
//     tell different classes, when a class of that set has a base outside
//     the graph (other than builtins, abc and typing), sets attributes by
//     computed names or customizes attribute access, or when any code writes
//     an attribute of that name on an object other than self or a
//     module-level object whose class is known.
//
// A field typed by a class the graph declares points the call at that class
// (the builder reaches the method through its method resolution order); one
// typed by a dependency's or the standard library's class names that class.
// Returns the number of calls typed.
func typePythonSelfFieldReceivers(graph *CallGraph, kb *contracts.KnowledgeBase) int {
	if len(graph.pythonFields) == 0 {
		return 0
	}
	t := newPythonFieldTyper(graph, kb)
	total := 0
	for round := 0; round < pythonFieldTypingRounds; round++ {
		t.fieldTypes = make(map[string]pythonFieldType)
		typed := t.retype()
		total += typed
		if typed == 0 {
			break
		}
	}
	return total
}

type pythonFieldType struct {
	ref pythonClassRef
	ok  bool
}

type pythonFieldTyper struct {
	graph   *CallGraph
	kb      *contracts.KnowledgeBase
	idx     *pythonClassIndex
	classes map[string]bool
	modules map[string]bool
	// writes holds each class's field writes, by field.
	writes   map[string]map[string][]*pythonFieldWrite
	foreign  map[string]bool
	open     map[string]bool
	shadowed map[string][][2]int
	subs     map[string][]string
	// related memoizes, by class, the classes whose writes reach its
	// instances' fields; nil when one of them is outside the graph.
	related    map[string][]string
	fieldTypes map[string]pythonFieldType
	// objects holds the binding of each module-level object, by
	// `<module>.<name>` (pythonFieldFacts.objects).
	objects map[string]*pythonFieldWrite
}

func newPythonFieldTyper(graph *CallGraph, kb *contracts.KnowledgeBase) *pythonFieldTyper {
	t := &pythonFieldTyper{
		graph:    graph,
		kb:       kb,
		idx:      newPythonClassIndex(graph),
		classes:  indexKnownClassTypes(graph),
		modules:  make(map[string]bool),
		writes:   make(map[string]map[string][]*pythonFieldWrite),
		foreign:  make(map[string]bool),
		open:     make(map[string]bool),
		shadowed: make(map[string][][2]int),
		subs:     make(map[string][]string),
		related:  make(map[string][]string),
		objects:  make(map[string]*pythonFieldWrite),
	}
	t.idx.bases = pythonPublicPathBases(graph)
	for owner, bases := range t.idx.bases {
		for _, base := range bases {
			t.subs[base] = append(t.subs[base], owner)
		}
	}
	for _, fn := range graph.Functions {
		t.modules[fn.ID.Package] = true
	}
	for _, facts := range graph.pythonFields {
		for name := range facts.objects {
			w := facts.objects[name]
			t.objects[name] = &w
		}
	}
	for _, facts := range graph.pythonFields {
		for i := range facts.writes {
			w := &facts.writes[i]
			class := w.class
			if w.object != (pythonClassRef{}) {
				// A write on a module-level object reaches the instances of
				// the class its call returns; one of an object whose class is
				// not known may reach any instance.
				ref, ok := t.objectClass(w.object)
				if !ok {
					t.foreign[w.field] = true
					continue
				}
				class = ref.fqn()
			} else if w.target != (pythonClassRef{}) {
				// A write on an annotated receiver reaches the instances of
				// its class; one whose annotation names no class may reach
				// any instance.
				ref, ok := t.validClass(w.target)
				if !ok {
					t.foreign[w.field] = true
					continue
				}
				class = ref.fqn()
			}
			if t.writes[class] == nil {
				t.writes[class] = make(map[string][]*pythonFieldWrite)
			}
			t.writes[class][w.field] = append(t.writes[class][w.field], w)
		}
		for field := range facts.foreign {
			t.foreign[field] = true
		}
		for class := range facts.open {
			t.open[class] = true
		}
		for caller, spans := range facts.shadowed {
			t.shadowed[caller] = append(t.shadowed[caller], spans...)
		}
	}
	return t
}

// retype types every untyped `self.<field>` call it can and returns how many
// it typed.
func (t *pythonFieldTyper) retype() int {
	// The types are all read before any call is typed, so what one round
	// types does not depend on the order it visits the calls in.
	type retyped struct {
		call *FunctionCall
		ref  pythonClassRef
	}
	var typed []retyped
	for key, fn := range t.graph.Functions {
		if fn.OwnerType != ownerTypeClass || fn.ID.Type == "" || fn.pythonStatic || !isPythonSourceFile(fn.FilePath) {
			continue
		}
		class := fn.ID.Package + "." + fn.ID.Type
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if call.pythonUntyped == "" || call.Callee.String() != call.pythonUntyped {
				continue
			}
			path, ok := pythonSelfAttributePath(call.Callee.Type)
			if !ok || t.inShadow(key, call.Line) {
				continue
			}
			if ref, ok := t.pathType(class, path); ok {
				typed = append(typed, retyped{call: call, ref: ref})
			}
		}
	}
	for _, r := range typed {
		r.call.Callee.Package, r.call.Callee.Type = r.ref.pkg, r.ref.typ
		r.call.ResolvedReceiverType = r.ref.typ
	}
	return len(typed)
}

// pythonSelfAttributePath splits a receiver text `self.a.b` (or `cls.a`)
// into its attributes. A part that is no attribute name (`make()`, `a[0]`)
// names no field any write records, so it types nothing.
func pythonSelfAttributePath(receiver string) ([]string, bool) {
	head, rest, ok := strings.Cut(receiver, ".")
	if !ok || head != pythonSelfObjectName && head != pythonClsObjectName {
		return nil, false
	}
	return strings.Split(rest, "."), true
}

// pathType is the class `self.a.b` holds in a method of class: a's class
// on class's instances, then b's on that class's instances. A class outside
// the graph has no typed fields (relatedClasses).
func (t *pythonFieldTyper) pathType(class string, path []string) (pythonClassRef, bool) {
	var ref pythonClassRef
	for i, attr := range path {
		if i > 0 {
			class = ref.fqn()
		}
		ft := t.fieldType(class, attr)
		if !ft.ok {
			return pythonClassRef{}, false
		}
		ref = ft.ref
	}
	return ref, true
}

func (t *pythonFieldTyper) inShadow(caller string, line int) bool {
	for _, span := range t.shadowed[caller] {
		if line >= span[0] && line <= span[1] {
			return true
		}
	}
	return false
}

func (t *pythonFieldTyper) fieldType(class, field string) pythonFieldType {
	key := class + "\x00" + field
	if ft, ok := t.fieldTypes[key]; ok {
		return ft
	}
	// Seeded before the writes are read: a field whose writes read the field
	// itself (`self.x = self.x.parent`, or through other fields) is untyped,
	// not a loop.
	t.fieldTypes[key] = pythonFieldType{}
	ft := t.computeFieldType(class, field)
	t.fieldTypes[key] = ft
	return ft
}

func (t *pythonFieldTyper) computeFieldType(class, field string) pythonFieldType {
	if t.foreign[field] {
		return pythonFieldType{}
	}
	related := t.relatedClasses(class)
	if related == nil {
		return pythonFieldType{}
	}
	var declared, found pythonClassRef
	conflict := false
	for _, c := range related {
		if t.open[c] {
			return pythonFieldType{}
		}
		for _, w := range t.writes[c][field] {
			ref, ok := t.writeType(w)
			if w.annotated && ok {
				if declared != (pythonClassRef{}) && declared != ref {
					return pythonFieldType{}
				}
				declared = ref
			}
			if !ok || (found != pythonClassRef{} && found != ref) {
				conflict = true
			}
			found = ref
		}
	}
	if declared != (pythonClassRef{}) {
		// The field's annotation is what every write must conform to.
		return pythonFieldType{ref: declared, ok: true}
	}
	if conflict {
		return pythonFieldType{}
	}
	return pythonFieldType{ref: found, ok: found != pythonClassRef{}}
}

// relatedClasses lists the classes whose code may write the attributes of an
// instance of class: those of the method resolution order of class and of
// each of its subclasses. Nil when one of them is outside the graph and not
// inert (pythonInertBaseModules).
func (t *pythonFieldTyper) relatedClasses(class string) []string {
	if related, ok := t.related[class]; ok {
		return related
	}
	seen := make(map[string]bool)
	var related []string
	complete := true
	var visit func(c string)
	visit = func(c string) {
		for _, m := range t.idx.order(c) {
			if seen[m] {
				continue
			}
			seen[m] = true
			if _, declared := t.graph.SourceSupertypes[m]; !declared && !pythonInertBase(m) {
				complete = false
			}
			related = append(related, m)
		}
		for _, sub := range t.subs[c] {
			if !seen[sub] {
				visit(sub)
			}
		}
	}
	visit(class)
	if !complete {
		related = nil
	}
	t.related[class] = related
	return related
}

// pythonPublicPathBases is SourceSupertypes with each base named through
// another module's import (`from pkg import Base` where pkg's `__init__.py`
// or any module pkg imports Base from pkg.impl) replaced by the class it
// names.
func pythonPublicPathBases(graph *CallGraph) map[string][]string {
	out := make(map[string][]string, len(graph.SourceSupertypes))
	for owner, bases := range graph.SourceSupertypes {
		resolved := bases
		for i, base := range bases {
			target, ok := graph.pythonImportedNames[base]
			if _, declared := graph.SourceSupertypes[target]; !ok || !declared {
				continue
			}
			if &resolved[0] == &bases[0] {
				resolved = append([]string(nil), bases...)
			}
			resolved[i] = target
		}
		out[owner] = resolved
	}
	return out
}

func pythonInertBase(class string) bool {
	for _, module := range pythonInertBaseModules {
		if strings.HasPrefix(class, module+".") {
			return true
		}
	}
	return false
}

// writeType is the class one write tells, ok false when it tells none: the
// class its evidence names, then, for each attribute of its path, the class
// that attribute of a graph class holds.
func (t *pythonFieldTyper) writeType(w *pythonFieldWrite) (pythonClassRef, bool) {
	var ref pythonClassRef
	var ok bool
	switch w.evidence {
	case pythonFieldDeclared, pythonFieldSelf:
		ref, ok = t.validClass(w.declared)
	case pythonFieldCall:
		ref, ok = t.callResultType(w)
	case pythonFieldObject:
		ref, ok = t.objectClass(w.declared)
	}
	for _, attr := range w.path {
		if !ok {
			return pythonClassRef{}, false
		}
		ft := t.fieldType(ref.fqn(), attr)
		ref, ok = ft.ref, ft.ok
	}
	return ref, ok
}

// objectClass is the class of a module-level object (`<module>.<name>`, also
// named through another module's import or a package's public path): the
// class the call it is bound to returns.
func (t *pythonFieldTyper) objectClass(object pythonClassRef) (pythonClassRef, bool) {
	binding := t.objects[object.fqn()]
	if binding == nil {
		if target, ok := pythonImportedPath(t.graph, object.fqn()); ok {
			binding = t.objects[target]
		}
	}
	if binding == nil {
		return pythonClassRef{}, false
	}
	return t.callResultType(binding)
}

// callResultType is the class the call a write assigns returns: a
// constructor's class, a function's annotated return class, a contract's
// return type. An `async def` returns its annotated class only when awaited.
func (t *pythonFieldTyper) callResultType(w *pythonFieldWrite) (pythonClassRef, bool) {
	fn := t.graph.Functions[w.caller]
	if fn == nil {
		return pythonClassRef{}, false
	}
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.Line != w.line || call.StartCol != w.col || call.EndLine != w.endLine || call.EndCol != w.endCol {
			continue
		}
		if call.pythonUntyped != "" && call.Callee.String() == call.pythonUntyped {
			return pythonClassRef{}, false
		}
		callee := t.graph.Functions[call.Callee.String()]
		if callee != nil && callee.pythonAsync != w.awaited {
			return pythonClassRef{}, false
		}
		if callee == nil && w.awaited {
			return pythonClassRef{}, false
		}
		returnType, declPackage := pythonCalleeReturnType(call, t.graph, t.kb, t.classes, fn.ID.Package)
		if returnType == "" {
			return pythonClassRef{}, false
		}
		pkg, typ := pythonSplitAssignedType(pythonTrackedAssignedType{name: returnType, declPackage: declPackage})
		return t.validClass(pythonClassRef{pkg: pkg, typ: typ})
	}
	return pythonClassRef{}, false
}

// validClass accepts a class the graph declares (also named through another
// module's import, pythonImportedNames) and a class of a module the graph does not hold (a
// dependency's, the standard library's); a name of a graph module that is no
// class of it (an alias, a function) is refused.
func (t *pythonFieldTyper) validClass(ref pythonClassRef) (pythonClassRef, bool) {
	if ref.pkg == "" || ref.typ == "" {
		return pythonClassRef{}, false
	}
	fqn := ref.fqn()
	if _, declared := t.graph.SourceSupertypes[fqn]; declared {
		return ref, true
	}
	if target, ok := pythonImportedPath(t.graph, fqn); ok {
		if _, declared := t.graph.SourceSupertypes[target]; declared {
			id := t.idx.classID(target)
			return pythonClassRef{pkg: id.Package, typ: id.Type}, true
		}
		return pythonClassRef{}, false
	}
	if t.modules[ref.pkg] || t.modules[fqn] {
		return pythonClassRef{}, false
	}
	return ref, true
}
