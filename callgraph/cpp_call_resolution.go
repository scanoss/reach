// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"sort"
	"strings"

	"github.com/rs/zerolog/log"

	"github.com/scanoss/reach/callgraph/contracts"
)

// resolveCPPCalls settles, once every file is parsed and before the caller
// index is built, which project definition each C++ call of the project
// names (graph-algo-cpp-4). The parser keys a call on what its own file says;
// this pass reads what other files declare:
//
//   - The receiver of a member call is typed from a local's or parameter's
//     declared type, a data member's declared type (`dh_->f()`,
//     `this->m_x.f()`), the declared return type of a project function
//     (`getInstance()->f()`, `key()->f()`, and an `auto` local bound to such
//     a call), or the constructed type of an `auto` local bound to a
//     construction. Through `->`, std::unique_ptr<T> and std::shared_ptr<T>
//     stand for T. A function whose return type is deduced (`const auto&
//     key() { return m_key; }`) returns its member's type. An unqualified
//     call in a member function is first looked up as a member of its class
//     (an implicit `this->`).
//   - A type or scope name is looked up as C++ looks it up: in the class and
//     the namespaces enclosing the caller, innermost first, then globally,
//     then in the namespaces the file's using-directives name. `DH d;
//     d.nonce();` inside namespace t names (t::DH).nonce.
//   - A method a class does not define is looked up in its base classes.
//   - A call that can dispatch (through a pointer, a reference, a smart
//     pointer, `this`, or an implicit `this`) also reaches the override in
//     every project class derived from the receiver's type, transitively
//     (class hierarchy analysis: every override, whether or not the class is
//     ever instantiated). Such an edge is interface_dispatch.
//   - A definition is found in any directory of the project, not only the
//     caller's: a C++ class is one class across its translation units. A
//     `static` function at namespace scope is found only from its own file.
//     When several definitions qualify (#if variants of one function, one
//     class compiled per platform), the call names the first and reaches
//     the others too.
//   - A constructor's member initializer list entry `m_x(args)` constructs
//     the member's declared type when it is a class held by value, or the
//     base it names; an entry for a pointer, a primitive, or a name no class
//     declares is not a call.
//
// Only a call that resolves to a definition in a project file, or to a
// method a project class declares, is rewritten; any other is left as the
// parser keyed it, so the contract KB passes type it exactly as before. An
// `auto` local whose producer the KB has an unconditional return for is left
// to resolveCPPDeducedReceiverCallees.
func (b *Builder) resolveCPPCalls(graph *CallGraph, kb *contracts.KnowledgeBase) {
	if b.ecosystem != ecosystemCPP || b.cppBuild == nil {
		return
	}
	r := newCPPResolver(graph, kb, b.cppBuild)
	keys := make([]string, 0, len(graph.Functions))
	for key, fn := range graph.Functions {
		if fn.cpp != nil && r.projectFiles[fn.FilePath] {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		fn := graph.Functions[key]
		for i := range fn.Calls {
			r.resolve(fn, &fn.Calls[i])
		}
	}
	// A member initializer entry the pass did not type, or did not read
	// (a dependency's), is no call.
	for _, fn := range graph.Functions {
		if fn.cpp == nil {
			continue
		}
		kept := fn.Calls[:0]
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if call.cpp != nil && call.cpp.shape == cppCallMemberInit {
				if _, resolved := r.results[call]; !resolved || call.cpp.drop {
					continue
				}
			}
			kept = append(kept, *call)
		}
		fn.Calls = kept
	}
	if r.rewritten > 0 {
		log.Info().Int("resolved", r.rewritten).Msg("Resolved C++ calls to project definitions")
	}
}

// cppBuildFacts accumulates, while files are merged, what resolveCPPCalls
// reads across files.
type cppBuildFacts struct {
	classes      []cppClassFacts
	usings       map[string][]string
	projectFiles map[string]bool
}

func newCPPBuildFacts() *cppBuildFacts {
	return &cppBuildFacts{usings: make(map[string][]string), projectFiles: make(map[string]bool)}
}

func (f *cppBuildFacts) add(analysis *FileAnalysis, projectLocal bool) {
	if projectLocal {
		f.projectFiles[analysis.FilePath] = true
	}
	if analysis.cppFacts == nil {
		return
	}
	f.classes = append(f.classes, analysis.cppFacts.classes...)
	if len(analysis.cppFacts.usings) > 0 {
		f.usings[analysis.FilePath] = analysis.cppFacts.usings
	}
}

// cppClass is one class, merged across its definitions' files.
type cppClass struct {
	name    string
	file    string
	fields  map[string]cppFieldFacts
	methods map[string]bool
	bases   []string
}

type cppResolver struct {
	graph        *CallGraph
	kb           *contracts.KnowledgeBase
	classes      map[string]*cppClass
	usings       map[string][]string
	projectFiles map[string]bool
	// defs indexes the project definitions by "Type|Name", the type
	// without template arguments.
	defs map[string][]*FunctionDecl
	// bases and children are the resolved direct bases and derived classes
	// of each class.
	bases    map[string][]string
	children map[string][]string
	results  map[*FunctionCall]*FunctionDecl
	visiting map[*FunctionCall]bool
	original map[*FunctionCall]FunctionID
	spans    map[*FunctionDecl]map[[4]int][]*FunctionCall

	rewritten int
}

// cppHierarchyDepth bounds the walks over the class hierarchy; it only
// guards against a malformed or cyclic one.
const cppHierarchyDepth = 32

func newCPPResolver(graph *CallGraph, kb *contracts.KnowledgeBase, facts *cppBuildFacts) *cppResolver {
	r := &cppResolver{
		graph:        graph,
		kb:           kb,
		classes:      make(map[string]*cppClass),
		usings:       facts.usings,
		projectFiles: facts.projectFiles,
		defs:         make(map[string][]*FunctionDecl),
		bases:        make(map[string][]string),
		children:     make(map[string][]string),
		results:      make(map[*FunctionCall]*FunctionDecl),
		visiting:     make(map[*FunctionCall]bool),
		original:     make(map[*FunctionCall]FunctionID),
		spans:        make(map[*FunctionDecl]map[[4]int][]*FunctionCall),
	}
	for i := range facts.classes {
		c := &facts.classes[i]
		name := cppStripTemplateArgs(c.name)
		class := r.classes[name]
		if class == nil {
			class = &cppClass{name: name, file: c.file, fields: make(map[string]cppFieldFacts), methods: make(map[string]bool)}
			r.classes[name] = class
		}
		for field, f := range c.fields {
			if _, seen := class.fields[field]; !seen {
				class.fields[field] = f
			}
		}
		for method := range c.methods {
			class.methods[method] = true
		}
		for _, base := range c.bases {
			if !slices.Contains(class.bases, base) {
				class.bases = append(class.bases, base)
			}
		}
	}
	for _, fn := range graph.Functions {
		if fn.cpp == nil || !r.projectFiles[fn.FilePath] {
			continue
		}
		key := cppStripTemplateArgs(fn.ID.Type) + "|" + fn.ID.Name
		r.defs[key] = append(r.defs[key], fn)
		if class := r.classes[cppStripTemplateArgs(fn.ID.Type)]; class != nil {
			class.methods[fn.ID.Name] = true
		}
	}
	for key := range r.defs {
		sort.Slice(r.defs[key], func(i, j int) bool { return r.defs[key][i].ID.String() < r.defs[key][j].ID.String() })
	}
	names := make([]string, 0, len(r.classes))
	for name := range r.classes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		class := r.classes[name]
		ctx := r.classContext(class)
		for _, base := range class.bases {
			resolved := r.resolveClass(base, ctx)
			if resolved == "" || resolved == name {
				continue
			}
			r.bases[name] = append(r.bases[name], resolved)
			r.children[resolved] = append(r.children[resolved], name)
		}
	}
	return r
}

// cppLookupContext is where a name written in some code is looked up: the
// class it is written in ("" for none), the enclosing scopes innermost first
// ending with the global one (""), and the file's using-directives.
type cppLookupContext struct {
	class  string
	scopes []string
	usings []string
}

func (r *cppResolver) functionContext(fn *FunctionDecl) cppLookupContext {
	owner := cppStripTemplateArgs(fn.ID.Type)
	ctx := cppLookupContext{scopes: cppEnclosingScopes(owner), usings: r.usings[fn.FilePath]}
	if r.classes[owner] != nil {
		ctx.class = owner
	}
	return ctx
}

func (r *cppResolver) classContext(class *cppClass) cppLookupContext {
	return cppLookupContext{class: class.name, scopes: cppEnclosingScopes(class.name), usings: r.usings[class.file]}
}

// cppEnclosingScopes lists a scope and each scope enclosing it, innermost
// first, ending with the global scope "": a::B → [a::B, a, ""].
func cppEnclosingScopes(scope string) []string {
	if scope == "" {
		return []string{""}
	}
	parts := cppSplitScope(scope)
	scopes := make([]string, 0, len(parts)+1)
	for i := len(parts); i > 0; i-- {
		scopes = append(scopes, strings.Join(parts[:i], "::"))
	}
	return append(scopes, "")
}

// nameCandidates lists the qualified names a name written in ctx may stand
// for, in lookup order.
func nameCandidates(name string, ctx cppLookupContext) []string {
	name = cppStripTemplateArgs(name)
	if global, ok := strings.CutPrefix(name, "::"); ok {
		return []string{global}
	}
	candidates := make([]string, 0, len(ctx.scopes)+len(ctx.usings))
	for _, scope := range ctx.scopes {
		if scope == "" {
			candidates = append(candidates, name)
		} else {
			candidates = append(candidates, scope+"::"+name)
		}
	}
	for _, ns := range ctx.usings {
		candidates = append(candidates, ns+"::"+name)
	}
	return candidates
}

// resolveClass names the class a type name written in ctx stands for, or "".
func (r *cppResolver) resolveClass(name string, ctx cppLookupContext) string {
	if name == "" {
		return ""
	}
	for _, candidate := range nameCandidates(name, ctx) {
		if r.classes[candidate] != nil {
			return candidate
		}
	}
	return ""
}

// cppTypeRef is a type as written, with where it was written; or a class
// already resolved.
type cppTypeRef struct {
	text  string
	ctx   cppLookupContext
	class string
}

// classOf names the class a value of type t is, read through `->` when
// arrow: the class a pointer or smart pointer points to.
func (r *cppResolver) classOf(t cppTypeRef, arrow bool) string {
	if t.class != "" {
		return t.class
	}
	text := cppBareType(t.text)
	if cppSmartPointer(cppStripTemplateArgs(text)) {
		args := cppTemplateArgs(text)
		if !arrow || len(args) == 0 {
			return ""
		}
		text = cppBareType(args[0])
	}
	return r.resolveClass(text, t.ctx)
}

// cppSmartPointer reports the owning smart pointers whose `->` reaches the
// pointee.
func cppSmartPointer(name string) bool {
	switch name {
	case "std::unique_ptr", "std::shared_ptr", "unique_ptr", "shared_ptr", "std::auto_ptr", "boost::shared_ptr", "boost::scoped_ptr":
		return true
	}
	return false
}

// cppBareType drops what does not name the type: cv-qualifiers, elaborated
// keywords, pointer and reference marks.
func cppBareType(text string) string {
	fields := strings.Fields(strings.NewReplacer("*", " ", "&", " ").Replace(text))
	kept := fields[:0]
	for _, f := range fields {
		switch f {
		case "const", "volatile", "struct", "class", "typename", "mutable":
			continue
		}
		kept = append(kept, f)
	}
	return cppCanonicalType(strings.Join(kept, " "))
}

// resolve settles one call and returns the project definition it names, or
// nil. Each call is settled once; a receiver that is another call settles
// that call first.
func (r *cppResolver) resolve(fn *FunctionDecl, call *FunctionCall) *FunctionDecl {
	if target, done := r.results[call]; done {
		return target
	}
	if r.visiting[call] {
		return nil
	}
	r.visiting[call] = true
	r.original[call] = call.Callee
	target := r.resolveCall(fn, call)
	delete(r.visiting, call)
	r.results[call] = target
	return target
}

func (r *cppResolver) resolveCall(fn *FunctionDecl, call *FunctionCall) *FunctionDecl {
	facts := call.cpp
	if facts == nil {
		return r.exact(call)
	}
	switch facts.shape {
	case cppCallFree:
		return r.resolveFree(fn, call)
	case cppCallQualified:
		return r.resolveQualified(fn, call)
	case cppCallMember:
		return r.resolveMember(fn, call)
	case cppCallConstruct:
		return r.resolveConstruct(fn, call)
	case cppCallMemberInit:
		return r.resolveMemberInit(fn, call)
	}
	return r.exact(call)
}

// exact is the project definition the call's key names as the parser keyed
// it.
func (r *cppResolver) exact(call *FunctionCall) *FunctionDecl {
	if fn := r.graph.Functions[call.Callee.String()]; fn != nil && fn.cpp != nil && r.projectFiles[fn.FilePath] {
		return fn
	}
	return nil
}

// keyed reports a call whose key names a definition of the graph, project or
// not: such a call is left as it is.
func (r *cppResolver) keyed(call *FunctionCall) bool {
	return r.graph.Functions[call.Callee.String()] != nil
}

// lookup lists the project definitions of qualified.name the caller can
// see: a static function only from its own file. The definitions in the
// caller's file or directory win over those elsewhere. With strict, only a
// definition taking as many arguments as the call passes (or more, for
// defaults) qualifies; otherwise one taking exactly as many is preferred.
func (r *cppResolver) lookup(qualified, name string, caller *FunctionDecl, arity int, strict bool) []*FunctionDecl {
	var near, far []*FunctionDecl
	for _, def := range r.defs[cppStripTemplateArgs(qualified)+"|"+name] {
		if def.cpp.static && def.FilePath != caller.FilePath {
			continue
		}
		if def.FilePath == caller.FilePath || def.OwnerName == caller.OwnerName {
			near = append(near, def)
		} else {
			far = append(far, def)
		}
	}
	found := near
	if len(found) == 0 {
		found = far
	}
	var exact, compatible []*FunctionDecl
	for _, def := range found {
		if len(def.Parameters) == arity {
			exact = append(exact, def)
		}
		if len(def.Parameters) >= arity {
			compatible = append(compatible, def)
		}
	}
	switch {
	case len(exact) > 0:
		return exact
	case strict:
		return compatible
	}
	return found
}

// findMethod looks a method up in a class and then in its bases, nearest
// first: the definitions found and the class that defines them.
func (r *cppResolver) findMethod(class, name string, caller *FunctionDecl, arity int, strict bool) ([]*FunctionDecl, string) {
	seen := map[string]bool{}
	level := []string{class}
	for depth := 0; depth < cppHierarchyDepth && len(level) > 0; depth++ {
		var next []string
		for _, c := range level {
			if seen[c] {
				continue
			}
			seen[c] = true
			if defs := r.lookup(c, name, caller, arity, strict); len(defs) > 0 {
				return defs, c
			}
			next = append(next, r.bases[c]...)
		}
		level = next
	}
	return nil, ""
}

// declares reports a class, or one of its bases, declaring a method.
func (r *cppResolver) declares(class, name string) bool {
	seen := map[string]bool{}
	level := []string{class}
	for depth := 0; depth < cppHierarchyDepth && len(level) > 0; depth++ {
		var next []string
		for _, c := range level {
			if seen[c] {
				continue
			}
			seen[c] = true
			if cls := r.classes[c]; cls != nil && cls.methods[name] {
				return true
			}
			next = append(next, r.bases[c]...)
		}
		level = next
	}
	return false
}

// field finds a data member in a class or its bases: its facts and the class
// that declares it.
func (r *cppResolver) field(class, name string) (cppFieldFacts, *cppClass, bool) {
	seen := map[string]bool{}
	level := []string{class}
	for depth := 0; depth < cppHierarchyDepth && len(level) > 0; depth++ {
		var next []string
		for _, c := range level {
			if seen[c] {
				continue
			}
			seen[c] = true
			if cls := r.classes[c]; cls != nil {
				if f, ok := cls.fields[name]; ok {
					return f, cls, true
				}
			}
			next = append(next, r.bases[c]...)
		}
		level = next
	}
	return cppFieldFacts{}, nil, false
}

// rewrite makes the call name the first of defs and reach the others.
func (r *cppResolver) rewrite(call *FunctionCall, defs []*FunctionDecl) *FunctionDecl {
	primary := defs[0]
	if call.Callee.String() != primary.ID.String() {
		r.rewritten++
	}
	call.Callee.Package, call.Callee.Type, call.Callee.Name = primary.ID.Package, primary.ID.Type, primary.ID.Name
	for _, def := range defs[1:] {
		r.addEdge(call, cppEdge{key: def.ID.String(), kind: EdgeKindExact})
	}
	return primary
}

func (r *cppResolver) addEdge(call *FunctionCall, edge cppEdge) {
	for _, e := range call.cpp.edges {
		if e.key == edge.key {
			return
		}
	}
	call.cpp.edges = append(call.cpp.edges, edge)
}

// dispatch adds the overrides of class.name in every class derived from
// class, transitively, but those already the call's targets.
func (r *cppResolver) dispatch(call *FunctionCall, class, name string, caller *FunctionDecl, targets []*FunctionDecl) {
	skip := make(map[*FunctionDecl]bool, len(targets))
	for _, t := range targets {
		skip[t] = true
	}
	seen := map[string]bool{class: true}
	level := r.children[class]
	for depth := 0; depth < cppHierarchyDepth && len(level) > 0; depth++ {
		var next []string
		for _, c := range level {
			if seen[c] {
				continue
			}
			seen[c] = true
			for _, def := range r.lookup(c, name, caller, len(call.Arguments), false) {
				if !skip[def] && def.ID.Type != "" && cppStripTemplateArgs(def.ID.Type) == c {
					r.addEdge(call, cppEdge{key: def.ID.String(), kind: EdgeKindInterfaceDispatch, declaredType: class})
				}
			}
			next = append(next, r.children[c]...)
		}
		level = next
	}
}

// resolveFree resolves `f(args)`: a member of the caller's class (an
// implicit `this->f`), then a function of an enclosing namespace, innermost
// first, then of a namespace a using-directive names. A call whose key
// names a definition already keeps it.
func (r *cppResolver) resolveFree(fn *FunctionDecl, call *FunctionCall) *FunctionDecl {
	if target := r.exact(call); target != nil || r.keyed(call) {
		return target
	}
	ctx := r.functionContext(fn)
	name, arity := call.Callee.Name, len(call.Arguments)
	if ctx.class != "" {
		defs, _ := r.findMethod(ctx.class, name, fn, arity, true)
		if len(defs) > 0 || r.declares(ctx.class, name) {
			var target *FunctionDecl
			if len(defs) > 0 {
				target = r.rewrite(call, defs)
			} else {
				call.Callee.Type = ctx.class
			}
			r.dispatch(call, ctx.class, name, fn, defs)
			return target
		}
	}
	for _, scope := range append(ctx.scopes, ctx.usings...) {
		if scope == "" || r.classes[scope] != nil {
			continue
		}
		if defs := r.lookup(scope, name, fn, arity, true); len(defs) > 0 {
			return r.rewrite(call, defs)
		}
	}
	return nil
}

// resolveQualified resolves `X::f(args)`: X is looked up as a class or a
// namespace from the caller's scope. It binds statically: no override is
// reached.
func (r *cppResolver) resolveQualified(fn *FunctionDecl, call *FunctionCall) *FunctionDecl {
	if target := r.exact(call); target != nil || r.keyed(call) {
		return target
	}
	ctx := r.functionContext(fn)
	name, arity := call.Callee.Name, len(call.Arguments)
	for _, candidate := range nameCandidates(call.cpp.scope, ctx) {
		var defs []*FunctionDecl
		if r.classes[candidate] != nil {
			defs, _ = r.findMethod(candidate, name, fn, arity, false)
		} else {
			defs = r.lookup(candidate, name, fn, arity, false)
		}
		if len(defs) > 0 {
			return r.rewrite(call, defs)
		}
	}
	return nil
}

// resolveMember resolves `recv.f(args)` and `recv->f(args)` on the
// receiver's class: its definition or the nearest base's, and, unless the
// receiver is an object held by value, every override.
func (r *cppResolver) resolveMember(fn *FunctionDecl, call *FunctionCall) *FunctionDecl {
	facts := call.cpp
	if facts.receiver == nil {
		return r.exact(call)
	}
	t, byValue := r.exprType(fn, facts.receiver)
	class := r.classOf(t, facts.arrow)
	if class == "" {
		return r.exact(call)
	}
	name := call.Callee.Name
	defs, _ := r.findMethod(class, name, fn, len(call.Arguments), false)
	var target *FunctionDecl
	switch {
	case len(defs) > 0:
		target = r.rewrite(call, defs)
	case r.declares(class, name):
		if call.Callee.Type != class {
			r.rewritten++
		}
		call.Callee.Type = class
	default:
		return r.exact(call)
	}
	if facts.arrow || !byValue {
		r.dispatch(call, class, name, fn, defs)
	}
	return target
}

// resolveConstruct resolves a construction of a type to the class's
// constructor.
func (r *cppResolver) resolveConstruct(fn *FunctionDecl, call *FunctionCall) *FunctionDecl {
	if target := r.exact(call); target != nil || r.keyed(call) {
		return target
	}
	return r.construct(fn, call, r.resolveClass(call.Callee.Type, r.functionContext(fn)))
}

func (r *cppResolver) construct(fn *FunctionDecl, call *FunctionCall, class string) *FunctionDecl {
	if class == "" {
		return nil
	}
	parts := cppSplitScope(class)
	if defs := r.lookup(class, parts[len(parts)-1], fn, len(call.Arguments), false); len(defs) > 0 {
		return r.rewrite(call, defs)
	}
	return nil
}

// resolveMemberInit resolves a member initializer list entry: the
// construction of the member's type, or of the base it names. An entry the
// pass cannot type is dropped.
func (r *cppResolver) resolveMemberInit(fn *FunctionDecl, call *FunctionCall) *FunctionDecl {
	ctx := r.functionContext(fn)
	member := call.cpp.member
	if ctx.class != "" && !strings.Contains(member, "::") {
		if f, owner, ok := r.field(ctx.class, member); ok {
			if f.ctor == "" {
				call.cpp.drop = true
				return nil
			}
			call.Raw = f.typ
			if class := r.resolveClass(f.typ, r.classContext(owner)); class != "" {
				parts := cppSplitScope(class)
				call.Callee.Type, call.Callee.Name = class, parts[len(parts)-1]
				return r.construct(fn, call, class)
			}
			call.Callee.Type, call.Callee.Name = f.typ, f.ctor
			return nil
		}
	}
	if class := r.resolveClass(member, ctx); class != "" {
		parts := cppSplitScope(class)
		call.Callee.Type, call.Callee.Name = class, parts[len(parts)-1]
		return r.construct(fn, call, class)
	}
	call.cpp.drop = true
	return nil
}

// exprType types a receiver expression: the type, and whether the value is
// an object held by value (a call on it binds statically).
func (r *cppResolver) exprType(fn *FunctionDecl, e *cppExpr) (cppTypeRef, bool) {
	switch e.kind {
	case cppExprVariable:
		if e.local {
			if !cppDeducedType(e.declared) {
				return cppTypeRef{text: e.declared, ctx: r.functionContext(fn)}, e.byValue
			}
			return r.deducedType(fn, e.name), e.byValue
		}
		ctx := r.functionContext(fn)
		if ctx.class == "" {
			return cppTypeRef{}, false
		}
		return r.memberType(ctx.class, e.name)
	case cppExprThis:
		return cppTypeRef{class: r.functionContext(fn).class}, false
	case cppExprField:
		inner, _ := r.exprType(fn, e.inner)
		class := r.classOf(inner, e.arrow)
		if class == "" {
			return cppTypeRef{}, false
		}
		return r.memberType(class, e.name)
	case cppExprCall:
		for _, call := range r.callsAt(fn, e.span) {
			if t := r.resultType(fn, call); t.text != "" || t.class != "" {
				return t, false
			}
		}
	}
	return cppTypeRef{}, false
}

func (r *cppResolver) memberType(class, name string) (cppTypeRef, bool) {
	f, owner, ok := r.field(class, name)
	if !ok {
		return cppTypeRef{}, false
	}
	return cppTypeRef{text: f.typ, ctx: r.classContext(owner)}, f.ctor != ""
}

// resultType types a call's value: the constructed type of a construction
// (a smart pointer to it for make_unique / make_shared), else the declared
// return type of the project definition it names.
func (r *cppResolver) resultType(fn *FunctionDecl, call *FunctionCall) cppTypeRef {
	if call.cpp != nil && call.cpp.shape == cppCallConstruct {
		r.resolve(fn, call)
		text := call.Callee.Type
		if call.cpp.smart {
			text = "std::unique_ptr<" + text + ">"
		}
		return cppTypeRef{text: text, ctx: r.functionContext(fn)}
	}
	target := r.resolve(fn, call)
	if target == nil || target.cpp == nil {
		return cppTypeRef{}
	}
	if target.cpp.returns != "" {
		return cppTypeRef{text: target.cpp.returns, ctx: r.functionContext(target)}
	}
	if target.cpp.returnsMember != "" {
		if ctx := r.functionContext(target); ctx.class != "" {
			t, _ := r.memberType(ctx.class, target.cpp.returnsMember)
			return t
		}
	}
	return cppTypeRef{}
}

// deducedType types an `auto` local from the calls bound to it: each must
// yield the same type, and none may be one the contract KB has an
// unconditional return for, which resolveCPPDeducedReceiverCallees types.
func (r *cppResolver) deducedType(fn *FunctionDecl, name string) cppTypeRef {
	var found cppTypeRef
	for i := range fn.Calls {
		producer := &fn.Calls[i]
		if producer.AssignedVar != name {
			continue
		}
		if r.contractTyped(producer) {
			return cppTypeRef{}
		}
		t := r.resultType(fn, producer)
		if t.text == "" && t.class == "" {
			continue
		}
		if found.text == "" && found.class == "" {
			found = t
			continue
		}
		if found.text != t.text || found.class != t.class {
			return cppTypeRef{}
		}
	}
	return found
}

// contractTyped reports a call the contract KB gives an unconditional
// return type, under the key the parser gave it or the one this pass did.
func (r *cppResolver) contractTyped(call *FunctionCall) bool {
	if r.kb == nil || call.cpp == nil || call.cpp.shape == cppCallConstruct {
		return false
	}
	for _, callee := range []FunctionID{r.original[call], call.Callee} {
		if method := cppContractMethod(&callee); method != "" &&
			cppReceiverTypeFromReturn(unconditionalContractReturn(r.kb.ContractsFor(method, len(call.Arguments)))) != "" {
			return true
		}
	}
	return false
}

// callsAt lists the calls of fn spanning exactly span.
func (r *cppResolver) callsAt(fn *FunctionDecl, span [4]int) []*FunctionCall {
	index := r.spans[fn]
	if index == nil {
		index = make(map[[4]int][]*FunctionCall, len(fn.Calls))
		for i := range fn.Calls {
			s := cppCallSpan(&fn.Calls[i])
			index[s] = append(index[s], &fn.Calls[i])
		}
		r.spans[fn] = index
	}
	return index[span]
}
