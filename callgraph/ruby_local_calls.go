// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// ruby_local_calls.go binds a Ruby call to the declaration its own component
// makes for it. The parser keys a call target by the caller's file and the
// constant exactly as the source spells it, and neither is how the
// declaration is keyed: `JWT.encode` runs `Encode.new(..)`, and the class is
// declared `JWT::Encode` in another file of the gem. Ruby resolves a
// relative constant against the enclosing namespace, so the two name one
// class; the component's own index is where that is settled, before the
// closure ever sees the call as external.

// rubyConstructorName is the method that instantiates a class, and
// rubyInitializeMethod the one the instantiation runs.
const (
	rubyConstructorName  = "new"
	rubyInitializeMethod = "initialize"
)

// rubyLocalIndex maps "<constant>.<method>" to the declaration behind it, or
// to nil where the name is ambiguous. A nil entry binds nothing: two classes
// whose last constant segment is the same ask for the namespace the parser
// did not record, and a guess between them would invent a call the program
// does not make.
type rubyLocalIndex map[string]*FunctionDecl

// resolveRubyLocalCalls rewrites each call target the component declares to
// the declaration's own key, leaving every other call untouched for the
// closure to resolve against a dependency.
func resolveRubyLocalCalls(graph *CallGraph) {
	index := indexRubyLocalDecls(graph)
	if len(index) == 0 {
		return
	}
	for _, fn := range graph.Functions {
		if fn == nil {
			continue
		}
		kept := make([]FunctionCall, 0, len(fn.Calls))
		for i := range fn.Calls {
			call := fn.Calls[i]
			if initializer := rubyInitializerFor(index, fn, &call); initializer != nil {
				// An instantiation is two things at once. It runs the
				// class's `initialize`, which is the edge, and it is a site
				// the card matcher reads from the component's external
				// calls — and binding the call would take it out of them.
				// Both are kept: the bound copy carries the route, the
				// original stays the site, and the site resolves to no
				// declaration anywhere, so it proves nothing on its own.
				bound := call
				bound.Callee = initializer.ID
				kept = append(kept, call, bound)
				continue
			}
			bindRubyLocalCall(graph, index, fn, &call)
			if call.RubySelfCandidate && call.Callee.Type == "" {
				// A bare word the caller's class does not declare: a local
				// read, a method of a dependency's base class, or Kernel's.
				// None of the three is an edge this component can prove.
				continue
			}
			kept = append(kept, call)
		}
		fn.Calls = kept
	}
}

// rubyInitializerFor is the `initialize` an instantiation runs, and nil for
// every other call.
func rubyInitializerFor(index rubyLocalIndex, caller *FunctionDecl, call *FunctionCall) *FunctionDecl {
	if BaseFunctionName(call.Callee.Name) != rubyConstructorName {
		return nil
	}
	constant := call.Callee.Type
	if constant == "" {
		// `new(args)` with no receiver, inside a class-side method: self is
		// the class, so it instantiates the caller's own.
		constant = caller.ID.Type
	}
	if constant == "" {
		return nil
	}
	return index[rubyLocalKey(constant, rubyInitializeMethod, false)]
}

// indexRubyLocalDecls keys the component's methods by the constant a caller
// can spell them through: the class's full path and its last segment, each
// without an arity, since Ruby declares a name once per class.
func indexRubyLocalDecls(graph *CallGraph) rubyLocalIndex {
	index := make(rubyLocalIndex)
	add := func(key string, decl *FunctionDecl) {
		if prior, seen := index[key]; seen {
			if prior == nil || prior.ID.String() != decl.ID.String() {
				index[key] = nil
			}
			return
		}
		index[key] = decl
	}
	for _, fn := range graph.Functions {
		if fn == nil || fn.ID.Type == "" || !strings.HasSuffix(fn.FilePath, ".rb") {
			continue
		}
		name := BaseFunctionName(fn.ID.Name)
		if name == "" || strings.HasPrefix(name, "<") {
			continue
		}
		add(rubyLocalKey(fn.ID.Type, name, fn.Static), fn)
		if suffix := rubyConstantSuffix(fn.ID.Type); suffix != fn.ID.Type {
			add(rubyLocalKey(suffix, name, fn.Static), fn)
		}
	}
	return index
}

// bindRubyLocalCall points call at the component's declaration for it, if
// the component makes one. A call already keyed to a declaration is left as
// it is: the parser resolved it, and this pass only reaches what it could
// not.
func bindRubyLocalCall(graph *CallGraph, index rubyLocalIndex, caller *FunctionDecl, call *FunctionCall) {
	if _, resolved := graph.Functions[call.Callee.String()]; resolved {
		return
	}
	name := BaseFunctionName(call.Callee.Name)
	if name == "" || strings.HasPrefix(name, "<") {
		return
	}
	constant := call.Callee.Type
	if call.RubySelfCandidate {
		constant = caller.ID.Type
	}
	if constant == "" {
		// A call with no receiver runs on self: the method the caller's own
		// class declares, if it declares one.
		constant = caller.ID.Type
	}
	if constant == "" {
		return
	}
	decl := index[rubyLocalKey(constant, name, call.StaticReceiver)]
	if decl == nil && !call.StaticReceiver {
		// A receiver the parser could only name by its constant is read as
		// the class itself; where the class declares no instance method of
		// that name, the class-side one is what the call runs.
		decl = index[rubyLocalKey(constant, name, true)]
	}
	if decl == nil {
		return
	}
	call.Callee = decl.ID
}

// rubyConstantSuffix is the last segment of a constant path: the name a
// caller inside the enclosing namespace spells it by.
func rubyConstantSuffix(constant string) string {
	if i := strings.LastIndex(constant, "::"); i >= 0 {
		return constant[i+len("::"):]
	}
	return constant
}

// rubyLocalKey keys a method by the constant that reaches it and the side
// it is declared on: `Request.execute` and `Request.new.execute` are two
// methods of one class, and one name would make each ambiguous.
func rubyLocalKey(constant, name string, static bool) string {
	if static {
		return constant + "::" + name
	}
	return constant + "#" + name
}
