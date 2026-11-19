// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

// node_value_access.go spells a value that comes from another package as
// the steps that lead to it from the import:
//
//	const cl = fc.client();          // fc.client, called
//	cl.getKey(16);                   // fc.client, called, member getKey
//	new fc.Totp().validate(x);       // fc.Totp, constructed, member validate
//
// JavaScript gives a value no type to read, so a method call on what a
// package's function returned, or on an instance of a package's class, names
// nothing in its text. The steps do. A call is keyed by them
// (nodeAccessKey), and the package that owns the root resolves the same
// steps against its own source and lists the function they reach under that
// key in its exports (node_value_exports.go).

// nodeAccessMaxSteps bounds the steps one access spells. A longer chain is a
// fluent builder or generated code, and names nothing a path resolves.
const nodeAccessMaxSteps = 8

// nodeAccessStep is one step of an access: the member read, then whether the
// value is called or constructed. A step with no name calls or constructs the
// value the steps before it reach.
type nodeAccessStep struct {
	name       string
	call, ctor bool
}

// nodeValueAccess is the path to a value of another package: the specifier
// of the module it is imported from, then the steps.
type nodeValueAccess struct {
	module string
	steps  []nodeAccessStep
	// runtime marks a module the runtime provides (`crypto`, `node:fs`): the
	// value is known to come from it, and no package's exports name it, so it
	// has no key.
	runtime bool
}

// then returns the access followed by step. It copies: accesses share no
// steps.
func (a *nodeValueAccess) then(step nodeAccessStep) *nodeValueAccess {
	if a == nil || len(a.steps) >= nodeAccessMaxSteps {
		return nil
	}
	out := &nodeValueAccess{module: a.module, runtime: a.runtime, steps: make([]nodeAccessStep, len(a.steps), len(a.steps)+1)}
	copy(out.steps, a.steps)
	if step.name == "" && len(out.steps) > 0 {
		// `f()` calls the member the last step read; `f()()` calls its result.
		if last := &out.steps[len(out.steps)-1]; !last.call && !last.ctor {
			last.call, last.ctor = step.call, step.ctor
			return out
		}
	}
	out.steps = append(out.steps, step)
	return out
}

// Names the keys of an access use where a step has none of its own.
const (
	// nodeAccessResult names the value a call returned, when that value is
	// what is called: `pkg.make()()` calls pkg.(make()).<result>.
	nodeAccessResult = "<result>"
	// nodeAccessSeparator joins the steps after the first call or
	// construction inside the type part of a key.
	nodeAccessSeparator = ">"
)

// nodeAccessKey is the key of the function the steps of an access reach,
// for an access that calls or constructs something on the way: the package
// part holds the module and the members read before the first call or
// construction, the type part that step and the ones after it, and the name
// the member reached.
//
//	fc.client().getKey           fc.(client()).getKey
//	new fc.Totp().validate       fc.(Totp).validate
//	new fc.Totp()                fc.(Totp).<init>
//	new fc.a.K().open().read     fc.a.(K>open()).read
//	fc.make()()                  fc.(make()).<result>
//	require('fc')().sign         fc.(default()).sign
//
// An instance method is keyed as the contracts key one (`m.(X).verify`). An
// access with no call or construction is a member path, which a call
// through an import already spells; it has no key here, and neither has one
// that constructs past its first call or construction.
func nodeAccessKey(module string, steps []nodeAccessStep) (FunctionID, bool) {
	first := -1
	for i := range steps {
		if steps[i].call || steps[i].ctor {
			first = i
			break
		}
	}
	if first < 0 || module == "" {
		return FunctionID{}, false
	}
	id := FunctionID{Package: module}
	for i := range first {
		id.Package += "." + steps[i].name
	}
	segment := func(step nodeAccessStep) string {
		if step.call {
			return step.name + "()"
		}
		return step.name
	}
	base := steps[first]
	if base.name == "" {
		base.name = nodeDefaultKeyword
	}
	id.Type = segment(base)
	rest := steps[first+1:]
	if len(rest) == 0 {
		id.Name = nodeAccessResult
		if base.ctor {
			id.Name = constructorMethodName
		}
		return id, true
	}
	for i := range rest {
		if rest[i].ctor || (rest[i].name == "" && !rest[i].call) {
			return FunctionID{}, false
		}
		if i == len(rest)-1 && !rest[i].call {
			id.Name = rest[i].name
			return id, true
		}
		id.Type += nodeAccessSeparator + segment(rest[i])
	}
	id.Name = nodeAccessResult
	return id, true
}

// nodeAccessMemberKey is the key of a member path with no call or
// construction, as a call through the import spells it: `fc.a.b` is fc.a.b.
func nodeAccessMemberKey(module string, steps []nodeAccessStep) (FunctionID, bool) {
	if module == "" || len(steps) == 0 {
		return FunctionID{}, false
	}
	id := FunctionID{Package: module}
	for i := range steps {
		if steps[i].call || steps[i].ctor || steps[i].name == "" {
			return FunctionID{}, false
		}
		if i == len(steps)-1 {
			id.Name = steps[i].name
			break
		}
		id.Package += "." + steps[i].name
	}
	return id, true
}

// key is the key of the function the access reaches, when it has one.
func (a *nodeValueAccess) key() (FunctionID, bool) {
	if a == nil || a.runtime {
		return FunctionID{}, false
	}
	if id, ok := nodeAccessKey(a.module, a.steps); ok {
		return id, true
	}
	return nodeAccessMemberKey(a.module, a.steps)
}
