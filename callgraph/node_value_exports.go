// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path/filepath"
	"sort"
	"strings"
)

// node_value_exports.go lists, in a package's exports, the functions a
// caller reaches through a value the package hands out, under the key the
// caller's graph gives the call (nodeAccessKey):
//
//	acme.(Totp).validate        a method of an instance of an exported class
//	acme.(Totp).<init>          the constructor `new acme.Totp()` runs
//	acme.(client()).getKey      a method of what an exported function returns
//	acme.(make()).<result>      the function an exported function returns
//	acme.(K>open()).read        a method of what a method of an instance returns
//	acme.<module>               the top-level code that loading acme runs
//
// The caller's graph holds no source of the package, so it can only spell
// the steps; the package's graph resolves them (node_value_shapes.go). The
// paths are followed to nodeValueExportHops calls or constructions, and
// nodeValueExportCap entries a package.

const (
	// nodeValueExportHops bounds the calls and constructions one listed path
	// makes.
	nodeValueExportHops = 2
	// nodeValueExportMembers bounds the member reads between two of them.
	nodeValueExportMembers = 2
	// nodeValueExportCap bounds the entries listed for one package.
	nodeValueExportCap = 8192
)

// nodeValueExports lists the value paths of one public module.
type nodeValueExports struct {
	r     *nodePackageCalls
	spec  string
	out   map[string]string
	count *int
	// skip holds the public keys two declarations claimed, which stay out.
	skip map[string]bool
}

// publishValues adds to out the keys this file's comment lists for one
// public module. A key another declaration already holds is left as it is.
func (r *nodePackageCalls) publishValues(module nodePublicModule, names []string, out map[string]string, skip map[string]bool, count *int) {
	mod := r.shapes.module(module.file)
	if mod == nil {
		return
	}
	if decl := r.moduleDecl(module.file); decl != "" {
		if public := module.spec + "." + moduleInitMethodName; out[public] == "" {
			out[public] = decl
		}
	}
	e := &nodeValueExports{r: r, spec: module.spec, out: out, count: count, skip: skip}
	root := nodeShapeValue{m: mod, n: mod.root, module: true}
	for _, name := range names {
		var steps []nodeAccessStep
		if name != nodeDefaultExport {
			steps = []nodeAccessStep{{name: name}}
		}
		e.expand(steps, r.shapes.query().member(root, name, 0), 0, 1)
	}
}

// moduleDecl is the key of the <module> function of file, "" for none.
func (r *nodePackageCalls) moduleDecl(file string) string {
	return r.modules[filepath.Clean(file)]
}

// functionKey is the key of the function v is, "" when the graph has none
// declared there.
func (r *nodePackageCalls) functionKey(v nodeShapeValue) string {
	if !v.callable() || v.class() {
		return ""
	}
	return r.starts[nodeDeclStart{file: filepath.Clean(v.m.path), line: nodeLine(v.n), col: int(v.n.StartPoint().Column) + 1}]
}

// emit lists the function values under the key of steps.
func (e *nodeValueExports) emit(steps []nodeAccessStep, values []nodeShapeValue) {
	id, ok := nodeAccessKey(e.spec, steps)
	if !ok {
		return
	}
	public := id.String()
	if _, taken := e.out[public]; taken {
		return
	}
	for _, v := range values {
		if key := e.r.functionKey(v); key != "" {
			e.out[public] = key
			*e.count++
			return
		}
	}
}

// emitMember lists the function values under the key of a member path, for
// a member the exports' own listing did not resolve (publishModule): a
// member of a bundle's namespace object, or one deeper than it reads.
func (e *nodeValueExports) emitMember(steps []nodeAccessStep, values []nodeShapeValue) {
	id, ok := nodeAccessMemberKey(e.spec, steps)
	if !ok {
		return
	}
	public := id.String()
	if _, taken := e.out[public]; taken || e.skip[public] {
		return
	}
	for _, v := range values {
		if key := e.r.functionKey(v); key != "" && key != public {
			e.out[public] = key
			*e.count++
			return
		}
	}
}

// expand lists what values, reached by steps, lead to: the function they
// are, their members, what constructing them builds and what calling them
// returns. hops counts the calls and constructions in steps, members the
// member reads since the last one.
func (e *nodeValueExports) expand(steps []nodeAccessStep, values []nodeShapeValue, hops, members int) {
	if len(values) == 0 || *e.count >= nodeValueExportCap {
		return
	}
	switch {
	case hops > 0:
		e.emit(steps, values)
	case len(steps) > 1:
		e.emitMember(steps, values)
	}
	access := &nodeValueAccess{module: e.spec, steps: steps}
	if members < nodeValueExportMembers {
		for _, v := range values {
			if v.external != nil || (hops == 0 && !v.object() && !v.instance) {
				// A class's or function's own members are listed with the
				// exports (publishModule); only what follows a call or a
				// construction is new here.
				continue
			}
			names := e.r.shapes.query().memberNames(v, 0)
			sort.Strings(names)
			for _, name := range names {
				next := access.then(nodeAccessStep{name: name})
				if next == nil {
					continue
				}
				e.expand(next.steps, e.r.shapes.query().member(v, name, 0), hops, members+1)
			}
		}
	}
	if hops >= nodeValueExportHops {
		return
	}
	if built := access.then(nodeAccessStep{ctor: true}); built != nil {
		if instances := nodeInstancesOf(e.constructible(values)); len(instances) > 0 {
			q := e.r.shapes.query()
			var constructors []nodeShapeValue
			for _, instance := range instances {
				constructors = appendNodeValues(constructors, q.constructors(instance, 0, 0)...)
			}
			e.emit(built.steps, constructors)
			e.expand(built.steps, instances, hops+1, 0)
		}
	}
	if called := access.then(nodeAccessStep{call: true}); called != nil {
		q := e.r.shapes.query()
		var results []nodeShapeValue
		for _, v := range nodeLocalValues(values) {
			results = appendNodeValues(results, q.results(v, 0)...)
		}
		e.expand(called.steps, nodeLocalValues(results), hops+1, 0)
	}
}

// nodeLocalValues drops the values of other packages: their paths are
// listed by the package that owns them.
func nodeLocalValues(values []nodeShapeValue) []nodeShapeValue {
	out := values[:0:0]
	for _, v := range values {
		if v.external == nil {
			out = append(out, v)
		}
	}
	return out
}

// constructible keeps the values a caller constructs: a class, and a
// function written as a constructor, one that assigns to this, has members
// assigned to its prototype or inherits from another. Any function can
// follow `new`; listing every exported one as a class would double the
// exports for paths no caller writes.
func (e *nodeValueExports) constructible(values []nodeShapeValue) []nodeShapeValue {
	var out []nodeShapeValue
	for _, v := range nodeLocalValues(values) {
		if !v.callable() || v.n.Type() == nodeMethodDefinition || v.n.Type() == nodeArrowFunction {
			continue
		}
		if v.class() || len(v.m.thisAssignments(v.n.ChildByFieldName("body"))) > 0 {
			out = append(out, v)
			continue
		}
		for _, name := range nodeValueNames(v) {
			if len(v.m.inherited()[name]) > 0 || v.m.hasPrototype(name) {
				out = append(out, v)
				break
			}
		}
	}
	return out
}

// hasPrototype reports whether the module assigns to `name.prototype` or to
// a member of it.
func (m *nodeShapeModule) hasPrototype(name string) bool {
	prefix := name + "." + nodePrototypeMember
	for target := range m.assignments().byTarget {
		if target == prefix || strings.HasPrefix(target, prefix+".") {
			return true
		}
	}
	return false
}
