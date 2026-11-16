// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"sort"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// python_exports.go maps the names a Python package makes public to the
// declarations they name, so a client's call `jwt.encode(..)` joins pyjwt's
// `jwt.api_jwt.(PyJWT).encode`. A client spells the public path; the
// dependency declares the function under its defining module, and a public
// name reaches it through re-exports (`from .api_jwt import encode`), star
// imports, `__all__` and module-level aliases (`encode =
// _jwt_global_obj.encode`, `_jwt_global_obj = PyJWT()`).

// pythonModuleAssignment is a module-level assignment of a name to a dotted
// expression (`f = mod.g`, `encode = _obj.encode`) or, instance, to the call
// of one (`_obj = PyJWT()`).
type pythonModuleAssignment struct {
	name, expr string
	instance   bool
}

// pythonModuleFacts is what a module's top level binds besides definitions
// and imports: its dotted assignments, and the names its `__all__` lists.
type pythonModuleFacts struct {
	assignments []pythonModuleAssignment
	all         []string
	allDefined  bool
}

// collectPythonModuleFacts reads the module-level statements of a file,
// those inside if / try / with blocks included.
func collectPythonModuleFacts(root *sitter.Node, src []byte) *pythonModuleFacts {
	facts := &pythonModuleFacts{}
	var visit func(node *sitter.Node)
	visit = func(node *sitter.Node) {
		count := int(node.NamedChildCount())
		for i := 0; i < count; i++ {
			child := node.NamedChild(i)
			switch {
			case child.Type() == "expression_statement":
				facts.observe(child.NamedChild(0), src)
			case pythonDefinitionBlocks[child.Type()]:
				visit(child)
			}
		}
	}
	visit(root)
	return facts
}

const pythonAllName = "__all__"

// observe records one module-level expression statement: `name = a.b`,
// `name = a.b(..)`, `__all__ = [..]`, `__all__ += [..]`,
// `__all__.extend([..])` and `__all__.append(..)`.
func (f *pythonModuleFacts) observe(stmt *sitter.Node, src []byte) {
	switch stmt.Type() {
	case "assignment":
		left, right := stmt.ChildByFieldName("left"), stmt.ChildByFieldName("right")
		if right == nil {
			return // an annotation without a value
		}
		name := left.Content(src)
		if name == pythonAllName {
			f.all, f.allDefined = pythonStringItems(right, src), true
		}
		value, instance := right, false
		if right.Symbol() == pythonSyms.call {
			value, instance = right.ChildByFieldName("function"), true
		}
		if expr := value.Content(src); pythonDottedIdentifier(expr) {
			f.assignments = append(f.assignments, pythonModuleAssignment{name: name, expr: expr, instance: instance})
		}
	case "augmented_assignment":
		if left := stmt.ChildByFieldName("left"); left != nil && left.Content(src) == pythonAllName {
			f.all = append(f.all, pythonStringItems(stmt.ChildByFieldName("right"), src)...)
		}
	case "call":
		args := stmt.ChildByFieldName("arguments")
		switch stmt.ChildByFieldName("function").Content(src) {
		case pythonAllName + ".extend":
			f.all = append(f.all, pythonStringItems(args.NamedChild(0), src)...)
		case pythonAllName + ".append":
			if item, ok := pythonLiteralStringContent(args.NamedChild(0), src); ok {
				f.all = append(f.all, item)
			}
		}
	}
}

// pythonStringItems lists the string literals of a list or tuple literal.
func pythonStringItems(node *sitter.Node, src []byte) []string {
	if node == nil || (node.Type() != "list" && node.Type() != "tuple") {
		return nil
	}
	var items []string
	for i := 0; i < int(node.NamedChildCount()); i++ {
		if item, ok := pythonLiteralStringContent(node.NamedChild(i), src); ok {
			items = append(items, item)
		}
	}
	return items
}

// pythonExportBinding is one way a module binds a name: an import (target is
// the absolute dotted path of the declaration or module), or an assignment
// (target is the expression, spelled from the module: `pkg.m.` + expr), of
// the call of it when instance.
type pythonExportBinding struct {
	target   string
	instance bool
}

// pythonExportModule is what resolution reads of one module of the project.
type pythonExportModule struct {
	bindings map[string][]pythonExportBinding
	stars    []string
	all      map[string]bool
	// allDefined says the module defines __all__, which then decides what a
	// star import of it binds.
	allDefined bool
}

func (m *pythonExportModule) bind(name string, binding pythonExportBinding) {
	if m.bindings == nil {
		m.bindings = make(map[string][]pythonExportBinding)
	}
	m.bindings[name] = append(m.bindings[name], binding)
}

// public says whether a star import of the module binds name: the names its
// __all__ lists, else every name that does not start with an underscore.
func (m *pythonExportModule) public(name string) bool {
	if m.allDefined {
		return m.all[name]
	}
	return !strings.HasPrefix(name, "_")
}

// pythonExportModules indexes the project files' module-level bindings by
// module, once their imports are requalified.
func pythonExportModules(analyses []*FileAnalysis) map[string]*pythonExportModule {
	modules := make(map[string]*pythonExportModule)
	for _, analysis := range analyses {
		module := modules[analysis.PackagePath]
		if module == nil {
			module = &pythonExportModule{all: make(map[string]bool)}
			modules[analysis.PackagePath] = module
		}
		module.record(analysis)
	}
	return modules
}

// record adds one file's module-level bindings (a module and its stub share
// a path).
func (module *pythonExportModule) record(analysis *FileAnalysis) {
	for _, imp := range analysis.PythonImports {
		switch {
		case imp.Local:
		case imp.Name == pythonWildcardImport:
			module.stars = append(module.stars, imp.Module)
		case imp.Alias != "" && imp.Name != "":
			module.bind(imp.Alias, pythonExportBinding{target: imp.Module + "." + imp.Name})
		case imp.Name != "":
			module.bind(imp.Name, pythonExportBinding{target: imp.Module + "." + imp.Name})
		case imp.Alias != "":
			module.bind(imp.Alias, pythonExportBinding{target: imp.Module})
		default:
			head, _, _ := strings.Cut(imp.Module, ".")
			module.bind(head, pythonExportBinding{target: head})
		}
	}
	if facts := analysis.pythonModule; facts != nil {
		for _, a := range facts.assignments {
			module.bind(a.name, pythonExportBinding{target: analysis.PackagePath + "." + a.expr, instance: a.instance})
		}
		for _, name := range facts.all {
			module.all[name] = true
		}
		module.allDefined = module.allDefined || facts.allDefined
	}
}

// pythonTargetKind is what a dotted path names.
type pythonTargetKind int

const (
	pythonTargetNone pythonTargetKind = iota
	pythonTargetFunction
	pythonTargetClass
	pythonTargetModule
	pythonTargetInstance
)

// pythonTarget is a resolved path: a function key, a class (its qualified
// name), a module path, or an instance of a class.
type pythonTarget struct {
	kind pythonTargetKind
	key  string
}

type pythonExportResolver struct {
	graph    *CallGraph
	classes  *pythonClassIndex
	modules  map[string]bool
	project  map[string]*pythonExportModule
	memo     map[string]pythonTarget
	visiting map[string]bool
	// topLevel lists each module's top-level declarations (starNames).
	topLevel map[string][]string
}

// resolvePythonExports maps every public name of the project's modules that
// names a declaration of the project somewhere else to that declaration: a
// function key, or a class as `pkg.(Type)`. A name is public when it does not
// start with an underscore or the module's __all__ lists it. Names bound to
// their own declaration, to modules, to instances and to anything outside
// the project are left out.
func resolvePythonExports(graph *CallGraph, classes *pythonClassIndex, modules map[string]bool, project map[string]*pythonExportModule) map[string]string {
	r := &pythonExportResolver{graph: graph, classes: classes, modules: modules, project: project,
		memo: make(map[string]pythonTarget), visiting: make(map[string]bool)}
	out := make(map[string]string)
	paths := make([]string, 0, len(project))
	for path := range project {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		module := project[path]
		names := make([]string, 0)
		for name := range r.names(path, map[string]bool{}) {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			if strings.HasPrefix(name, "_") && !module.all[name] {
				continue
			}
			public := path + "." + name
			if decl, ok := r.declaration(public); ok {
				out[public] = decl
			}
		}
	}
	return out
}

// declaration is the export entry of public: the declaration it resolves
// to, when that is a function or class of the project declared elsewhere.
func (r *pythonExportResolver) declaration(public string) (string, bool) {
	target := r.resolve(public)
	switch target.kind {
	case pythonTargetFunction:
		decl := r.graph.Functions[target.key]
		if target.key == public || r.project[decl.ID.Package] == nil {
			return "", false
		}
		return target.key, true
	case pythonTargetClass:
		id := r.classes.classID(target.key)
		if target.key == public || r.project[id.Package] == nil {
			return "", false
		}
		return id.Package + ".(" + id.Type + ")", true
	default:
		return "", false
	}
}

// names lists the names module binds that can be public: its imports and
// assignments, and what its star imports may bind (resolve decides which
// they do).
func (r *pythonExportResolver) names(path string, seen map[string]bool) map[string]bool {
	out := make(map[string]bool)
	module := r.project[path]
	if module == nil || seen[path] {
		return out
	}
	seen[path] = true
	for name := range module.bindings {
		out[name] = true
	}
	for _, star := range module.stars {
		for name := range r.starNames(star, seen) {
			out[name] = true
		}
	}
	return out
}

// starNames is what `from star import *` can bind: the module's own
// top-level declarations and the names it binds.
func (r *pythonExportResolver) starNames(star string, seen map[string]bool) map[string]bool {
	out := r.names(star, seen)
	if r.topLevel == nil {
		r.topLevel = pythonTopLevelNames(r.graph, r.classes)
	}
	for _, name := range r.topLevel[star] {
		out[name] = true
	}
	return out
}

// pythonTopLevelNames lists, by module, the functions and classes a module
// declares at its top level.
func pythonTopLevelNames(graph *CallGraph, classes *pythonClassIndex) map[string][]string {
	out := make(map[string][]string)
	for _, fn := range graph.Functions {
		if fn.ID.Type == "" && isPythonIdentifier(fn.ID.Name) {
			out[fn.ID.Package] = append(out[fn.ID.Package], fn.ID.Name)
		}
	}
	for class := range classes.bases {
		id := classes.classID(class)
		out[id.Package] = append(out[id.Package], id.Type)
	}
	return out
}

func (r *pythonExportResolver) resolve(path string) pythonTarget {
	if target, ok := r.memo[path]; ok {
		return target
	}
	if r.visiting[path] {
		return pythonTarget{}
	}
	r.visiting[path] = true
	target := r.resolveUncached(path)
	delete(r.visiting, path)
	r.memo[path] = target
	return target
}

func (r *pythonExportResolver) resolveUncached(path string) pythonTarget {
	if _, ok := r.graph.Functions[path]; ok {
		return pythonTarget{kind: pythonTargetFunction, key: path}
	}
	if _, ok := r.classes.bases[path]; ok {
		return pythonTarget{kind: pythonTargetClass, key: path}
	}
	cut := strings.LastIndex(path, ".")
	if cut < 0 {
		return r.module(path)
	}
	prefix, name := path[:cut], path[cut+1:]
	// A package's own binding of a name shadows its submodule of that name:
	// `from github.GithubException import GithubException` in github's
	// __init__.py makes github.GithubException the class.
	if module := r.project[prefix]; module != nil {
		for _, binding := range module.bindings[name] {
			if target := r.resolveBinding(binding); target.kind != pythonTargetNone {
				return target
			}
		}
		for _, star := range module.stars {
			if source := r.project[star]; source != nil && source.public(name) {
				if target := r.resolve(star + "." + name); target.kind != pythonTargetNone {
					return target
				}
			}
		}
	}
	if target := r.module(path); target.kind != pythonTargetNone {
		return target
	}
	base := r.resolve(prefix)
	switch base.kind {
	case pythonTargetModule:
		return r.resolve(base.key + "." + name)
	case pythonTargetClass, pythonTargetInstance:
		if key, ok := r.classes.declaration(base.key, name, false); ok {
			return pythonTarget{kind: pythonTargetFunction, key: key}
		}
	}
	return pythonTarget{}
}

// module is the module path names, if the build parsed one.
func (r *pythonExportResolver) module(path string) pythonTarget {
	if r.modules[path] {
		return pythonTarget{kind: pythonTargetModule, key: path}
	}
	return pythonTarget{}
}

// resolveBinding is what a binding names; an instance is only ever read for
// its methods.
func (r *pythonExportResolver) resolveBinding(binding pythonExportBinding) pythonTarget {
	target := r.resolve(binding.target)
	if binding.instance && target.kind != pythonTargetNone {
		return pythonTarget{kind: pythonTargetInstance, key: target.key}
	}
	return target
}
