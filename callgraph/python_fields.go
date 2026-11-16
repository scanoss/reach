// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// pythonFieldEvidence is what one write of an attribute says about the value
// the attribute then holds.
type pythonFieldEvidence uint8

const (
	// pythonFieldUnknown: a value whose class the write does not tell (a
	// literal, a local, an augmented assignment, an unpacking).
	pythonFieldUnknown pythonFieldEvidence = iota
	// pythonFieldDeclared: an annotation names the class (`x: C`, a typed
	// parameter stored as is, a property's return annotation).
	pythonFieldDeclared
	// pythonFieldCall: the value is the result of a call, typed once the
	// graph knows what the call returns.
	pythonFieldCall
	// pythonFieldSelf: the value is the writing method's own instance
	// (`p.parent = self`), or read off it (`self.x = self.a.b`).
	pythonFieldSelf
	// pythonFieldObject: the value is a module-level object (declared names
	// it, `<module>.<name>`): a name a module binds once, to a call, whose
	// result is then the object's class.
	pythonFieldObject
)

// pythonFieldWrite is one write of attribute field on the instances of class
// (`<module>.<Class>`, the way the graph keys owners): `self.field = ..` in
// one of its methods, or `field = ..` / `field: T` in its body. A write on
// another object whose annotation names its class (`p.hs = ..` after
// `p = cast(Sub, p)`) names that class as target instead.
type pythonFieldWrite struct {
	class, field string
	target       pythonClassRef
	// object names the module-level object a module statement writes the
	// attribute of (`_obj.f = ..` after `_obj = C()`): the write reaches the
	// instances of the class the object's call returns.
	object   pythonClassRef
	evidence pythonFieldEvidence
	// declared is the class a pythonFieldDeclared write names, and the
	// writing method's class for a pythonFieldSelf one.
	declared pythonClassRef
	// path lists the attributes read off the value the evidence names:
	// `hs.get_datastores().main` is the call's result, then main.
	path []string
	// caller, line and col locate the call of a pythonFieldCall write among
	// the calls of its declaration (the method, or the class's <clinit>).
	caller          string
	line, col       int
	endLine, endCol int
	// awaited marks `self.f = await g()`: the value is what g's coroutine
	// returns, not g's result.
	awaited bool
	// annotated marks the field's own annotation (`f: C` in the body,
	// `self.f: C = ..`, a property's return annotation): the class the
	// field is declared to hold, which every write must conform to.
	annotated bool
}

// pythonFieldFacts is what one file says about the attributes of class
// instances, for typing `self.<field>` receivers across methods
// (typePythonSelfFieldReceivers).
type pythonFieldFacts struct {
	writes []pythonFieldWrite
	// foreign holds the attribute names the file writes on an object that is
	// not a method's own self (`obj.f = ..`, `setattr(x, "f", ..)`): such a
	// write may reach any class's instance, so no class's f is typed.
	foreign map[string]bool
	// open holds the classes whose instances get attributes by a name the
	// code does not spell (`setattr(self, name, ..)`, `self.__dict__`,
	// `vars(self)`) or whose attribute writes run custom code (`__setattr__`,
	// `__getattribute__`): none of their fields is typed.
	open map[string]bool
	// shadowed holds, by method key, the line spans of the definitions
	// nested in the method that bind their own self (a local class, a
	// closure with a parameter of self's name): their calls are the
	// method's, but their `self` is another object.
	shadowed map[string][][2]int
	// objects holds, by `<module>.<name>`, the call each module-level name
	// the module binds exactly once, to a call, is bound to (a
	// pythonFieldCall write locating it in the module's `<module>`).
	objects map[string]pythonFieldWrite
}

// pythonFieldCollector walks one file for pythonFieldFacts.
type pythonFieldCollector struct {
	src        []byte
	modulePath string
	analysis   *FileAnalysis
	fw         *pythonFileWalk
	facts      *pythonFieldFacts
}

// pythonFieldScope is where a node sits: in the body of class (body), in a
// method of class whose instance parameter is self, or outside any class
// ("" class: every attribute write there is foreign).
type pythonFieldScope struct {
	class string
	body  bool
	// module is true for the module's own statements (blocks included).
	module bool
	self   string
	caller string
	// varTypes are the enclosing method's declared local and parameter types
	// (pythonScope.varTypes).
	varTypes map[string]string
}

// collectPythonFieldFacts records the attribute writes of every class the
// file declares (fw.classNames), and the writes that may reach the
// attributes of any class.
func collectPythonFieldFacts(root *sitter.Node, src []byte, modulePath string, analysis *FileAnalysis, fw *pythonFileWalk) *pythonFieldFacts {
	c := &pythonFieldCollector{src: src, modulePath: modulePath, analysis: analysis, fw: fw, facts: &pythonFieldFacts{}}
	module := pythonFieldScope{module: true, caller: FunctionID{Package: modulePath, Name: moduleInitMethodName}.String()}
	c.walk(root, module, pythonDecoratorInfo{})
	for name := range fw.moduleSources.byName {
		if call := fw.moduleSources.boundCall(name); call != nil {
			if c.facts.objects == nil {
				c.facts.objects = make(map[string]pythonFieldWrite)
			}
			c.facts.objects[modulePath+"."+name] = c.callWrite(pythonFieldWrite{}, call, module)
		}
	}
	if len(c.facts.writes) == 0 && len(c.facts.foreign) == 0 && len(c.facts.open) == 0 && len(c.facts.shadowed) == 0 && len(c.facts.objects) == 0 {
		return nil
	}
	return c.facts
}

func (c *pythonFieldCollector) walk(node *sitter.Node, scope pythonFieldScope, deco pythonDecoratorInfo) {
	switch node.Type() {
	case pythonNodeClassDefinition:
		c.walkClass(node, scope)
		return
	case pythonDecoratedDefinition:
		if def := node.ChildByFieldName("definition"); def != nil {
			c.walk(def, scope, pythonFieldDecorators(node, c.src))
		}
		return
	case pythonNodeFunctionDefinition:
		c.walkFunction(node, scope, deco)
		return
	case pythonNodeAssignment:
		c.assignment(node, scope)
	case "augmented_assignment":
		c.targets(node.ChildByFieldName("left"), scope)
	case "for_statement", "for_in_clause":
		c.targets(node.ChildByFieldName("left"), scope)
	case "as_pattern":
		c.targets(node.ChildByFieldName("alias"), scope)
	case pythonNodeCall:
		c.call(node, scope)
	case pythonNodeAttribute:
		if attr := node.ChildByFieldName("attribute"); attr != nil && attr.Content(c.src) == "__dict__" && c.isSelf(node.ChildByFieldName("object"), scope) {
			c.markOpen(scope.class)
		}
	}
	if kind := node.Type(); !pythonDefinitionBlocks[kind] && kind != "module" && kind != rustNodeExpressionStatement {
		scope.body, scope.module = false, false
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		c.walk(node.NamedChild(i), scope, pythonDecoratorInfo{})
	}
}

func (c *pythonFieldCollector) walkClass(node *sitter.Node, scope pythonFieldScope) {
	nameNode, body := node.ChildByFieldName("name"), node.ChildByFieldName("body")
	if nameNode == nil || body == nil {
		return
	}
	name := ""
	switch {
	case scope.class != "" && scope.body:
		name = scope.class + "." + nameNode.Content(c.src)
	case scope.module:
		name = nameNode.Content(c.src)
	}
	if name != "" && c.fw.classNames[name] {
		if scope.class != "" {
			c.write(pythonFieldWrite{class: scope.class, field: nameNode.Content(c.src)})
		}
		c.walk(body, pythonFieldScope{class: name, body: true, caller: FunctionID{Package: c.modulePath, Type: name, Name: clinitMethodName}.String()}, pythonDecoratorInfo{})
		return
	}
	// A class declared in a function: its attribute writes reach instances
	// the graph does not model, so all of them are foreign.
	if scope.class != "" && scope.caller != "" {
		c.shadow(scope.caller, node)
	}
	c.walk(body, pythonFieldScope{}, pythonDecoratorInfo{})
}

func (c *pythonFieldCollector) shadow(caller string, node *sitter.Node) {
	if c.facts.shadowed == nil {
		c.facts.shadowed = make(map[string][][2]int)
	}
	span := [2]int{int(node.StartPoint().Row) + 1, int(node.EndPoint().Row) + 1}
	c.facts.shadowed[caller] = append(c.facts.shadowed[caller], span)
}

func (c *pythonFieldCollector) walkFunction(node *sitter.Node, scope pythonFieldScope, deco pythonDecoratorInfo) {
	name, body, params := pythonFunctionDefParts(node, c.src)
	if body == nil {
		return
	}
	if scope.class == "" || !scope.body {
		// A module function, or a closure that keeps its method's self
		// unless a parameter rebinds it.
		inner := scope
		inner.body, inner.module = false, false
		switch {
		case scope.class == "" && scope.module:
			inner = pythonFieldScope{caller: FunctionID{Package: c.modulePath, Name: name}.String()}
			if fs := c.fw.funcScopes[node.StartByte()]; fs != nil {
				inner.varTypes = fs.varTypes
			}
		case scope.class == "":
		case stringSliceContains(pythonParameterNames(params, c.src), scope.self):
			c.shadow(scope.caller, node)
			inner = pythonFieldScope{}
		}
		c.walk(body, inner, pythonDecoratorInfo{})
		return
	}
	switch {
	case name == "__setattr__" || name == "__getattribute__" || name == "__delattr__":
		c.markOpen(scope.class)
	case deco.property:
		c.write(c.declaredOr(pythonFieldWrite{class: scope.class, field: name}, node.ChildByFieldName("return_type"), scope.class))
	case !deco.setter:
		c.write(pythonFieldWrite{class: scope.class, field: name})
	}
	method := pythonFieldScope{class: scope.class}
	if !deco.static {
		if names := pythonParameterNames(params, c.src); len(names) > 0 {
			method.self = names[0]
		}
	}
	method.caller = FunctionID{Package: c.modulePath, Type: scope.class, Name: pythonDeclName(name)}.String()
	if fs := c.fw.funcScopes[node.StartByte()]; fs != nil {
		method.varTypes = fs.varTypes
	}
	c.walk(body, method, pythonDecoratorInfo{})
}

func pythonDeclName(name string) string {
	if name == pythonInitMethodName {
		return constructorMethodName
	}
	return name
}

// assignment records `self.f = v`, `self.f: T = v` and, in a class body,
// `f = v` / `f: T`. Any other attribute target is a foreign write.
func (c *pythonFieldCollector) assignment(node *sitter.Node, scope pythonFieldScope) {
	left := node.ChildByFieldName("left")
	if left == nil {
		return
	}
	right, annotation := node.ChildByFieldName("right"), node.ChildByFieldName("type")
	if scope.class != "" && scope.body && left.Symbol() == pythonSyms.identifier {
		c.valueWrites(pythonFieldWrite{class: scope.class, field: left.Content(c.src)}, right, annotation, scope)
		return
	}
	if left.Symbol() == pythonSyms.attribute {
		object, attr := left.ChildByFieldName("object"), left.ChildByFieldName("attribute")
		if attr == nil {
			return
		}
		if c.isSelf(object, scope) {
			c.valueWrites(pythonFieldWrite{class: scope.class, field: attr.Content(c.src)}, right, annotation, scope)
			return
		}
		if ref, ok := c.receiverClass(object, scope); ok {
			c.valueWrites(pythonFieldWrite{target: ref, field: attr.Content(c.src)}, right, annotation, scope)
			return
		}
		if ref, ok := c.moduleObject(object, scope); ok {
			c.valueWrites(pythonFieldWrite{object: ref, field: attr.Content(c.src)}, right, annotation, scope)
			return
		}
	}
	c.targets(left, scope)
}

// moduleObject is the module-level object a module statement names: a name
// the module binds exactly once, to a call (and declares global in no
// function), or one it binds only by a from-import, which names the
// importing module's object. Anything else, and any name in a class body or
// a function, where a local may shadow the module's, is no object.
func (c *pythonFieldCollector) moduleObject(object *sitter.Node, scope pythonFieldScope) (pythonClassRef, bool) {
	if !scope.module || scope.class != "" || object == nil || object.Symbol() != pythonSyms.identifier {
		return pythonClassRef{}, false
	}
	name := object.Content(c.src)
	if c.fw.moduleSources.boundCall(name) != nil {
		return pythonClassRef{pkg: c.modulePath, typ: name}, true
	}
	module, imported := c.analysis.Imports[name]
	if !imported || !c.analysis.FromImports[name] || !c.fw.moduleSources.boundOnlyBy(name, pythonBoundImport) {
		return pythonClassRef{}, false
	}
	return pythonClassRef{pkg: module, typ: pythonImportedName(c.analysis, name)}, true
}

// receiverClass is the class a parameter's or local's annotation (or its
// `cast`) names, the class of every object it holds.
func (c *pythonFieldCollector) receiverClass(object *sitter.Node, scope pythonFieldScope) (pythonClassRef, bool) {
	if object == nil || object.Symbol() != pythonSyms.identifier {
		return pythonClassRef{}, false
	}
	t := scope.varTypes[object.Content(c.src)]
	if t == "" {
		return pythonClassRef{}, false
	}
	return pythonAnnotationClass(t, scope.class, c.modulePath, c.fw.classNames, c.analysis)
}

// valueWrites records the evidence of one field write: its annotation when
// it names a class, else what the value tells. A bare annotation that names
// no class (`x: Dict[str, int]`) tells nothing and records nothing.
func (c *pythonFieldCollector) valueWrites(w pythonFieldWrite, value, annotation *sitter.Node, scope pythonFieldScope) {
	if annotation != nil {
		if ref, ok := c.annotationClass(annotation, scope.class); ok {
			w.evidence, w.declared, w.annotated = pythonFieldDeclared, ref, true
			c.write(w)
			return
		}
	}
	if value == nil {
		return
	}
	c.valueEvidence(w, value, scope)
}

// valueEvidence records what an assigned expression tells: None nothing, a
// call its result (`cast(C, v)` C), a parameter or local with a declared
// class that class, self the writing class, an attribute read off any of
// those (`hs.get_datastores().main`) that attribute's class, both branches of
// `a if c else b` and `a or b`, anything else unknown.
func (c *pythonFieldCollector) valueEvidence(w pythonFieldWrite, value *sitter.Node, scope pythonFieldScope) {
	if value.Symbol() == pythonSyms.attribute && len(w.path) == 0 {
		var path []string
		base := value
		for base.Symbol() == pythonSyms.attribute {
			attr := base.ChildByFieldName("attribute")
			if attr == nil {
				break
			}
			path = append([]string{attr.Content(c.src)}, path...)
			base = base.ChildByFieldName("object")
		}
		if base != nil && base.Symbol() != pythonSyms.attribute {
			w.path = path
			c.valueEvidence(w, base, scope)
			return
		}
	}
	switch value.Type() {
	case "none":
		return
	case "parenthesized_expression":
		if value.NamedChildCount() == 1 {
			c.valueEvidence(w, value.NamedChild(0), scope)
			return
		}
	case "conditional_expression":
		if value.NamedChildCount() == 3 {
			c.valueEvidence(w, value.NamedChild(0), scope)
			c.valueEvidence(w, value.NamedChild(2), scope)
			return
		}
	case "boolean_operator":
		if l, r := value.ChildByFieldName("left"), value.ChildByFieldName("right"); l != nil && r != nil {
			c.valueEvidence(w, l, scope)
			c.valueEvidence(w, r, scope)
			return
		}
	case "await":
		if value.NamedChildCount() == 1 && value.NamedChild(0).Type() == pythonNodeCall {
			w.awaited = true
			c.valueEvidence(w, value.NamedChild(0), scope)
			return
		}
	case pythonNodeCall:
		if t := pythonCastType(value, c.src, c.analysis); t != "" {
			if ref, ok := pythonAnnotationClass(t, scope.class, c.modulePath, c.fw.classNames, c.analysis); ok {
				w.evidence, w.declared = pythonFieldDeclared, ref
			}
			break
		}
		w = c.callWrite(w, value, scope)
	case goNodeIdentifier:
		if c.isSelf(value, scope) {
			w.evidence, w.declared = pythonFieldSelf, pythonClassRef{pkg: c.modulePath, typ: scope.class}
		} else if ref, ok := c.receiverClass(value, scope); ok {
			w.evidence, w.declared = pythonFieldDeclared, ref
		} else if ref, ok := c.moduleObject(value, scope); ok {
			w.evidence, w.declared = pythonFieldObject, ref
		}
	}
	c.write(w)
}

// callWrite is w with the evidence of a call's result: the call, located
// among the calls of scope's declaration.
func (c *pythonFieldCollector) callWrite(w pythonFieldWrite, call *sitter.Node, scope pythonFieldScope) pythonFieldWrite {
	w.evidence, w.caller = pythonFieldCall, scope.caller
	w.line, w.col = int(call.StartPoint().Row)+1, int(call.StartPoint().Column)+1
	w.endLine, w.endCol = int(call.EndPoint().Row)+1, int(call.EndPoint().Column)+1
	return w
}

// pythonCastType is the normalized annotation T of `cast(T, v)` (typing's
// cast, imported or as `typing.cast`), "" for any other call.
func pythonCastType(call *sitter.Node, src []byte, analysis *FileAnalysis) string {
	fn := call.ChildByFieldName("function")
	args := pythonArgumentListChild(call)
	if fn == nil || args == nil || args.NamedChildCount() != 2 {
		return ""
	}
	switch text := fn.Content(src); {
	case text == "cast" && analysis.Imports["cast"] == "typing" && pythonImportedName(analysis, "cast") == "cast":
	case text == "typing.cast" && analysis.Imports["typing"] == "typing" && !analysis.FromImports["typing"]:
	default:
		return ""
	}
	return pythonNormalizeAnnotation(args.NamedChild(0), src)
}

func (c *pythonFieldCollector) declaredOr(w pythonFieldWrite, annotation *sitter.Node, outer string) pythonFieldWrite {
	if annotation != nil {
		if ref, ok := c.annotationClass(annotation, outer); ok {
			w.evidence, w.declared, w.annotated = pythonFieldDeclared, ref, true
		}
	}
	return w
}

func (c *pythonFieldCollector) annotationClass(annotation *sitter.Node, outer string) (pythonClassRef, bool) {
	return pythonAnnotationClass(pythonNormalizeAnnotation(annotation, c.src), outer, c.modulePath, c.fw.classNames, c.analysis)
}

// targets records the attribute targets of a binding that is not a plain
// `self.f = v`: an unpacking, an augmented assignment, a for / with target.
// A target on the method's self is a write of unknown value.
func (c *pythonFieldCollector) targets(target *sitter.Node, scope pythonFieldScope) {
	if target == nil {
		return
	}
	switch target.Symbol() {
	case pythonSyms.attribute:
		attr := target.ChildByFieldName("attribute")
		if attr == nil {
			return
		}
		if c.isSelf(target.ChildByFieldName("object"), scope) {
			c.write(pythonFieldWrite{class: scope.class, field: attr.Content(c.src)})
		} else {
			c.markForeign(attr.Content(c.src))
		}
		return
	case pythonSyms.subscript, pythonSyms.identifier:
		return
	}
	for i := 0; i < int(target.NamedChildCount()); i++ {
		c.targets(target.NamedChild(i), scope)
	}
}

// call records the writes setattr and object.__setattr__ make, and
// `vars(self)`.
func (c *pythonFieldCollector) call(node *sitter.Node, scope pythonFieldScope) {
	fn := node.ChildByFieldName("function")
	args := pythonArgumentListChild(node)
	if fn == nil || args == nil || args.NamedChildCount() == 0 {
		return
	}
	switch fn.Content(c.src) {
	case "vars":
		if c.isSelf(args.NamedChild(0), scope) {
			c.markOpen(scope.class)
		}
	case "setattr", "object.__setattr__":
		if args.NamedChildCount() < 2 {
			return
		}
		if name, ok := pythonLiteralStringContent(args.NamedChild(1), c.src); ok {
			c.markForeign(name)
		} else if c.isSelf(args.NamedChild(0), scope) {
			c.markOpen(scope.class)
		}
	}
}

func (c *pythonFieldCollector) isSelf(object *sitter.Node, scope pythonFieldScope) bool {
	return object != nil && scope.class != "" && scope.self != "" &&
		object.Symbol() == pythonSyms.identifier && object.Content(c.src) == scope.self
}

func (c *pythonFieldCollector) write(w pythonFieldWrite) {
	if w.target == (pythonClassRef{}) && w.object == (pythonClassRef{}) {
		w.class = c.modulePath + "." + w.class
	}
	c.facts.writes = append(c.facts.writes, w)
}

func (c *pythonFieldCollector) markForeign(field string) {
	if c.facts.foreign == nil {
		c.facts.foreign = make(map[string]bool)
	}
	c.facts.foreign[field] = true
}

func (c *pythonFieldCollector) markOpen(class string) {
	if class == "" {
		return
	}
	if c.facts.open == nil {
		c.facts.open = make(map[string]bool)
	}
	c.facts.open[c.modulePath+"."+class] = true
}

// pythonFieldDecorators classifies a decorated definition for field typing:
// staticmethod, a property getter (`@property`, `@cached_property`,
// `@functools.cached_property`), a property's setter or deleter
// (`@f.setter`).
func pythonFieldDecorators(node *sitter.Node, src []byte) pythonDecoratorInfo {
	info := classifyPythonDecorators(node, src)
	for i := 0; i < int(node.NamedChildCount()); i++ {
		child := node.NamedChild(i)
		if child.Symbol() != pythonSyms.decorator || child.NamedChildCount() == 0 {
			continue
		}
		expr := child.NamedChild(0)
		switch text := expr.Content(src); {
		case text == "cached_property" || text == "functools.cached_property":
			info.property = true
		case expr.Symbol() == pythonSyms.attribute:
			if attr := expr.ChildByFieldName("attribute"); attr != nil && (attr.Content(src) == "setter" || attr.Content(src) == "deleter") {
				info.setter = true
			}
		}
	}
	return info
}
