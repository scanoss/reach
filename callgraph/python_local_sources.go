// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// pythonLocalSources indexes, for ONE outermost function scope, every name the
// function can bind, in the same descent pythonWalk already makes, so a call
// argument that names a local resolves with one map lookup and no rescan of the
// function body.
//
// A local resolves only when EVERY binding of that name anywhere in the
// function subtree is a plain `name = <literal>` whose source text is
// identical. Python makes a name local to the whole function, so a use that
// runs before any binding raises instead of reading a different value: the
// shared value is the only one the use can ever observe. Anything else poisons
// the name, and a poisoned name resolves to nothing: an extra assignment, an
// augmented assignment, a loop or `with`/`except` target, tuple unpacking,
// walrus, a parameter of the function or of a nested def/lambda, an import, a
// nested def/class of that name, `global`/`nonlocal`/`del`, a match capture, or
// a value that is not an integer literal or a zero-argument constructor call.
// The index is deliberately flow-insensitive: where the assignment sits
// (if/else, loop, try) cannot change the value, only whether it exists.
type pythonLocalSources struct {
	byName map[string]*pythonLocalSource
	// root is the StartByte of the outermost function_definition this index
	// belongs to. A binding under a nested def, class or lambda binds in THAT
	// scope, not the function's, so it can only poison the name here.
	root uint32
	// work, when non-nil, counts every map probe and ancestor step the index
	// takes, so a test can bound the cost per binding and per argument.
	work *int
	// module marks the file-level index: comprehension targets, lambda
	// parameters and a def's parameters bind in their own scope there, so only
	// a def's name poisons.
	module bool
	// all poisons every name in the file-level index: the file rebinds names
	// dynamically (exec, globals(), setattr on the module).
	all bool
	// escaped records the names used other than as the receiver of a direct
	// method call in the function's own scope. Kept apart from byName, whose
	// keys are the names the function binds.
	escaped map[string]bool
	// nonArgument records the names used other than as a bare argument of a
	// call in the function's own scope (a method receiver, a subscript, an
	// operand, a name a nested scope reads): a list held in one may change.
	nonArgument map[string]bool
}

func (s *pythonLocalSources) tick() {
	if s.work != nil {
		*s.work++
	}
}

type pythonLocalSource struct {
	// value is the right-hand side node shared by every binding, kept so the
	// use site resolves it in its own binding layer.
	value *sitter.Node
	text  string
	// root is the leading name of a dotted constructor call (`ec` in
	// `ec.SECP521R1()`), empty for an integer literal.
	root     string
	poisoned bool
	// passed marks a parameter a caller's argument fills: at position
	// parameterIndex of the call (a method's self or cls is the receiver, not
	// an argument, so the parameter after it is at 0), or only by its name
	// (a keyword-only parameter, parameterIndex -1). rebound records any
	// other binding of the name, after which the value at a use may differ
	// from the caller's argument.
	passed         bool
	rebound        bool
	parameterIndex int
	// bindings counts the statements that bind the name, and kind is what
	// the first one binds, so a use can require one import or one class.
	bindings int
	kind     pythonBindingKind
	// construction is the call the first binding assigns, for a receiver
	// bound exactly once; mutated records an attribute write through the name.
	construction *sitter.Node
	mutated      bool
	// declared marks a parameter of the indexed function, of any kind.
	// table is the dict display the first binding assigns, for a dispatch
	// table bound exactly once (tableOf).
	declared bool
	table    *sitter.Node
	// literals are the plain string literals the name's bindings assign, in
	// source order, without repeats; nonLiteral records a binding of
	// anything else, or a parameter, whose value is the caller's (E1.3a).
	literals   []string
	nonLiteral bool
}

type pythonBindingKind uint8

const (
	pythonBoundOther pythonBindingKind = iota
	pythonBoundImport
	pythonBoundClass
)

func (e *pythonLocalSource) note(kind pythonBindingKind) {
	if e.bindings == 0 {
		e.kind = kind
	}
	e.bindings++
}

// boundOnlyBy reports whether exactly one statement binds name, of kind.
func (s *pythonLocalSources) boundOnlyBy(name string, kind pythonBindingKind) bool {
	if s.all {
		return false
	}
	e := s.byName[name]
	return e != nil && e.bindings == 1 && e.kind == kind
}

func (s *pythonLocalSources) entry(name string) *pythonLocalSource {
	s.tick()
	if s.byName == nil {
		s.byName = make(map[string]*pythonLocalSource)
	}
	e := s.byName[name]
	if e == nil {
		e = &pythonLocalSource{}
		s.byName[name] = e
	}
	return e
}

func (s *pythonLocalSources) bind(name string, value *sitter.Node, text, root string) {
	e := s.entry(name)
	e.rebound = e.rebound || e.passed
	e.note(pythonBoundOther)
	if value.Symbol() == pythonSyms.string {
		if !slices.Contains(e.literals, text) {
			e.literals = append(e.literals, text)
		}
	} else {
		e.nonLiteral = true
	}
	switch {
	case e.poisoned:
	case e.value == nil && e.text == "":
		e.value, e.text, e.root = value, text, root
	case e.text != text:
		e.poisoned = true
	}
}

func (s *pythonLocalSources) poison(name string) {
	e := s.entry(name)
	e.note(pythonBoundOther)
	e.poisoned, e.nonLiteral = true, true
	e.rebound = e.rebound || e.passed
}

// bindParameters records the indexed function's parameters. Every name stays
// poisoned for lookup, since its value comes from the caller. The first
// positional ones are parameters a caller fills by position: a method's
// receiver parameter (receiver 1) is none, and the ones after it count from
// 0, as the caller writes them. keywordOnly names the parameters a caller
// fills by keyword alone.
func (s *pythonLocalSources) bindParameters(names []string, receiver, positional int, keywordOnly []string) {
	for i, name := range names {
		e := s.entry(name)
		e.poisoned, e.nonLiteral, e.declared = true, true, true
		switch {
		case i < receiver:
		case i < positional:
			e.passed, e.parameterIndex = true, i-receiver
		case slices.Contains(keywordOnly, name):
			e.passed, e.parameterIndex = true, -1
		}
	}
}

// parameterSource returns the parameter index a use of name reads (-1 for a
// keyword-only parameter), ok only when the function never rebinds the
// parameter.
func (s *pythonLocalSources) parameterSource(name string) (index int, ok bool) {
	if s == nil || s.all {
		return 0, false
	}
	e := s.byName[name]
	if e == nil || !e.passed || e.rebound {
		return 0, false
	}
	return e.parameterIndex, true
}

func (s *pythonLocalSources) poisonIdentifiers(node *sitter.Node, src []byte) {
	if node == nil {
		return
	}
	if node.Symbol() == pythonSyms.identifier {
		s.poison(node.Content(src))
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		s.poisonIdentifiers(node.NamedChild(i), src)
	}
}

// poisonCaptures poisons the names a case pattern spells, but for a dotted
// value pattern (`case hashes.SHA256:`), which reads a name and binds none.
func (s *pythonLocalSources) poisonCaptures(node *sitter.Node, src []byte) {
	if node.Symbol() == pythonSyms.dottedName && node.NamedChildCount() > 1 {
		return
	}
	if node.Symbol() == pythonSyms.identifier {
		s.poison(node.Content(src))
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		s.poisonCaptures(node.NamedChild(i), src)
	}
}

// mayValues is the VARIABLE node of a name bound more than once that
// carries the string literals it may hold (E1.3a), exhaustive when every
// binding is one; nil when no binding is a string literal.
func (s *pythonLocalSources) mayValues(name string) []SourceNode {
	if s == nil || s.all {
		return nil
	}
	e := s.byName[name]
	if e == nil || len(e.literals) == 0 {
		return nil
	}
	return []SourceNode{{Type: "VARIABLE", Name: name, MayValues: e.literals, MayValuesExhaustive: !e.nonLiteral}}
}

// lookup returns the resolvable source of a local name, with known reporting
// whether the function binds the name at all (a known name never falls back to
// a same-named module constant).
func (s *pythonLocalSources) lookup(name string) (source *pythonLocalSource, known bool) {
	if s == nil {
		return nil, false
	}
	s.tick()
	if s.all {
		return nil, true
	}
	e, ok := s.byName[name]
	if !ok {
		return nil, false
	}
	if e.poisoned {
		return nil, true
	}
	return e, true
}

// observe records the bindings one node of the function subtree creates.
func (s *pythonLocalSources) observe(node *sitter.Node, sym sitter.Symbol, src []byte) {
	switch sym {
	case pythonSyms.assignment:
		s.observeAssignment(node, src)
	case pythonSyms.forInClause:
		if !s.module {
			s.poisonTarget(node.ChildByFieldName("left"), src)
		}
	case pythonSyms.augmentedAssignment, pythonSyms.forStatement:
		s.poisonTarget(node.ChildByFieldName("left"), src)
	case pythonSyms.namedExpression:
		s.poisonIdentifiers(node.ChildByFieldName("name"), src)
	case pythonSyms.asPattern:
		if alias := node.ChildByFieldName("alias"); alias != nil {
			s.poisonIdentifiers(alias, src)
		} else {
			s.poisonIdentifiers(node, src)
		}
	case pythonSyms.functionDefinition:
		s.poisonIdentifiers(node.ChildByFieldName("name"), src)
		if !s.module {
			s.poisonIdentifiers(node.ChildByFieldName("parameters"), src)
		}
	case pythonSyms.lambdaParameters:
		if !s.module {
			s.poisonIdentifiers(node, src)
		}
	case pythonSyms.wildcardImport:
		s.poisonExisting()
	case pythonSyms.importStatement, pythonSyms.importFromStatement:
		s.observeImport(node, src)
	case pythonSyms.globalStatement, pythonSyms.nonlocalStatement, pythonSyms.deleteStatement, pythonSyms.typeAliasStatement:
		s.poisonIdentifiers(node, src)
	case pythonSyms.casePattern:
		s.poisonCaptures(node, src)
	}
	s.observeUse(node, sym, src)
}

// observeUse marks a function local escaped when this identifier uses it in a
// way that hands the object to other code; see escapes.
func (s *pythonLocalSources) observeUse(node *sitter.Node, sym sitter.Symbol, src []byte) {
	if sym != pythonSyms.identifier || s.module {
		return
	}
	if !pythonBareArgument(node) && !s.spelledOnly(node) || s.inNestedScope(node) {
		if s.nonArgument == nil {
			s.nonArgument = make(map[string]bool)
		}
		s.nonArgument[node.Content(src)] = true
	}
	if !s.escapes(node) {
		return
	}
	if s.escaped == nil {
		s.escaped = make(map[string]bool)
	}
	s.escaped[node.Content(src)] = true
}

// pythonBareArgument reports an identifier passed as a whole argument of a
// call: positional, or the value of a keyword argument.
func pythonBareArgument(node *sitter.Node) bool {
	parent := node.Parent()
	if parent != nil && parent.Symbol() == pythonSyms.keywordArgument && pythonIsFieldChild(parent, "value", node) {
		parent = parent.Parent()
	}
	return parent != nil && parent.Symbol() == pythonSyms.argumentList
}

// spelledOnly reports an identifier that is no use of a local: a binding
// target of a plain assignment, the attribute name of `x.name`, a keyword
// argument's name.
func (s *pythonLocalSources) spelledOnly(node *sitter.Node) bool {
	parent := node.Parent()
	if parent == nil {
		return false
	}
	switch parent.Symbol() {
	case pythonSyms.assignment:
		return pythonIsFieldChild(parent, "left", node)
	case pythonSyms.attribute:
		return pythonIsFieldChild(parent, "attribute", node)
	case pythonSyms.keywordArgument:
		return pythonIsFieldChild(parent, pythonFieldName, node)
	}
	return false
}

// listChanges reports whether the list a function local holds may change:
// the name is used other than as a bare argument of a call.
func (s *pythonLocalSources) listChanges(name string) bool {
	return s == nil || s.all || s.nonArgument[name]
}

// escapes reports an identifier that may hand its object to other code. Only
// three occurrences do not: the name's own binding, an attribute or keyword
// name that merely spells it, and the receiver of a direct method call
// `name.m(...)` outside any nested def, class or lambda. Passed, aliased,
// returned, stored, captured or used as a context manager, the object reaches
// code that may write its attributes.
func (s *pythonLocalSources) escapes(node *sitter.Node) bool {
	parent := node.Parent()
	if parent == nil {
		return false
	}
	switch parent.Symbol() {
	case pythonSyms.assignment:
		return !pythonIsFieldChild(parent, "left", node)
	case pythonSyms.keywordArgument:
		return !pythonIsFieldChild(parent, pythonFieldName, node)
	case pythonSyms.attribute:
		if !pythonIsFieldChild(parent, "object", node) {
			return false
		}
		call := parent.Parent()
		return call == nil || call.Symbol() != pythonSyms.call || !pythonIsFieldChild(call, "function", parent) || s.inNestedScope(node)
	}
	return true
}

func pythonIsFieldChild(parent *sitter.Node, field string, child *sitter.Node) bool {
	node := parent.ChildByFieldName(field)
	return node != nil && node.Equal(child)
}

// inNestedScope reports whether node sits under a def, class or lambda nested
// inside the indexed function. The climb is bounded by the node's own
// statement nesting depth.
func (s *pythonLocalSources) inNestedScope(node *sitter.Node) bool {
	for p := node.Parent(); p != nil; p = p.Parent() {
		s.tick()
		switch p.Symbol() {
		case pythonSyms.functionDefinition:
			return p.StartByte() != s.root
		case pythonSyms.classDefinition:
			return true
		}
		// The grammar has two named "lambda" symbols and pythonSyms keeps only
		// one of them, so match the node type.
		if p.Type() == "lambda" {
			return true
		}
	}
	return false
}

// observeClassName poisons a class statement's own name; pythonWalkClass
// returns before observe sees the node.
func (s *pythonLocalSources) observeClassName(node *sitter.Node, src []byte) {
	if name := node.ChildByFieldName(pythonFieldName); name != nil {
		e := s.entry(name.Content(src))
		e.poisoned, e.nonLiteral = true, true
		e.note(pythonBoundClass)
	}
}

// observeImport poisons every name an import statement spells and counts one
// import binding for each name it binds: `import a.b` binds a, `as x` binds x.
func (s *pythonLocalSources) observeImport(node *sitter.Node, src []byte) {
	s.markPoisoned(node, src)
	from := node.Symbol() == pythonSyms.importFromStatement
	for i := 0; i < int(node.ChildCount()); i++ {
		if from && node.FieldNameForChild(i) != pythonFieldName {
			continue
		}
		var bound string
		switch child := node.Child(i); child.Symbol() {
		case pythonSyms.dottedName:
			bound, _, _ = strings.Cut(child.Content(src), ".")
		case pythonSyms.aliasedImport:
			if alias := child.ChildByFieldName("alias"); alias != nil {
				bound = alias.Content(src)
			}
		}
		if bound != "" {
			s.entry(bound).note(pythonBoundImport)
		}
	}
}

func (s *pythonLocalSources) markPoisoned(node *sitter.Node, src []byte) {
	if node.Symbol() == pythonSyms.identifier {
		e := s.entry(node.Content(src))
		e.poisoned, e.nonLiteral = true, true
		e.rebound = e.rebound || e.passed
		return
	}
	for i := 0; i < int(node.NamedChildCount()); i++ {
		s.markPoisoned(node.NamedChild(i), src)
	}
}

func (s *pythonLocalSources) observeAssignment(node *sitter.Node, src []byte) {
	left, right := node.ChildByFieldName("left"), node.ChildByFieldName("right")
	if left == nil {
		return
	}
	if left.Symbol() != pythonSyms.identifier {
		s.poisonTarget(left, src)
		return
	}
	name := left.Content(src)
	if right != nil && !s.inNestedScope(node) {
		if root, ok := pythonLocalSourceRoot(right, src); ok {
			s.bind(name, right, right.Content(src), root)
			return
		}
	}
	s.poison(name)
	if e := s.byName[name]; right != nil && e.bindings == 1 && !s.inNestedScope(node) {
		switch {
		case right.Symbol() == pythonSyms.call:
			e.construction = right
		case right.Type() == pythonNodeDictionary:
			e.table = right
		}
	}
}

// construction returns the call that constructs the receiver name, when the
// function binds name exactly once, to that call, writes none of its
// attributes, and uses it only to call its methods. A module-level name is
// left out: any module may rebind it.
func (s *pythonLocalSources) construction(name string) *sitter.Node {
	if s == nil || s.all || s.module {
		return nil
	}
	e := s.byName[name]
	if e == nil || e.bindings != 1 || e.passed || e.mutated || s.escaped[name] {
		return nil
	}
	return e.construction
}

// boundCall returns the call a name is bound to, when the scope binds the
// name exactly once, to that call: no other assignment, import, class,
// parameter or `global` declaration binds it.
func (s *pythonLocalSources) boundCall(name string) *sitter.Node {
	if s == nil || s.all {
		return nil
	}
	e := s.byName[name]
	if e == nil || e.bindings != 1 || e.kind != pythonBoundOther || e.declared {
		return nil
	}
	for _, value := range []*sitter.Node{e.construction, e.value} {
		if value != nil && value.Symbol() == pythonSyms.call {
			return value
		}
	}
	return nil
}

// poisonTarget poisons every name a binding target introduces. An attribute
// or subscript target binds no name.
func (s *pythonLocalSources) poisonTarget(target *sitter.Node, src []byte) {
	if target == nil {
		return
	}
	if sym := target.Symbol(); sym == pythonSyms.attribute || sym == pythonSyms.subscript {
		if object := target.ChildByFieldName("object"); sym == pythonSyms.attribute && object != nil && object.Symbol() == pythonSyms.identifier {
			s.entry(object.Content(src)).mutated = true
		}
		return
	}
	s.poisonIdentifiers(target, src)
}

// pythonLocalSourceRoot admits the value shapes a key size or an algorithm name
// can come from: an integer literal or a plain string literal (empty root),
// a dotted name (an algorithm constant such as hashes.SHA256 or Type.ID), a
// zero-argument call through a dotted name (a curve constructor such as
// ec.SECP521R1()), a read of a dispatch table (`DIGESTS[alg]`), and a read
// that looks like a runtime input (os.getenv, sys.argv[1]), whose leading
// name is returned so the use site can require it to be an import.
func pythonLocalSourceRoot(value *sitter.Node, src []byte) (root string, ok bool) {
	switch value.Symbol() {
	case pythonSyms.integer:
		return "", true
	case pythonSyms.string:
		return "", pythonPlainString(value, src)
	case pythonSyms.list, pythonSyms.tuple:
		return "", pythonLiteralDisplay(value, src) != ""
	case pythonSyms.attribute:
		// A dotted name (`hashes.SHA256`): a constant when its leading name
		// is an import, which the use site requires.
		return pythonDottedRoot(value, src)
	case pythonSyms.subscript:
		if pythonRuntimeShape(value, src) {
			return pythonDottedRoot(value.ChildByFieldName("value"), src)
		}
		// A read of a dispatch table, by name or in place: the use site
		// decides whether the table is one (pythonTableSubscript).
		table := pythonUnparenthesized(value.ChildByFieldName("value"))
		return "", table != nil && (table.Symbol() == pythonSyms.identifier || table.Type() == pythonNodeDictionary)
	case pythonSyms.call:
		if pythonRuntimeShape(value, src) {
			return pythonDottedRoot(value.ChildByFieldName("function"), src)
		}
		args := value.ChildByFieldName("arguments")
		if args == nil || args.NamedChildCount() != 0 {
			return "", false
		}
		fn := value.ChildByFieldName("function")
		if fn == nil || fn.Symbol() != pythonSyms.attribute {
			return "", false
		}
		return pythonDottedRoot(fn, src)
	default:
		return "", false
	}
}

// pythonLiteralDisplay is a list or tuple display of plain string and
// integer literals (one or more), written `[e1, e2]` / `(e1, e2)` / `(e1,)`
// with its elements as written; "" for any other value.
func pythonLiteralDisplay(value *sitter.Node, src []byte) string {
	if value == nil || value.Symbol() != pythonSyms.list && value.Symbol() != pythonSyms.tuple {
		return ""
	}
	var elements []string
	for i := 0; i < int(value.NamedChildCount()); i++ {
		switch child := value.NamedChild(i); {
		case child.Type() == pythonNodeComment:
		case child.Symbol() == pythonSyms.integer || child.Symbol() == pythonSyms.string && pythonPlainString(child, src):
			elements = append(elements, child.Content(src))
		default:
			return ""
		}
	}
	switch {
	case len(elements) == 0:
		return ""
	case value.Symbol() == pythonSyms.list:
		return "[" + strings.Join(elements, ", ") + "]"
	case len(elements) == 1:
		return "(" + elements[0] + ",)"
	}
	return "(" + strings.Join(elements, ", ") + ")"
}

// pythonPlainString admits a string literal whose source text is its value:
// one quote character, no prefix (f, b, r, u), no escape sequence, no
// interpolation.
func pythonPlainString(value *sitter.Node, src []byte) bool {
	for i := 0; i < int(value.NamedChildCount()); i++ {
		child := value.NamedChild(i)
		switch child.Type() {
		case "string_start":
			if start := child.Content(src); start != `"` && start != "'" {
				return false
			}
		case "string_content":
			if child.NamedChildCount() != 0 {
				return false
			}
		case "string_end":
		default:
			return false
		}
	}
	return true
}

func pythonDottedRoot(node *sitter.Node, src []byte) (string, bool) {
	for node != nil {
		switch node.Symbol() {
		case pythonSyms.identifier:
			return node.Content(src), true
		case pythonSyms.attribute:
			if attr := node.ChildByFieldName("attribute"); attr == nil || attr.Symbol() != pythonSyms.identifier {
				return "", false
			}
			node = node.ChildByFieldName("object")
		default:
			return "", false
		}
	}
	return "", false
}

// poisonExisting poisons every name bound so far: `from m import *` can
// rebind any of them, while a name bound after it overrides the import.
func (s *pythonLocalSources) poisonExisting() {
	for _, e := range s.byName {
		s.tick()
		e.note(pythonBoundOther)
		e.poisoned, e.nonLiteral = true, true
		e.rebound = e.rebound || e.passed
	}
}

// observeDynamicBinding poisons the whole file-level index when a call can
// bind module names by string: exec, globals()/vars()/locals() (a module-level
// locals() is the module dict) and setattr on the module object.
func (s *pythonLocalSources) observeDynamicBinding(call *sitter.Node, src []byte) {
	fn := call.ChildByFieldName("function")
	if fn == nil || fn.Symbol() != pythonSyms.identifier {
		return
	}
	switch string(src[fn.StartByte():fn.EndByte()]) {
	case "exec", "globals", "vars", "locals":
		s.all = true
	case "setattr":
		if args := call.ChildByFieldName("arguments"); args != nil {
			text := args.Content(src)
			if strings.Contains(text, "sys.modules") || strings.Contains(text, "__name__") || strings.Contains(text, "globals") {
				s.all = true
			}
		}
	}
}
