// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// rustValueMaxDepth bounds how deep one argument's provenance goes: the
// nesting of `let` hops, call results and the arguments below them, and
// const-to-const hops.
const rustValueMaxDepth = 4

// rustValueKind is what the value walk knows a binding holds.
type rustValueKind uint8

const (
	// rustValueLet is a `let name = init` (or `let mut`), traced to init.
	rustValueLet rustValueKind = iota + 1
	// rustValueParam is a parameter of the function being parsed, which a
	// caller's argument fills.
	rustValueParam
	// rustValueConst is a const or static item declared in a block.
	rustValueConst
)

// rustValue is one binding the value walk can follow. A binding it cannot
// follow (a destructuring pattern, a match arm, a closure parameter) is
// recorded as nil, so it still shadows an enclosing name.
type rustValue struct {
	kind         rustValueKind
	declaredType string
	line         int
	// sources is a let's initializer, resolved in the scope of the let, or
	// a block const's value.
	sources []SourceNode
	// index is a parameter's position among the arguments a call passes:
	// `self` is the receiver, not an argument.
	index int
	// mayValues, for a let the function assigns again, are the string
	// literals it may hold; mayExhaustive says it holds nothing else.
	reassigned    bool
	mayValues     []string
	mayExhaustive bool
}

// rustConstItem is a const or non-mut static item of the file outside any
// function body, keyed by the identity a use of it resolves to.
type rustConstItem struct {
	value        *sitter.Node
	module       string
	declaredType string
	line         int
	ambiguous    bool
}

// rustValueTracker traces the values of a function's call arguments during
// its call walk (FunctionCall.ArgumentSources): literals, the file's const
// and static items, lets traced to their initializer, the function's
// parameters, and call results with the values passed to them. It stays
// within the function and the file: a parameter is reported as one, for a
// consumer to follow into the callers.
type rustValueTracker struct {
	p        *RustParser
	src      []byte
	filePath string
	body     *sitter.Node
	// calleeAt is the callee of each call the walk already parsed, by span,
	// so a let initialized from a call names its target without parsing the
	// call again.
	calleeAt map[[2]uint32]FunctionID
	// assigns holds, by name, the assignments the body makes to a plain name
	// (`x = ..`, `x += ..`), collected on first need.
	assigns map[string][]*sitter.Node
	scanned bool
}

func (p *RustParser) newRustValueTracker(body *sitter.Node, src []byte, filePath string) *rustValueTracker {
	return &rustValueTracker{p: p, src: src, filePath: filePath, body: body, calleeAt: make(map[[2]uint32]FunctionID)}
}

func rustSpanKey(node *sitter.Node) [2]uint32 {
	return [2]uint32{node.StartByte(), node.EndByte()}
}

func (t *rustValueTracker) location(node *sitter.Node) *SourceLocation {
	return &SourceLocation{FilePath: t.filePath, Line: int(node.StartPoint().Row) + 1}
}

// noteCall records the callee a parsed call resolved to.
func (t *rustValueTracker) noteCall(node *sitter.Node, callee FunctionID) {
	t.calleeAt[rustSpanKey(node)] = callee
}

// record binds name in the innermost scope of c to v (nil: a binding the
// walk cannot follow).
func (c *rustTypeCtx) recordValue(name string, v *rustValue) {
	if name == "" || c.bindings == nil {
		return
	}
	if c.bindings.values == nil {
		c.bindings.values = make(map[string]*rustValue)
	}
	c.bindings.values[name] = v
}

// lookupValue returns what the innermost binding of name holds. bound is
// false when no local binds name; a binding the value walk does not follow
// is bound with a nil value.
func (b *rustBindings) lookupValue(name string) (v *rustValue, bound bool) {
	for scope := b; scope != nil; scope = scope.parent {
		if v, ok := scope.values[name]; ok {
			return v, true
		}
		if scope.declared[name] {
			return nil, true
		}
		if _, typed := scope.names[name]; typed {
			return nil, true
		}
	}
	return nil, false
}

// bindOpaque binds every name a pattern, a parameter or a parameter list
// introduces as a binding the walk does not follow.
func (t *rustValueTracker) bindOpaque(c *rustTypeCtx, node *sitter.Node) {
	if node == nil {
		return
	}
	switch node.Type() {
	case "parameters", "closure_parameters":
		for i := 0; i < int(node.NamedChildCount()); i++ {
			t.bindOpaque(c, node.NamedChild(i))
		}
		return
	case "parameter":
		t.bindOpaque(c, node.ChildByFieldName("pattern"))
		return
	}
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case goNodeIdentifier, "shorthand_field_identifier":
			c.recordValue(n.Content(c.src), nil)
			return
		case javaNodeScopedIdentifier, goNodeTypeIdentifier, javaNodeScopedTypeIdentifier, rustNodeFieldIdentifier:
			return
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(node)
}

// rustSimplePatternName is the one name a pattern binds when it is `x` or
// `mut x`, with whether it is mutable.
func rustSimplePatternName(pattern *sitter.Node, src []byte) (string, bool) {
	if pattern == nil {
		return "", false
	}
	switch pattern.Type() {
	case goNodeIdentifier:
		return pattern.Content(src), false
	case rustNodeMutPattern:
		for i := 0; i < int(pattern.NamedChildCount()); i++ {
			if child := pattern.NamedChild(i); child.Type() == goNodeIdentifier {
				return child.Content(src), true
			}
		}
	}
	return "", false
}

// bindParameters binds the parameters of the function whose body the walk
// covers. A parameter the body assigns no longer holds the caller's value at
// every use, so it is followed no further.
func (t *rustValueTracker) bindParameters(c *rustTypeCtx) {
	if t.body == nil {
		return
	}
	fn := t.body.Parent()
	if fn == nil || fn.Symbol() != rustSyms.functionItem {
		return
	}
	params := fn.ChildByFieldName("parameters")
	if params == nil {
		return
	}
	if params.HasError() {
		t.bindOpaque(c, params)
		for name := range collectRustParameterTypes(params, c.src) {
			c.recordValue(name, nil)
		}
		return
	}
	index := 0
	for i := 0; i < int(params.NamedChildCount()); i++ {
		param := params.NamedChild(i)
		switch param.Type() {
		case "parameter":
			pattern := param.ChildByFieldName("pattern")
			name, _ := rustSimplePatternName(pattern, c.src)
			mutable := rustNamedChildOfType(param, "mutable_specifier") != nil
			if name == "" || mutable && len(t.assignments(name)) > 0 {
				t.bindOpaque(c, pattern)
			} else {
				c.recordValue(name, &rustValue{kind: rustValueParam, index: index, declaredType: nodeFieldText(param, "type", c.src)})
			}
			index++
		case "variadic_parameter":
			index++
		}
	}
}

// assignments returns the assignments the body makes to name.
func (t *rustValueTracker) assignments(name string) []*sitter.Node {
	if !t.scanned {
		t.scanned = true
		var walk func(n *sitter.Node)
		walk = func(n *sitter.Node) {
			switch n.Type() {
			case rustNodeAssignmentExpression, "compound_assignment_expr":
				if left := n.ChildByFieldName("left"); left != nil && left.Type() == goNodeIdentifier {
					if t.assigns == nil {
						t.assigns = make(map[string][]*sitter.Node)
					}
					key := left.Content(t.src)
					t.assigns[key] = append(t.assigns[key], n)
				}
			}
			for i := 0; i < int(n.NamedChildCount()); i++ {
				walk(n.NamedChild(i))
			}
		}
		if t.body != nil {
			walk(t.body)
		}
	}
	return t.assigns[name]
}

// bindBlockItems binds the const and non-mut static items a block declares,
// which are in scope in the whole block.
func (t *rustValueTracker) bindBlockItems(c *rustTypeCtx, block *sitter.Node) {
	for i := 0; i < int(block.NamedChildCount()); i++ {
		item := block.NamedChild(i)
		if item.Type() != rustNodeConstItem && item.Type() != rustNodeStaticItem {
			continue
		}
		name := nodeFieldText(item, "name", c.src)
		if rustNamedChildOfType(item, "mutable_specifier") != nil {
			c.recordValue(name, nil)
			continue
		}
		c.recordValue(name, &rustValue{
			kind:         rustValueConst,
			declaredType: nodeFieldText(item, "type", c.src),
			line:         int(item.StartPoint().Row) + 1,
			sources:      t.sources(c, item.ChildByFieldName("value"), 0),
		})
	}
}

// letSources resolves a let's initializer in the scope the let reads it in.
func (t *rustValueTracker) letSources(c *rustTypeCtx, let *sitter.Node) []SourceNode {
	return t.sources(c, let.ChildByFieldName("value"), 0)
}

// bindLet records a `let x = init` or `let mut x = init`; any other pattern
// was bound as opaque by bindPattern. A let without an initializer, or a
// `let mut` the block assigns again after it, holds the string literals it
// is given (MayValues) rather than one source.
func (t *rustValueTracker) bindLet(c *rustTypeCtx, let *sitter.Node, init []SourceNode) {
	name, mutable := rustSimplePatternName(let.ChildByFieldName("pattern"), c.src)
	if name == "" {
		return
	}
	// `let mut x` carries its `mut` on the declaration, not in the pattern.
	mutable = mutable || rustNamedChildOfType(let, "mutable_specifier") != nil
	value := let.ChildByFieldName("value")
	v := &rustValue{
		kind:         rustValueLet,
		declaredType: nodeFieldText(let, "type", c.src),
		line:         int(let.StartPoint().Row) + 1,
		sources:      init,
	}
	if mutable || value == nil {
		t.noteReassignments(c, let, name, value, v)
	}
	c.recordValue(name, v)
}

// noteReassignments fills in what a let the function may assign again can
// hold: the string literals of its initializer and of the plain assignments
// to its name after it in its block. Exhaustive when every one of them is a
// string literal.
func (t *rustValueTracker) noteReassignments(c *rustTypeCtx, let *sitter.Node, name string, value *sitter.Node, v *rustValue) {
	scope := let.Parent()
	var later []*sitter.Node
	for _, a := range t.assignments(name) {
		if a.StartByte() >= let.EndByte() && (scope == nil || a.EndByte() <= scope.EndByte()) {
			later = append(later, a)
		}
	}
	if len(later) == 0 {
		return
	}
	v.reassigned, v.sources = true, nil
	exhaustive := true
	add := func(expr *sitter.Node) {
		expr = rustUnwrapValue(expr)
		if expr == nil || expr.Type() != rustNodeStringLiteral && expr.Type() != rustNodeRawStringLiteral {
			exhaustive = false
			return
		}
		text := expr.Content(c.src)
		for _, seen := range v.mayValues {
			if seen == text {
				return
			}
		}
		v.mayValues = append(v.mayValues, text)
	}
	if value != nil {
		add(value)
	}
	for _, a := range later {
		if a.Type() != rustNodeAssignmentExpression {
			exhaustive = false
			continue
		}
		add(a.ChildByFieldName("right"))
	}
	v.mayExhaustive = exhaustive && len(v.mayValues) > 0
}

// rustUnwrapValue sees through what does not change a value: parentheses,
// `&`/`&mut`, a deref, `?`, `.await` and an `as` cast.
func rustUnwrapValue(node *sitter.Node) *sitter.Node {
	for depth := 0; node != nil && depth < rustMaxTypeDepth; depth++ {
		switch node.Symbol() {
		case rustSyms.parenthesized:
			node = rustInnerExpression(node)
		case rustSyms.referenceExpression, rustSyms.typeCast:
			node = node.ChildByFieldName("value")
		case rustSyms.tryExpression, rustSyms.awaitExpression:
			node = node.NamedChild(0)
		case rustSyms.unaryExpression:
			if op := node.Child(0); op == nil || op.Type() != "*" {
				return node
			}
			node = node.NamedChild(0)
		default:
			return node
		}
	}
	return node
}

// argumentSources is FunctionCall.ArgumentSources for a parsed call: one
// entry per argument of call.Arguments, nil where nothing is known, and nil
// when no argument is known.
func (t *rustValueTracker) argumentSources(c *rustTypeCtx, node *sitter.Node, call *FunctionCall) [][]SourceNode {
	args := rustArgumentNodes(node)
	if len(args) == len(call.Arguments)+1 && call.ReceiverVar != "" {
		// A call in fully qualified syntax passes its receiver first; its
		// Arguments leave the receiver out.
		args = args[1:]
	}
	if len(args) == 0 || len(args) != len(call.Arguments) {
		return nil
	}
	sources := make([][]SourceNode, len(args))
	known := false
	for i, arg := range args {
		sources[i] = t.sources(c, arg, 0)
		known = known || sources[i] != nil
	}
	if !known {
		return nil
	}
	return sources
}

// rustArgumentNodes returns a call's argument expressions, comments and
// attributes left out.
func rustArgumentNodes(call *sitter.Node) []*sitter.Node {
	list := rustCallArgumentsNode(call)
	if list == nil {
		return nil
	}
	args := make([]*sitter.Node, 0, list.NamedChildCount())
	for i := 0; i < int(list.NamedChildCount()); i++ {
		arg := list.NamedChild(i)
		if rustIsComment(arg.Symbol()) || arg.Type() == rustNodeAttributeItem {
			continue
		}
		args = append(args, arg)
	}
	return args
}

// sources is the provenance of an expression at nesting depth: a literal is
// a VALUE, a local a VARIABLE over its initializer, a parameter a PARAMETER,
// a const or static item a FIELD over its value, a call a CALL_RESULT over
// the values passed to it (its receiver's included), and an operation or an
// expression macro an EXPRESSION over its operands. Anything else, and
// anything deeper than rustValueMaxDepth, yields nothing.
func (t *rustValueTracker) sources(c *rustTypeCtx, node *sitter.Node, depth int) []SourceNode {
	node = rustUnwrapValue(node)
	if node == nil || depth > rustValueMaxDepth {
		return nil
	}
	switch node.Type() {
	case rustNodeStringLiteral, rustNodeRawStringLiteral, "char_literal", "integer_literal", "float_literal", "boolean_literal":
		return []SourceNode{{Type: sourceNodeValue, Value: node.Content(c.src)}}
	case "unary_expression":
		if literal := rustNegativeLiteral(node, c.src); literal != "" {
			return []SourceNode{{Type: sourceNodeValue, Value: literal}}
		}
	case goNodeIdentifier:
		return t.identifierSources(c, node, depth)
	case javaNodeScopedIdentifier:
		return t.pathSources(c, node, depth)
	case rustNodeCallExpression:
		return t.callSources(c, node, depth)
	case "binary_expression":
		operands := append(t.sources(c, node.ChildByFieldName("left"), depth+1), t.sources(c, node.ChildByFieldName("right"), depth+1)...)
		return t.expression(node, c.src, operands)
	case "macro_invocation":
		return t.macroSources(c, node, depth)
	}
	return nil
}

// rustNegativeLiteral is the text of `-1` or `-1.5`, "" for any other unary.
func rustNegativeLiteral(node *sitter.Node, src []byte) string {
	inner := node.NamedChild(0)
	if op := node.Child(0); inner == nil || op == nil || op.Type() != "-" {
		return ""
	}
	if inner.Type() != "integer_literal" && inner.Type() != "float_literal" {
		return ""
	}
	return "-" + inner.Content(src)
}

func (t *rustValueTracker) expression(node *sitter.Node, src []byte, operands []SourceNode) []SourceNode {
	if len(operands) == 0 {
		return nil
	}
	return []SourceNode{{Type: sourceNodeExpression, Value: strings.TrimSpace(node.Content(src)), Location: t.location(node), SourceNodes: operands}}
}

func (t *rustValueTracker) identifierSources(c *rustTypeCtx, node *sitter.Node, depth int) []SourceNode {
	name := node.Content(c.src)
	v, bound := c.bindings.lookupValue(name)
	if bound {
		if v == nil {
			return nil
		}
		switch v.kind {
		case rustValueParam:
			return []SourceNode{{Type: sourceNodeParameter, Name: name, DeclaredType: v.declaredType, ParameterIndex: v.index, Location: t.location(node)}}
		case rustValueLet:
			location := &SourceLocation{FilePath: t.filePath, Line: v.line}
			if v.reassigned {
				if len(v.mayValues) == 0 {
					return nil
				}
				return []SourceNode{{Type: sourceNodeVariable, Name: name, DeclaredType: v.declaredType, Location: location, MayValues: v.mayValues, MayValuesExhaustive: v.mayExhaustive}}
			}
			if len(v.sources) == 0 {
				return nil
			}
			return []SourceNode{{Type: sourceNodeVariable, Name: name, DeclaredType: v.declaredType, Location: location, SourceNodes: rustClipSources(v.sources, depth+1)}}
		case rustValueConst:
			if len(v.sources) == 0 {
				return nil
			}
			return []SourceNode{{Type: sourceNodeField, Name: name, DeclaredType: v.declaredType, Location: &SourceLocation{FilePath: t.filePath, Line: v.line}, SourceNodes: rustClipSources(v.sources, depth+1)}}
		}
		return nil
	}
	analysis := c.analysis
	key := FunctionID{Package: analysis.PackagePath, Name: name}
	if pkg, ok := analysis.Imports[name]; ok {
		key = FunctionID{Package: pkg, Name: name}
	} else if renamed, ok := rustRenamedFunctionCallee(analysis, name); ok {
		key = renamed
	}
	return t.constSources(key, name, depth)
}

// pathSources resolves a path such as `consts::ALG`, `Self::ALG` or
// `crate::m::ALG` the way a call of that path resolves, to a const or static
// item of the file.
func (t *rustValueTracker) pathSources(c *rustTypeCtx, node *sitter.Node, depth int) []SourceNode {
	if len(t.p.rustConsts) == 0 {
		return nil
	}
	call := t.p.parseScopedCall(node, c.src, t.filePath, int(node.StartPoint().Row)+1, nil, c.analysis, c.selfType, c.generics)
	if call == nil {
		return nil
	}
	return t.constSources(call.Callee, strings.TrimSpace(node.Content(c.src)), depth)
}

// constSources is the FIELD a use of the file's const or static item key
// reads, over the literal it is initialized with.
func (t *rustValueTracker) constSources(key FunctionID, written string, depth int) []SourceNode {
	item := t.p.rustConsts[key.String()]
	if item == nil || item.ambiguous {
		return nil
	}
	value := t.rustConstValue(item, 0)
	if value == "" {
		return nil
	}
	return []SourceNode{{
		Type:         sourceNodeField,
		Name:         written,
		DeclaredType: item.declaredType,
		Location:     &SourceLocation{FilePath: t.filePath, Line: item.line},
		SourceNodes:  rustClipSources([]SourceNode{{Type: sourceNodeValue, Value: value}}, depth+1),
	}}
}

// rustConstValue is the literal a const item holds, through a chain of
// consts of its module naming one another.
func (t *rustValueTracker) rustConstValue(item *rustConstItem, hops int) string {
	value := rustUnwrapValue(item.value)
	if value == nil || hops > rustValueMaxDepth {
		return ""
	}
	switch value.Type() {
	case rustNodeStringLiteral, rustNodeRawStringLiteral, "char_literal", "integer_literal", "float_literal", "boolean_literal":
		return value.Content(t.src)
	case "unary_expression":
		return rustNegativeLiteral(value, t.src)
	case goNodeIdentifier:
		next := t.p.rustConsts[FunctionID{Package: item.module, Name: value.Content(t.src)}.String()]
		if next == nil || next.ambiguous || next == item {
			return ""
		}
		return t.rustConstValue(next, hops+1)
	}
	return ""
}

// callSources is the CALL_RESULT of a call, over the values of its receiver
// and its arguments: a value passed to a call reaches its result as far as
// a taint rule reads it.
func (t *rustValueTracker) callSources(c *rustTypeCtx, node *sitter.Node, depth int) []SourceNode {
	callee, ok := t.calleeAt[rustSpanKey(node)]
	if !ok {
		call := t.p.parseCallExpr(node, c, t.filePath)
		if call == nil {
			return nil
		}
		callee = call.Callee
	}
	result := SourceNode{Type: sourceNodeCallResult, Value: strings.TrimSpace(node.Content(c.src)), CallTarget: &callee, Location: t.location(node)}
	if depth < rustValueMaxDepth {
		if fn := node.ChildByFieldName("function"); fn != nil && fn.Type() == rustNodeFieldExpression {
			result.SourceNodes = append(result.SourceNodes, t.sources(c, fn.ChildByFieldName("value"), depth+1)...)
		}
		for _, arg := range rustArgumentNodes(node) {
			result.SourceNodes = append(result.SourceNodes, t.sources(c, arg, depth+1)...)
		}
	}
	return []SourceNode{result}
}

// macroSources is an expression macro (`format!`, `concat!`, `vec!`) as an
// EXPRESSION over the values of its arguments, read the way the call walk
// reads them (parseRustMacroArguments).
func (t *rustValueTracker) macroSources(c *rustTypeCtx, node *sitter.Node, depth int) []SourceNode {
	if depth >= rustValueMaxDepth {
		return nil
	}
	tree := t.p.parseRustMacroArguments(node, c.src)
	if tree == nil {
		return nil
	}
	defer tree.Close()
	statement := tree.RootNode().NamedChild(0)
	if statement == nil || statement.NamedChildCount() == 0 {
		return nil
	}
	expr := statement.NamedChild(0)
	elements := []*sitter.Node{expr}
	switch expr.Type() {
	case "tuple_expression", "array_expression":
		elements = elements[:0]
		for i := 0; i < int(expr.NamedChildCount()); i++ {
			if child := expr.NamedChild(i); !rustIsComment(child.Symbol()) {
				elements = append(elements, child)
			}
		}
	}
	var operands []SourceNode
	for _, element := range elements {
		operands = append(operands, t.sources(c, element, depth+1)...)
	}
	return t.expression(node, c.src, operands)
}

// rustClipSources copies nodes placed at nesting depth, dropping what lies
// deeper than rustValueMaxDepth. A let's traced initializer is shared by
// every use of the let, so each use gets its own copy.
func rustClipSources(nodes []SourceNode, depth int) []SourceNode {
	if len(nodes) == 0 || depth > rustValueMaxDepth {
		return nil
	}
	out := make([]SourceNode, len(nodes))
	for i := range nodes {
		out[i] = nodes[i]
		out[i].SourceNodes = rustClipSources(nodes[i].SourceNodes, depth+1)
	}
	return out
}

// collectRustConstItems indexes the const and non-mut static items the file
// declares outside function bodies, at its top level, in inline modules and
// in inherent or trait impl blocks, under the identity a use resolves to:
// `<module>.NAME`, and `<module>.(Type).NAME` for an associated const. A
// name declared twice (under different cfg attributes) is ambiguous.
func (p *RustParser) collectRustConstItems(root *sitter.Node, src []byte, packagePath string) map[string]*rustConstItem {
	items := make(map[string]*rustConstItem)
	add := func(item *sitter.Node, id FunctionID, module string) {
		if rustNamedChildOfType(item, "mutable_specifier") != nil || id.Name == "" {
			return
		}
		key := id.String()
		if existing := items[key]; existing != nil {
			existing.ambiguous = true
			return
		}
		items[key] = &rustConstItem{
			value:        item.ChildByFieldName("value"),
			module:       module,
			declaredType: nodeFieldText(item, "type", src),
			line:         int(item.StartPoint().Row) + 1,
		}
	}
	var walk func(scope *sitter.Node, module string)
	walk = func(scope *sitter.Node, module string) {
		for i := 0; i < int(scope.NamedChildCount()); i++ {
			child := scope.NamedChild(i)
			switch child.Type() {
			case rustNodeConstItem, rustNodeStaticItem:
				add(child, FunctionID{Package: module, Name: nodeFieldText(child, "name", src)}, module)
			case rustNodeModItem:
				if body := child.ChildByFieldName("body"); body != nil {
					walk(body, p.SubPackagePath(module, nodeFieldText(child, "name", src)))
				}
			case rustNodeImplItem:
				typeNode, body := child.ChildByFieldName("type"), child.ChildByFieldName("body")
				if typeNode == nil || body == nil {
					continue
				}
				typeName := p.extractTypeName(typeNode, src)
				if typeName == "" {
					continue
				}
				for j := 0; j < int(body.NamedChildCount()); j++ {
					if item := body.NamedChild(j); item.Type() == rustNodeConstItem {
						add(item, FunctionID{Package: module, Type: typeName, Name: nodeFieldText(item, "name", src)}, module)
					}
				}
			}
		}
	}
	walk(root, packagePath)
	return items
}
