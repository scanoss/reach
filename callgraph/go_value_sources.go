// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// goValueMaxDepth bounds how deep one argument's provenance goes: the nesting
// of local hops, call results and the arguments below them, and operands. It
// matches rustValueMaxDepth.
const goValueMaxDepth = 4

// goConversionTypes are the predeclared types a call-shaped conversion
// (`string(b)`, `int64(n)`) names.
var goConversionTypes = map[string]bool{
	"any": true, "bool": true, "byte": true, "complex64": true, "complex128": true,
	"error": true, "float32": true, "float64": true, "int": true, "int8": true,
	"int16": true, "int32": true, "int64": true, "rune": true, "string": true,
	"uint": true, "uint8": true, "uint16": true, "uint32": true, "uint64": true,
	"uintptr": true,
}

// goValueBinding is what a local var holds at its uses, computed once per
// declared name. A local the function writes again after its declaration
// holds the string literals it is given (mayValues) rather than one source.
type goValueBinding struct {
	sources       []SourceNode
	reassigned    bool
	mayValues     []string
	mayExhaustive bool
}

// goValueWrite is a write to a plain name: an assignment, an increment, a
// range or receive assignment, or `&name`, which lets anything write it.
// value is the expression a plain `=` stores, nil for every other write.
type goValueWrite struct {
	node  *sitter.Node
	value *sitter.Node
}

type goValueBindingKey struct {
	spec uintptr
	name string
}

// goValueCache holds what the value walk computes once per file. Reset it
// when the tree is closed.
type goValueCache struct {
	// calleeAt is the callee of each call the walk already parsed, by span,
	// so a local initialized from a call names the target the walk resolved
	// in the scope of the declaration, without parsing the call again.
	calleeAt map[[2]uint32]FunctionID
	bindings map[goValueBindingKey]*goValueBinding
	// writes holds, by name, the writes the file makes to a plain name,
	// collected on first need.
	writes  map[string][]goValueWrite
	scanned bool
}

func (c *goValueCache) reset() { *c = goValueCache{} }

// noteCall records the callee a parsed call resolved to.
func (c *goValueCache) noteCall(node *sitter.Node, callee FunctionID) {
	if c.calleeAt == nil {
		c.calleeAt = make(map[[2]uint32]FunctionID)
	}
	c.calleeAt[rustSpanKey(node)] = callee
}

// goValueWalk traces the values of a call's arguments
// (FunctionCall.ArgumentSources): literals, consts, locals traced to their
// initializer, the enclosing function's parameters, and call results with the
// values passed to them. It stays within the function and the file, except
// for a const a sibling file of the package declares: a parameter is reported
// as one, for a consumer to follow into the callers. Names resolve by position
// through the lexical scopes (goConstScopes), so a local shadowing an outer
// name in a nested scope hides it exactly where Go does.
type goValueWalk struct {
	p                         *GoParser
	src                       []byte
	filePath                  string
	analysis                  *FileAnalysis
	receiverType, receiverVar string
	varTypes                  map[string]string
}

func (w *goValueWalk) location(node *sitter.Node) *SourceLocation {
	return &SourceLocation{FilePath: w.filePath, Line: int(node.StartPoint().Row) + 1}
}

// argumentSources is FunctionCall.ArgumentSources for a parsed call: one entry
// per argument of call.Arguments, nil where nothing is known, and nil when no
// argument is known.
func (w *goValueWalk) argumentSources(node *sitter.Node, call *FunctionCall) [][]SourceNode {
	args := goArgumentNodes(node)
	if len(args) == 0 || len(args) != len(call.Arguments) {
		return nil
	}
	sources := make([][]SourceNode, len(args))
	known := false
	for i, arg := range args {
		sources[i] = w.sources(arg, 0)
		known = known || sources[i] != nil
	}
	if !known {
		return nil
	}
	return sources
}

// goArgumentNodes returns a call's argument expressions, comments left out.
func goArgumentNodes(call *sitter.Node) []*sitter.Node {
	args := call.ChildByFieldName("arguments")
	if args == nil || args.Type() != goNodeArgumentList {
		return nil
	}
	out := make([]*sitter.Node, 0, args.NamedChildCount())
	for i := 0; i < int(args.NamedChildCount()); i++ {
		if arg := args.NamedChild(i); arg.Type() != goNodeComment {
			out = append(out, arg)
		}
	}
	return out
}

// unwrap sees through what does not change a value: parentheses, `&` and
// `*`, and a conversion, `[]byte(s)`, `string(b)` or `T(v)` to a type the
// file declares, the way the Rust walk sees through an `as` cast.
func (w *goValueWalk) unwrap(node *sitter.Node) *sitter.Node {
	for node != nil {
		switch node.Type() {
		case goNodeParenExpr:
			node = node.NamedChild(0)
		case goNodeUnaryExpression:
			if op := node.Child(0); op == nil || op.Type() != "&" && op.Type() != "*" {
				return node
			}
			node = node.ChildByFieldName(goFieldOperand)
		case goNodeTypeConversion:
			node = node.ChildByFieldName(goFieldOperand)
		case goNodeCallExpression:
			operand := w.conversionOperand(node)
			if operand == nil {
				return node
			}
			node = operand
		default:
			return node
		}
	}
	return nil
}

// conversionOperand is the operand of a call-shaped conversion to a
// predeclared type no local shadows, or to a type the file declares; nil for
// a call.
func (w *goValueWalk) conversionOperand(call *sitter.Node) *sitter.Node {
	fn := call.ChildByFieldName(goFieldFunction)
	args := goArgumentNodes(call)
	if fn == nil || fn.Type() != goNodeIdentifier || len(args) != 1 || args[0].Type() == "variadic_argument" {
		return nil
	}
	name := fn.Content(w.src)
	if _, local := w.varTypes[name]; local || !goConversionTypes[name] && !w.analysis.DeclaredTypes[name] {
		return nil
	}
	return args[0]
}

// sources is the provenance of an expression at nesting depth: a literal is a
// VALUE, a local a VARIABLE over its initializer, a parameter a PARAMETER, a
// const a VARIABLE over its literal, a call a CALL_RESULT over the values
// passed to it (its receiver's included), and an operation or a composite
// literal an EXPRESSION over its operands. Anything else, and anything deeper
// than goValueMaxDepth, yields nothing.
func (w *goValueWalk) sources(node *sitter.Node, depth int) []SourceNode {
	node = w.unwrap(node)
	if node == nil || depth > goValueMaxDepth {
		return nil
	}
	switch node.Type() {
	case goNodeInterpretedStr, goNodeRawStr, goNodeIntLiteral, "float_literal", "imaginary_literal", "rune_literal", "true", "false":
		return []SourceNode{{Type: sourceNodeValue, Value: node.Content(w.src)}}
	case goNodeUnaryExpression:
		if literal := goNegativeLiteral(node, w.src); literal != "" {
			return []SourceNode{{Type: sourceNodeValue, Value: literal}}
		}
	case goNodeIdentifier:
		return w.identifierSources(node, depth)
	case goNodeCallExpression:
		return w.callSources(node, depth)
	case "binary_expression":
		operands := append(w.sources(node.ChildByFieldName(goFieldLeft), depth+1), w.sources(node.ChildByFieldName(goFieldRight), depth+1)...)
		return w.expression(node, operands)
	case goNodeCompositeLiteral:
		return w.literalSources(node, node.ChildByFieldName("body"), depth)
	case "literal_value":
		return w.literalSources(node, node, depth)
	}
	return nil
}

// goNegativeLiteral is the text of `-1` or `-1.5`, "" for any other unary.
func goNegativeLiteral(node *sitter.Node, src []byte) string {
	inner := node.ChildByFieldName(goFieldOperand)
	if op := node.Child(0); inner == nil || op == nil || op.Type() != "-" {
		return ""
	}
	if inner.Type() != goNodeIntLiteral && inner.Type() != "float_literal" {
		return ""
	}
	return "-" + inner.Content(src)
}

func (w *goValueWalk) expression(node *sitter.Node, operands []SourceNode) []SourceNode {
	if len(operands) == 0 {
		return nil
	}
	return []SourceNode{{Type: sourceNodeExpression, Value: strings.TrimSpace(node.Content(w.src)), Location: w.location(node), SourceNodes: operands}}
}

// literalSources is a composite literal, `T{A: v, w}`, or an untyped
// element literal nested in one, as an EXPRESSION over the values of its
// elements; a keyed element's key names a field or an index, not a value.
func (w *goValueWalk) literalSources(node, body *sitter.Node, depth int) []SourceNode {
	if body == nil {
		return nil
	}
	var operands []SourceNode
	for i := 0; i < int(body.NamedChildCount()); i++ {
		element := body.NamedChild(i)
		switch element.Type() {
		case "keyed_element":
			element = element.NamedChild(int(element.NamedChildCount()) - 1)
		case goNodeComment:
			continue
		}
		if element != nil && element.Type() == "literal_element" {
			element = element.NamedChild(0)
		}
		operands = append(operands, w.sources(element, depth+1)...)
	}
	return w.expression(node, operands)
}

func (w *goValueWalk) identifierSources(node *sitter.Node, depth int) []SourceNode {
	name := node.Content(w.src)
	decl, scope := w.p.consts.resolve(node, name, w.src)
	if decl == nil {
		if _, imported := w.analysis.Imports[name]; imported || w.p.consts.crossFile == nil {
			return nil
		}
		if value, ok := w.p.consts.crossFile(name); ok {
			return goConstSources(name, value, depth)
		}
		return nil
	}
	switch decl.kind {
	case goDeclLiteral:
		return goConstSources(name, decl.value, depth)
	case goDeclParam:
		if len(w.p.values.writesIn(w.root(node), w.src, name, scope.StartByte(), scope.EndByte())) > 0 {
			// Written in the body, it no longer holds the caller's value at
			// every use.
			return nil
		}
		return []SourceNode{{Type: sourceNodeParameter, Name: name, DeclaredType: goParameterType(decl.spec, w.src), ParameterIndex: decl.index, Location: w.location(node)}}
	case goDeclVar:
		if scope.Type() == goNodeSourceFile {
			// Any function of the package may write a package-level var.
			return nil
		}
		return w.varSources(node, name, decl, scope, depth)
	}
	return nil
}

// goConstSources is the VARIABLE a use of a literal const reads, over its
// literal: the shape const arguments have always had.
func goConstSources(name, value string, depth int) []SourceNode {
	return []SourceNode{{Type: sourceNodeVariable, Name: name, SourceNodes: rustClipSources([]SourceNode{{Type: sourceNodeValue, Value: value}}, depth+1)}}
}

// goParameterType is the type a parameter declaration states.
func goParameterType(param *sitter.Node, src []byte) string {
	if param == nil {
		return ""
	}
	return nodeFieldText(param, goFieldType, src)
}

func (w *goValueWalk) varSources(use *sitter.Node, name string, decl *goDecl, scope *sitter.Node, depth int) []SourceNode {
	if decl.tuple {
		return nil
	}
	b := w.binding(use, name, decl, scope)
	location := &SourceLocation{FilePath: w.filePath, Line: int(decl.spec.StartPoint().Row) + 1}
	declaredType := ""
	if decl.spec.Type() == goNodeVarSpec {
		declaredType = nodeFieldText(decl.spec, goFieldType, w.src)
	}
	if b.reassigned {
		if len(b.mayValues) == 0 {
			return nil
		}
		return []SourceNode{{Type: sourceNodeVariable, Name: name, DeclaredType: declaredType, Location: location, MayValues: b.mayValues, MayValuesExhaustive: b.mayExhaustive}}
	}
	if len(b.sources) == 0 {
		return nil
	}
	return []SourceNode{{Type: sourceNodeVariable, Name: name, DeclaredType: declaredType, Location: location, SourceNodes: rustClipSources(b.sources, depth+1)}}
}

// binding computes, once per declared name, what a local holds: its
// initializer resolved where it is declared, or, when the function writes it
// again after the declaration, the string literals it may hold.
func (w *goValueWalk) binding(use *sitter.Node, name string, decl *goDecl, scope *sitter.Node) *goValueBinding {
	cache := &w.p.values
	key := goValueBindingKey{spec: decl.spec.ID(), name: name}
	if b, ok := cache.bindings[key]; ok {
		return b
	}
	b := &goValueBinding{}
	if cache.bindings == nil {
		cache.bindings = make(map[goValueBindingKey]*goValueBinding)
	}
	cache.bindings[key] = b
	// A write is a later write to this local only when it lies after the
	// declaration in the declaring scope; a `:=` in that same scope that
	// lists the name again assigns it rather than declaring a new one.
	writes := cache.writesIn(w.root(use), w.src, name, decl.end, scope.EndByte())
	for _, other := range w.p.consts.index(scope, w.src)[name] {
		if other.kind == goDeclVar && other.end > decl.end {
			writes = append(writes, goValueWrite{node: other.spec, value: other.init})
		}
	}
	if len(writes) == 0 {
		b.sources = w.sources(decl.init, 0)
		return b
	}
	b.reassigned = true
	// A var declared without a value holds its zero value until a write, so
	// what the writes store is never all it may hold.
	exhaustive := decl.init != nil
	add := func(expr *sitter.Node) {
		expr = w.unwrap(expr)
		if expr == nil || expr.Type() != goNodeInterpretedStr && expr.Type() != goNodeRawStr {
			exhaustive = false
			return
		}
		text := expr.Content(w.src)
		for _, seen := range b.mayValues {
			if seen == text {
				return
			}
		}
		b.mayValues = append(b.mayValues, text)
	}
	if decl.init != nil {
		add(decl.init)
	}
	for _, write := range writes {
		add(write.value)
	}
	b.mayExhaustive = exhaustive && len(b.mayValues) > 0
	return b
}

// callSources is the CALL_RESULT of a call, over the values of its receiver
// and its arguments: a value passed to a call reaches its result as far as a
// taint rule reads it.
func (w *goValueWalk) callSources(node *sitter.Node, depth int) []SourceNode {
	callee, ok := w.p.values.calleeAt[rustSpanKey(node)]
	if !ok {
		call := w.p.parseCallTarget(node, w.src, w.filePath, w.analysis, w.receiverType, w.receiverVar, w.varTypes)
		if call == nil {
			return nil
		}
		callee = call.Callee
	}
	result := SourceNode{Type: sourceNodeCallResult, Value: strings.TrimSpace(node.Content(w.src)), CallTarget: &callee, Location: w.location(node)}
	if depth < goValueMaxDepth {
		if fn := goCallFunctionNode(node); fn != nil && fn.Type() == goNodeSelectorExpression {
			result.SourceNodes = append(result.SourceNodes, w.sources(fn.ChildByFieldName(goFieldOperand), depth+1)...)
		}
		for _, arg := range goArgumentNodes(node) {
			result.SourceNodes = append(result.SourceNodes, w.sources(arg, depth+1)...)
		}
	}
	return []SourceNode{result}
}

// goCallFunctionNode is the function a call invokes, through parentheses and
// the type arguments of an explicit instantiation.
func goCallFunctionNode(call *sitter.Node) *sitter.Node {
	fn := call.ChildByFieldName(goFieldFunction)
	for fn != nil && (fn.Type() == goNodeParenExpr || fn.Type() == goNodeIndexExpression) {
		if fn.Type() == goNodeParenExpr {
			fn = fn.NamedChild(0)
		} else {
			fn = fn.ChildByFieldName(goFieldOperand)
		}
	}
	return fn
}

// root is the source_file node holding node.
func (w *goValueWalk) root(node *sitter.Node) *sitter.Node {
	for parent := node.Parent(); parent != nil; parent = node.Parent() {
		node = parent
	}
	return node
}

// writesIn returns the writes to name the file makes within [from, to).
func (c *goValueCache) writesIn(root *sitter.Node, src []byte, name string, from, to uint32) []goValueWrite {
	if !c.scanned {
		c.scanned = true
		c.scanWrites(root, src)
	}
	var out []goValueWrite
	for _, write := range c.writes[name] {
		if write.node.StartByte() >= from && write.node.EndByte() <= to {
			out = append(out, write)
		}
	}
	return out
}

func (c *goValueCache) scanWrites(root *sitter.Node, src []byte) {
	c.writes = make(map[string][]goValueWrite)
	goWalk(root, func(n *sitter.Node) {
		switch n.Type() {
		case goNodeAssignmentStmt:
			left := goListItems(n.ChildByFieldName(goFieldLeft))
			right := goListItems(n.ChildByFieldName(goFieldRight))
			plain := goHasToken(n, "=") && len(left) == len(right)
			for i, target := range left {
				var value *sitter.Node
				if plain {
					value = right[i]
				}
				c.addWrite(src, target, n, value)
			}
		case "inc_statement", "dec_statement":
			c.addWrite(src, n.NamedChild(0), n, nil)
		case goNodeRangeClause, goNodeReceiveStatement:
			if goHasToken(n, "=") {
				for _, target := range goListItems(n.ChildByFieldName(goFieldLeft)) {
					c.addWrite(src, target, n, nil)
				}
			}
		case goNodeUnaryExpression:
			if op := n.Child(0); op != nil && op.Type() == "&" {
				c.addWrite(src, n.ChildByFieldName(goFieldOperand), n, nil)
			}
		}
	})
}

func (c *goValueCache) addWrite(src []byte, target, write *sitter.Node, value *sitter.Node) {
	if target == nil || target.Type() != goNodeIdentifier {
		return
	}
	name := target.Content(src)
	c.writes[name] = append(c.writes[name], goValueWrite{node: write, value: value})
}
