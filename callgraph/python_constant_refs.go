// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// Python positions of a constant reference (ConstantRef.Context) beyond the
// ones Java shares (compare, case, return, assign, init, array, arg, other).
const (
	ConstantRefIn   = "in"   // operand of `in` / `not in`, or an element of the container one tests
	ConstantRefDict = "dict" // key or value of a dict display entry
	// ConstantRefTypeCheck: the class tested by isinstance / issubclass, alone
	// or in the tuple of classes (`isinstance(a, (hashes.MD5, hashes.SHA1))`).
	ConstantRefTypeCheck = "type_check"
)

// pythonTypeCheckArg reports whether n is the class argument of a call to
// isinstance or issubclass, or an element of that argument's (nested)
// tuple, looking through parentheses.
func pythonTypeCheckArg(n *sitter.Node, src []byte) bool {
	for {
		parent := n.Parent()
		if parent == nil {
			return false
		}
		switch parent.Type() {
		case "parenthesized_expression", "tuple":
			n = parent
			continue
		case pythonNodeArgumentList:
			call := parent.Parent()
			if call == nil || call.Type() != "call" || parent.NamedChildCount() != 2 ||
				!sameSyntaxNode(parent.NamedChild(1), n) {
				return false
			}
			fn := call.ChildByFieldName("function")
			if fn == nil || fn.Type() != "identifier" {
				return false
			}
			name := fn.Content(src)
			return name == "isinstance" || name == "issubclass"
		}
		return false
	}
}

// pythonFactKind is what a pythonPendingFact records.
type pythonFactKind uint8

const (
	// pythonFactRef is a constant reference: an attribute chain rooted in an
	// import (`ssl.PROTOCOL_TLSv1_1`), a from-imported name used as a value,
	// or a dotted value pattern of a case clause.
	pythonFactRef pythonFactKind = iota
	// pythonFactStore is an assignment to an attribute of an object.
	pythonFactStore
	// pythonFactDeclaration is an annotated assignment.
	pythonFactDeclaration
	// pythonFactCast is a call spelled as typing's cast.
	pythonFactCast
)

// pythonPendingFact is a node of one scope that the fragment records beyond
// its calls, collected in pythonWalk's descent with the binding layer at its
// position and resolved with its scope's calls, once the scope's bindings
// are complete.
type pythonPendingFact struct {
	node  *sitter.Node
	layer *pythonBindingLayer
	kind  pythonFactKind
}

// recordPythonPendingFact attributes a fact to the scope its position runs
// in, as recordPythonPendingCall does a call.
func recordPythonPendingFact(fact pythonPendingFact, fw *pythonFileWalk, activeFunc, activeClassDirect *pythonScope, moduleDirect bool) {
	switch {
	case activeFunc != nil:
		activeFunc.facts = append(activeFunc.facts, fact)
	case activeClassDirect != nil:
		activeClassDirect.facts = append(activeClassDirect.facts, fact)
	case moduleDirect:
		fw.moduleScope.facts = append(fw.moduleScope.facts, fact)
	}
}

// pythonConstantRefCandidate is the reference an identifier the file imports
// starts, or nil: the whole attribute chain it is the root of, when the chain
// is read (not called, not written); the dotted value pattern of a case
// clause it starts; or the identifier itself, when it names a from-imported
// value in a value position. An import later in the file than the use is not
// seen yet (as for notePythonImportUse).
func pythonConstantRefCandidate(node *sitter.Node, src []byte, analysis *FileAnalysis) *sitter.Node {
	name := node.Content(src)
	if _, imported := analysis.Imports[name]; !imported {
		return nil
	}
	parent := node.Parent()
	if parent == nil {
		return nil
	}
	switch parent.Symbol() {
	case pythonSyms.attribute:
		if !sameSyntaxNode(parent.ChildByFieldName("object"), node) {
			return nil
		}
		top := parent
		for up := top.Parent(); up != nil && up.Symbol() == pythonSyms.attribute && sameSyntaxNode(up.ChildByFieldName("object"), top); up = top.Parent() {
			top = up
		}
		if up := top.Parent(); up != nil && up.Symbol() == pythonSyms.call && sameSyntaxNode(up.ChildByFieldName("function"), top) {
			return nil
		}
		if pythonWriteTarget(top) {
			return nil
		}
		return top
	case pythonSyms.dottedName:
		if parent.NamedChildCount() < 2 || !sameSyntaxNode(parent.NamedChild(0), node) || pythonCaseClauseOf(parent) == nil {
			return nil
		}
		return parent
	}
	if !analysis.FromImports[name] || !pythonValuePosition(node, parent) {
		return nil
	}
	return node
}

// pythonValuePosition reports a bare name read as a value where a constant
// can stand: an argument, a returned value, a comparison operand, a
// collection element or dict entry, the right side of an assignment, a
// branch of a conditional, or inside parentheses.
func pythonValuePosition(node, parent *sitter.Node) bool {
	switch parent.Type() {
	case pythonNodeArgumentList, "return_statement", "comparison_operator", "list", "tuple", "set", "expression_list",
		"conditional_expression", "parenthesized_expression", "pair":
		return true
	case pythonKeywordArgument:
		return sameSyntaxNode(parent.ChildByFieldName("value"), node)
	case "assignment", "augmented_assignment":
		return sameSyntaxNode(parent.ChildByFieldName("right"), node)
	}
	return false
}

// pythonCaseClauseOf is the case clause whose pattern holds n, or nil.
func pythonCaseClauseOf(n *sitter.Node) *sitter.Node {
	for up := n.Parent(); up != nil; up = up.Parent() {
		switch up.Type() {
		case "case_clause":
			return up
		case "case_pattern", "union_pattern", "class_pattern", "as_pattern", "keyword_pattern", "list_pattern",
			"tuple_pattern", "dict_pattern", "splat_pattern":
			continue
		}
		return nil
	}
	return nil
}

// resolvePythonConstantRefs turns a scope's reference facts into the
// references of the function that scope builds. definitions marks a module
// or class body, whose assignments define names (init), where a function's
// rebind them (assign). A root a binding of the scope shadows is no import,
// except at module level, where a fallback binding (`except ImportError:
// ssl = None`) leaves the import the name the code was written against. A
// reference in a decorator, a type annotation or a class's bases is left out.
func (p *PythonParser) resolvePythonConstantRefs(scope *pythonScope, attrs map[string]bool, src []byte, filePath string, analysis *FileAnalysis, fw *pythonFileWalk, definitions bool) []ConstantRef {
	if scope == nil {
		return nil
	}
	var refs []ConstantRef
	for _, fact := range scope.facts {
		if fact.kind != pythonFactRef {
			continue
		}
		n := fact.node
		root := n
		for root.Symbol() == pythonSyms.attribute {
			root = root.ChildByFieldName("object")
		}
		if root.Symbol() == pythonSyms.dottedName {
			root = root.NamedChild(0)
		}
		name := root.Content(src)
		if fact.layer != fw.moduleScope.locals && fact.layer.has(name) {
			continue
		}
		if pythonInAnnotationOrDecorator(n) {
			continue
		}
		text := strings.Join(strings.Fields(n.Content(src)), "")
		if n.Symbol() == pythonSyms.identifier {
			text = analysis.Imports[name] + "." + pythonImportedName(analysis, name)
		}
		start, end := n.StartPoint(), n.EndPoint()
		ref := ConstantRef{
			Text: text, Line: int(start.Row) + 1, StartCol: int(start.Column) + 1, EndCol: int(end.Column) + 1,
		}
		if end.Row != start.Row {
			ref.EndLine = int(end.Row) + 1
		}
		var operand *sitter.Node
		ref.Context, operand = pythonConstantRefContext(n, src, definitions)
		if operand != nil {
			bindings := pythonBindings{
				layer: fact.layer, attrs: attrs, staticMethod: scope.staticMethod, selfAlias: scope.selfAlias,
				bases: scope.bases, className: scope.className, varTypes: scope.varTypes, locals: &scope.sources,
				classNames: fw.classNames,
			}
			sources := p.pythonArgumentSourceFor(operand, src, filePath, analysis, bindings, fw, 0)
			if len(sources) == 0 {
				// A field of the object: the constants its class assigns it.
				sources = pythonComparedFieldWrites(operand, src, analysis, bindings, fw)
			}
			ref.Operand = &ComparedOperand{Text: strings.TrimSpace(operand.Content(src)), Sources: sources}
		}
		refs = append(refs, ref)
	}
	return refs
}

// pythonInAnnotationOrDecorator reports a node inside a type annotation, a
// decorator or a class statement's bases, up to its statement.
func pythonInAnnotationOrDecorator(n *sitter.Node) bool {
	for up := n.Parent(); up != nil; up = up.Parent() {
		switch up.Symbol() {
		case pythonSyms.typeNode, pythonSyms.decorator:
			return true
		case pythonSyms.argumentList:
			if class := up.Parent(); class != nil && class.Symbol() == pythonSyms.classDefinition {
				return true
			}
		case pythonSyms.block, pythonSyms.expressionStatement, pythonSyms.functionDefinition, pythonSyms.classDefinition:
			return false
		}
	}
	return false
}

// pythonConstantRefContext classifies where the reference n stands, looking
// through parentheses and the branches of a conditional, and returns the
// operand it is compared with (compare, in, case) or the key of its dict
// entry (dict), when there is one.
func pythonConstantRefContext(n *sitter.Node, src []byte, definitions bool) (string, *sitter.Node) {
	if pythonTypeCheckArg(n, src) {
		return ConstantRefTypeCheck, nil
	}
	if n.Symbol() == pythonSyms.dottedName {
		if clause := pythonCaseClauseOf(n); clause != nil {
			return ConstantRefCase, pythonMatchSubject(clause)
		}
		return ConstantRefOther, nil
	}
	for {
		parent := n.Parent()
		if parent == nil {
			return ConstantRefOther, nil
		}
		switch parent.Type() {
		case "parenthesized_expression":
			n = parent
			continue
		case "conditional_expression":
			// a if <condition> else b
			if parent.NamedChildCount() == 3 && sameSyntaxNode(parent.NamedChild(1), n) {
				return ConstantRefOther, nil
			}
			n = parent
			continue
		case "comparison_operator":
			return pythonComparisonContext(parent, n, src)
		case "return_statement":
			return ConstantRefReturn, nil
		case "assignment":
			if !sameSyntaxNode(parent.ChildByFieldName("right"), n) {
				return ConstantRefOther, nil
			}
			if definitions || parent.ChildByFieldName("type") != nil {
				return ConstantRefInit, nil
			}
			return ConstantRefAssign, nil
		case "augmented_assignment":
			if sameSyntaxNode(parent.ChildByFieldName("right"), n) {
				return ConstantRefAssign, nil
			}
			return ConstantRefOther, nil
		case "list", "tuple", "set", "expression_list":
			if outer := parent.Parent(); outer != nil && outer.Type() == "comparison_operator" {
				if context, operand := pythonComparisonContext(outer, parent, src); context == ConstantRefIn {
					return context, operand
				}
			}
			return ConstantRefArray, nil
		case "pair":
			if sameSyntaxNode(parent.ChildByFieldName("value"), n) {
				return ConstantRefDict, parent.ChildByFieldName("key")
			}
			return ConstantRefDict, nil
		case pythonNodeArgumentList:
			return ConstantRefArg, nil
		case pythonKeywordArgument:
			if sameSyntaxNode(parent.ChildByFieldName("value"), n) {
				return ConstantRefArg, nil
			}
			return ConstantRefOther, nil
		}
		return ConstantRefOther, nil
	}
}

// pythonComparisonContext is the context of operand n of comparison cmp and
// what it is compared with: the next operand when the operator after n is an
// equality or a membership test, else the previous one when the operator
// before n is. `a < X` and the like are other.
func pythonComparisonContext(cmp, n *sitter.Node, src []byte) (string, *sitter.Node) {
	var operands []*sitter.Node
	var operators []string // operators[i] stands between operands[i] and operands[i+1]
	index := -1
	pending := ""
	for i := 0; i < int(cmp.ChildCount()); i++ {
		child := cmp.Child(i)
		if !child.IsNamed() {
			pending = strings.TrimSpace(pending + " " + child.Content(src))
			continue
		}
		if child.Type() == pythonNodeComment {
			continue
		}
		if len(operands) > 0 {
			operators = append(operators, strings.Join(strings.Fields(pending), " "))
		}
		pending = ""
		if sameSyntaxNode(child, n) {
			index = len(operands)
		}
		operands = append(operands, child)
	}
	if index < 0 {
		return ConstantRefOther, nil
	}
	if index < len(operators) {
		if context := pythonComparisonKind(operators[index]); context != "" {
			return context, operands[index+1]
		}
	}
	if index > 0 {
		if context := pythonComparisonKind(operators[index-1]); context != "" {
			return context, operands[index-1]
		}
	}
	return ConstantRefOther, nil
}

// pythonComparisonKind is the context an operator puts its operands in:
// compare for an equality or identity test, in for a membership test, ""
// for an ordering.
func pythonComparisonKind(operator string) string {
	switch operator {
	case "==", "!=", "is", "is not":
		return ConstantRefCompare
	case "in", "not in":
		return ConstantRefIn
	}
	return ""
}

// pythonMatchSubject is the subject of the match statement a case clause
// belongs to.
func pythonMatchSubject(clause *sitter.Node) *sitter.Node {
	for up := clause.Parent(); up != nil; up = up.Parent() {
		if up.Type() == "match_statement" {
			return up.ChildByFieldName("subject")
		}
	}
	return nil
}
