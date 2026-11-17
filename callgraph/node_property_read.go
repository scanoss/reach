// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"sort"

	"github.com/scanoss/reach/callgraph/contracts"
	sitter "github.com/smacker/go-tree-sitter"
)

// NodePropertyRead is one member expression of a JavaScript or TypeScript
// file whose value is read, not called: `acme.enums.hash.md5`,
// `cert.fingerprint256`, `new acme.Cert(p).fingerprint`, `o['key']`. Only
// the outermost member of a chain is listed (`a.b.c`, not `a.b`), and only
// where the chain is read: not as the callee of a call or `new` (`a.b.c()`
// lists nothing), an assignment, compound assignment or update target, a
// `delete` operand, a destructuring target, a computed object key, a JSX tag
// name or a TypeScript type. A chain headed by `this`, `super`, `module` or
// `exports` is not listed.
//
// TargetKey is the key a call of the expression, `<expression>()`, would
// target in the same place: module-qualified for an import
// (`acme-crypto.enums.hash.md5`), the declared class for a typed receiver
// (`acme-crypto.(Cert).fingerprint`), or caller-local when nothing resolves.
// MethodName is the last property, Raw the expression as written. ReceiverVar
// and AssignedVar are set as a call's would be: the local the property is
// read on, and the variable a declaration or assignment binds the value to.
//
// Line and EndLine are 1-based; StartCol and EndCol are 1-based, start
// inclusive, end exclusive, as a call's. EndLine is 0 for a read on one line.
// CallerKey is the key of the function whose body holds the read, the key its
// calls carry; at module level it is the module's `<module>` key.
type NodePropertyRead struct {
	CallerKey   string
	TargetKey   string
	MethodName  string
	Raw         string
	Line        int
	StartCol    int
	EndLine     int
	EndCol      int
	ReceiverVar string
	AssignedVar string
	// CandidateModules are the modules a read on a merged module object may
	// read the member from, as a call's (FunctionCall.CandidateModules).
	CandidateModules []string
}

// nodePropertyReadSite is a read while the graph is built: the call the read
// would be, keyed by the parser and then retyped by the builder's receiver
// passes, never part of any function's calls.
type nodePropertyReadSite struct {
	callerKey string
	// moduleVar reports that the receiver is a module variable the enclosing
	// function does not declare itself, the names a call would add to the
	// function's ModuleVars.
	moduleVar bool
	call      FunctionCall
}

// nodeReadScope is the function whose body extractCalls is walking: reads
// found there are keyed by it.
type nodeReadScope struct {
	callerKey string
	own       map[string]bool
}

// withReadScope runs fn with the reads it finds attributed to callerKey.
func (p *NodeParser) withReadScope(callerKey string, own map[string]bool, fn func()) {
	previous := p.readScope
	p.readScope = &nodeReadScope{callerKey: callerKey, own: own}
	defer func() { p.readScope = previous }()
	fn()
}

// recordNodePropertyRead keys node, when it is a read, through the path a
// call of it takes (resolveNodeMember) and records it with the parser's reads.
func (p *NodeParser) recordNodePropertyRead(node *sitter.Node, src []byte, filePath, packagePath, owner string, imports nodeBindings, locals map[string]bool) {
	if p.readScope == nil {
		return
	}
	object, name, ok := nodeReadMember(node, src)
	if !ok || !isNodeReadPosition(node) || !nodeReadHead(object, src) {
		return
	}
	start, end := node.StartPoint(), node.EndPoint()
	call := &FunctionCall{
		Raw:      node.Content(src),
		FilePath: filePath,
		Line:     int(start.Row) + 1,
		StartCol: int(start.Column) + 1,
		EndCol:   int(end.Column) + 1,
		EndLine:  int(end.Row) + 1,
	}
	call.AssignedVar = assignedVarFromParent(nodeResolvedValue(node), src)
	if p.resolveNodeMember(call, object, name, src, packagePath, owner, imports, locals) == nil {
		return
	}
	site := nodePropertyReadSite{callerKey: p.readScope.callerKey, call: *call}
	if binding, bound := imports[call.ReceiverVar]; bound && binding.module == "" && !p.readScope.own[call.ReceiverVar] {
		site.moduleVar = true
	}
	p.reads = append(p.reads, site)
}

// nodeReadMember splits a member expression, `o.name` or `o['name']`, into
// its object and property name. A computed index other than a plain string
// names no property.
func nodeReadMember(node *sitter.Node, src []byte) (object *sitter.Node, name string, ok bool) {
	switch node.Type() {
	case nodeMemberExpression:
		object, property := node.ChildByFieldName("object"), node.ChildByFieldName("property")
		if object == nil || property == nil {
			return nil, "", false
		}
		return object, property.Content(src), true
	case nodeSubscriptExpression:
		object, index := node.ChildByFieldName("object"), node.ChildByFieldName("index")
		if object == nil || index == nil || index.Type() != "string" {
			return nil, "", false
		}
		name, ok := canonicalNodeStringLiteral(index.Content(src))
		return object, unquoteNodeString(name), ok
	}
	return nil, "", false
}

// isNodeReadPosition reports whether a member expression is the outermost of
// its chain and stands where its value is read.
func isNodeReadPosition(node *sitter.Node) bool {
	parent := node.Parent()
	if parent == nil {
		return true
	}
	switch parent.Type() {
	case nodeMemberExpression, nodeSubscriptExpression:
		if sameSyntaxNode(parent.ChildByFieldName("object"), node) {
			return false
		}
	case nodeCallExpression:
		if sameSyntaxNode(parent.ChildByFieldName("function"), node) {
			return false
		}
	case nodeNewExpression:
		if sameSyntaxNode(parent.ChildByFieldName("constructor"), node) {
			return false
		}
	case nodeAssignmentExpression, "augmented_assignment_expression", nodeAssignmentPattern:
		if sameSyntaxNode(parent.ChildByFieldName("left"), node) {
			return false
		}
	case "for_in_statement":
		if sameSyntaxNode(parent.ChildByFieldName("left"), node) {
			return false
		}
	case "update_expression", "array_pattern", "object_pattern", "pair_pattern", "rest_pattern",
		"computed_property_name", "jsx_opening_element", "jsx_closing_element", "jsx_self_closing_element":
		return false
	case "unary_expression":
		if operator := parent.ChildByFieldName("operator"); operator != nil && operator.Type() == "delete" {
			return false
		}
	}
	return !nodeInTypePosition(parent)
}

// nodeTypePositions are the TypeScript nodes under which an expression names
// a type, not a value.
var nodeTypePositions = map[string]bool{
	"type_annotation": true, "type_query": true, "type_arguments": true, "type_parameters": true,
	"type_alias_declaration": true, "interface_declaration": true, "implements_clause": true,
	"opting_type_annotation": true, "omitting_type_annotation": true, "asserts_annotation": true,
}

// nodeInTypePosition reports whether n is, or sits inside, a TypeScript type.
func nodeInTypePosition(n *sitter.Node) bool {
	for ; n != nil; n = n.Parent() {
		if nodeTypePositions[n.Type()] {
			return true
		}
		if isNodeNestedScope(n.Type()) || n.Type() == "statement_block" {
			return false
		}
	}
	return false
}

// nodeReadHead reports whether the chain object ends in starts at a value a
// read is listed for: a name other than `module` and `exports`, or a call or
// `new` expression. `this`, `super`, `import.meta` and literals start none.
func nodeReadHead(object *sitter.Node, src []byte) bool {
	for {
		switch object.Type() {
		case nodeMemberExpression, nodeSubscriptExpression:
			object = object.ChildByFieldName("object")
			if object == nil {
				return false
			}
		case goNodeIdentifier:
			name := object.Content(src)
			return name != "module" && name != "exports"
		case nodeCallExpression, nodeNewExpression:
			return true
		default:
			return false
		}
	}
}

// takeNodePropertyReads returns the reads collected since the last call, in
// source order, one per expression.
func (p *NodeParser) takeNodePropertyReads() []nodePropertyReadSite {
	reads := p.reads
	p.reads = nil
	sort.SliceStable(reads, func(i, j int) bool {
		a, b := &reads[i].call, &reads[j].call
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.StartCol < b.StartCol
	})
	out := reads[:0]
	for i := range reads {
		if i > 0 && reads[i].call.Line == reads[i-1].call.Line && reads[i].call.StartCol == reads[i-1].call.StartCol &&
			reads[i].call.EndLine == reads[i-1].call.EndLine && reads[i].call.EndCol == reads[i-1].call.EndCol {
			continue
		}
		out = append(out, reads[i])
	}
	return out
}

// finishNodePropertyReads types the reads whose receiver a contracted call
// produced, as resolveNodeAssignedVarCallees types a call on it, and files
// the reads into graph.NodePropertyReads. The calls are final by then, so
// each read sees the variable types the calls before it leave; a read binds
// no type itself, so no call changes.
func finishNodePropertyReads(graph *CallGraph, kb *contracts.KnowledgeBase) {
	if len(graph.nodePropertyReads) == 0 {
		return
	}
	if kb != nil && kb.Ecosystem == ecosystemNode {
		typeNodeReadsByContract(graph, kb)
	}
	graph.NodePropertyReads = make(map[string][]NodePropertyRead)
	for _, site := range graph.nodePropertyReads {
		call := &site.call
		read := NodePropertyRead{
			CallerKey:   site.callerKey,
			TargetKey:   call.Callee.String(),
			MethodName:  call.Callee.Name,
			Raw:         call.Raw,
			Line:        call.Line,
			StartCol:    call.StartCol,
			EndCol:      call.EndCol,
			ReceiverVar: call.ReceiverVar,
			AssignedVar: call.AssignedVar,

			CandidateModules: call.CandidateModules,
		}
		if call.EndLine != call.Line {
			read.EndLine = call.EndLine
		}
		graph.NodePropertyReads[call.FilePath] = append(graph.NodePropertyReads[call.FilePath], read)
	}
	graph.nodePropertyReads = nil
}

// typeNodeReadsByContract gives a read on a variable the KB types the type a
// call on it gets from resolveNodeAssignedVarCallees: the variable types of
// its function, seeded by the module's for a module variable it does not
// declare.
func typeNodeReadsByContract(graph *CallGraph, kb *contracts.KnowledgeBase) {
	receivers := contractReceiverTypes(kb)
	moduleTypes := make(map[string]map[string]string)
	for file, fn := range nodeModuleDecls(graph) {
		moduleTypes[file] = nodeVarTypesBefore(fn, nil, -1, -1, kb, receivers)
	}
	for _, site := range graph.nodePropertyReads {
		call := &site.call
		if call.ReceiverVar == "" || call.Callee.Type != "" {
			continue
		}
		fn := graph.Functions[site.callerKey]
		var seed map[string]string
		if fn != nil && fn.FunctionType != functionTypeModuleInit {
			seed = moduleVariableTypes(fn, moduleTypes[call.FilePath])
			if typ, ok := moduleTypes[call.FilePath][call.ReceiverVar]; ok && site.moduleVar {
				seed[call.ReceiverVar] = typ
			}
		}
		varTypes := nodeVarTypesBefore(fn, seed, call.Line, call.StartCol, kb, receivers)
		if typ, ok := varTypes[call.ReceiverVar]; ok {
			pkg, name := splitQualifiedTypeName(typ)
			call.Callee = FunctionID{Package: pkg, Type: name, Name: call.Callee.Name}
		}
	}
}

// nodeVarTypesBefore replays the variable types fn's calls bind, from seed,
// over the calls that end before line:col (every call for a negative line).
func nodeVarTypesBefore(fn *FunctionDecl, seed map[string]string, line, col int, kb *contracts.KnowledgeBase, receivers map[string]bool) map[string]string {
	varTypes := make(map[string]string, len(seed))
	for name, typ := range seed {
		varTypes[name] = typ
	}
	if fn == nil {
		return varTypes
	}
	for _, i := range assignmentPropagationOrder(fn.Calls) {
		call := &fn.Calls[i]
		if line >= 0 && (call.EndLine > line || call.EndLine == line && call.EndCol > col) {
			continue
		}
		bindNodeAssignedVarType(varTypes, call, kb, receivers)
	}
	return varTypes
}
