// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// nodePromiseMethods are the methods of the promise import() returns, which a
// promise of a module held without `await` answers itself.
var nodePromiseMethods = map[string]bool{"then": true, "catch": true, "finally": true}

// nodeHeldModule is a module binding that a name holds through the file's own
// declarations rather than an import of its own: an alias (`const s =
// sodium`), a destructuring (`const { sm2 } = smCrypto`), a require or
// import() inside a function, or an interop helper applied to a module
// binding. pending marks a promise of the module, an import() not awaited.
type nodeHeldModule struct {
	binding nodeBinding
	pending bool
}

// receiverModuleBinding reads the receiver of a member call, or the callee of
// a call or `new`, as a module binding the file holds: a member chain rooted
// at a name that holds one (nodeHeldModule), or at an inline require
// (`require('m').Gen.create()`). The module-level imports are read before it:
// this resolves only what they do not bind.
func (p *NodeParser) receiverModuleBinding(expr *sitter.Node) (nodeHeldModule, bool) {
	if p.values == nil || expr == nil {
		return nodeHeldModule{}, false
	}
	src := p.values.src
	if binding, ok := nodeRequireBinding(expr, src); ok {
		return nodeHeldModule{binding: p.resolveRelativeBinding(binding)}, true
	}
	root, rest := nodeReceiverChain(unwrapNodeValue(expr), src)
	if root == nil {
		return nodeHeldModule{}, false
	}
	held, ok := p.nameModuleBinding(root, 0)
	if !ok {
		return nodeHeldModule{}, false
	}
	return held.member(rest...), true
}

// nodeReceiverChain splits a receiver as nodeMemberChain does, reading a
// string-literal index as the property it names (`acme['mode'].CTR` is
// acme, [mode CTR]), as a call through it is keyed.
func nodeReceiverChain(node *sitter.Node, src []byte) (*sitter.Node, []string) {
	var rest []string
	for node != nil && (node.Type() == nodeMemberExpression || node.Type() == nodeSubscriptExpression) {
		object, name, ok := nodeReadMember(node, src)
		if !ok || node.Type() == nodeMemberExpression && node.ChildByFieldName("property").Type() != nodePropertyIdentifier {
			return nil, nil
		}
		rest = append([]string{name}, rest...)
		node = unwrapNodeValue(object)
	}
	if node == nil || node.Type() != goNodeIdentifier {
		return nil, nil
	}
	return node, rest
}

// member is the binding of a member path read from held: a promise is no
// longer one once a member of it is read.
func (held nodeHeldModule) member(path ...string) nodeHeldModule {
	if len(path) == 0 {
		return held
	}
	held.binding.member = joinNodeMember(held.binding.member, strings.Join(path, "."))
	held.binding.isDefault = false
	held.pending = false
	return held
}

// resolveRelativeBinding resolves a relative specifier to the project module
// it names, as the file's imports are (resolveNodeRelativeImports).
func (p *NodeParser) resolveRelativeBinding(binding nodeBinding) nodeBinding {
	if p.file == nil {
		return binding
	}
	if resolved, relative := resolveNodeRelativeModule(p.file.filePath, p.file.pkgPath, binding.module); relative {
		binding.module = resolved
	}
	return binding
}

// nameModuleBinding follows the declaration a use of a name reads to the
// module binding it holds. The declaration must hold its initializer at the
// use: never reassigned, and a var read after it ran.
func (p *NodeParser) nameModuleBinding(name *sitter.Node, depth int) (nodeHeldModule, bool) {
	x := p.values
	text := name.Content(x.src)
	d := x.resolve(text, name)
	if d == nil || d.writes != 0 || depth > nodeValueMaxDepth {
		return nodeHeldModule{}, false
	}
	switch {
	case d.hasRequired:
		return nodeHeldModule{binding: p.resolveRelativeBinding(d.required)}, true
	case d.from != nil:
		if d.fromVar && !x.varHoldsAt(d, name) {
			return nodeHeldModule{}, false
		}
		held, ok := p.valueModuleBinding(d.from, depth+1)
		if !ok || held.pending {
			return nodeHeldModule{}, false
		}
		return held.member(d.fromMember), true
	case nodeDeclaredByImport(d.name):
		if p.file == nil {
			return nodeHeldModule{}, false
		}
		binding, ok := p.file.bindings[text]
		return nodeHeldModule{binding: binding}, ok && binding.module != ""
	case x.holdsInitializer(d, name):
		return p.valueModuleBinding(d.value, depth+1)
	}
	return nodeHeldModule{}, false
}

// valueModuleBinding reads an initializer as a module binding: a require
// (nodeRequireBinding), a name or member chain that holds one, an interop
// helper called with one argument that is one, or import() of a module,
// awaited or not, with or without one `.catch(handler)`.
func (p *NodeParser) valueModuleBinding(value *sitter.Node, depth int) (nodeHeldModule, bool) {
	value = unwrapNodeValue(value)
	if value == nil || depth > nodeValueMaxDepth {
		return nodeHeldModule{}, false
	}
	src := p.values.src
	awaited := false
	if value.Type() == "await_expression" && value.NamedChildCount() == 1 {
		value, awaited = unwrapNodeValue(value.NamedChild(0)), true
	}
	if module, ok := nodeDynamicImportModule(value, src); ok {
		return nodeHeldModule{binding: p.resolveRelativeBinding(nodeBinding{module: module}), pending: !awaited}, true
	}
	if awaited {
		return nodeHeldModule{}, false
	}
	if binding, ok := nodeRequireBinding(value, src); ok {
		return nodeHeldModule{binding: p.resolveRelativeBinding(binding)}, true
	}
	switch value.Type() {
	case goNodeIdentifier, nodeMemberExpression:
		root, rest := nodeMemberChain(value, src)
		if root == nil {
			return nodeHeldModule{}, false
		}
		held, ok := p.nameModuleBinding(root, depth)
		if !ok || held.pending {
			return nodeHeldModule{}, false
		}
		return held.member(rest...), true
	case nodeCallExpression:
		function, args := value.ChildByFieldName("function"), nodeArgumentNodes(value)
		if function == nil || len(args) != 1 || !isNodeImportInteropHelper(function, src) {
			return nodeHeldModule{}, false
		}
		held, ok := p.valueModuleBinding(args[0], depth+1)
		if !ok || held.pending {
			return nodeHeldModule{}, false
		}
		return held, true
	}
	return nodeHeldModule{}, false
}

// nodeDynamicImportModule reads `import('m')`, or `import('m').catch(h)` with
// one handler, as the module it loads.
func nodeDynamicImportModule(call *sitter.Node, src []byte) (string, bool) {
	if call.Type() != nodeCallExpression {
		return "", false
	}
	function, args := call.ChildByFieldName("function"), nodeArgumentNodes(call)
	if function == nil || len(args) != 1 {
		return "", false
	}
	switch function.Type() {
	case "import":
		if args[0].Type() != nodeStringNode {
			return "", false
		}
		module := unquoteNodeString(args[0].Content(src))
		return module, module != ""
	case nodeMemberExpression:
		property, object := function.ChildByFieldName("property"), function.ChildByFieldName("object")
		if property == nil || property.Content(src) != "catch" || object == nil {
			return "", false
		}
		object = unwrapNodeValue(object)
		if object == nil || object.Type() != nodeCallExpression {
			return "", false
		}
		if inner := object.ChildByFieldName("function"); inner == nil || inner.Type() != "import" {
			return "", false
		}
		return nodeDynamicImportModule(object, src)
	}
	return "", false
}

// nodeDeclaredByImport reports a name an import statement declares.
func nodeDeclaredByImport(name *sitter.Node) bool {
	for n := name.Parent(); n != nil; n = n.Parent() {
		switch n.Type() {
		case nodeImportStatement:
			return true
		case nodeProgramNode, nodeStatementBlock:
			return false
		}
	}
	return false
}

// varHoldsAt reports whether a var a destructuring declares holds the member
// it read at use, as holdsInitializer reports for a var's initializer: read
// after its declaration ran in the same function, or a module-level var read
// from inside a function.
func (x *nodeValueIndex) varHoldsAt(d *nodeDecl, use *sitter.Node) bool {
	if d.writes != 0 {
		return false
	}
	return x.varInitializedBefore(d, use) || d.fn == nil && nodeEnclosingFunction(use) != nil
}

// holdsInitializer reports whether a variable holds its initializer at use:
// a const or let never reassigned, a var of the use's own function declared
// before it (stable), or a module-level var read from inside a function, which
// runs once the module has loaded.
func (x *nodeValueIndex) holdsInitializer(d *nodeDecl, use *sitter.Node) bool {
	if x.stable(d, use) {
		return true
	}
	return d.kind == nodeDeclVar && d.value != nil && d.writes == 0 && d.fn == nil && nodeEnclosingFunction(use) != nil
}
