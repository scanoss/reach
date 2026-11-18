// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// WebCrypto is a runtime API, not a module: browsers and Node expose it as the
// global `crypto`, and Node also as `require('crypto').webcrypto` and, for
// `subtle` and `getRandomValues`, on the crypto module itself. Every spelling
// names one of two WebIDL interfaces, and calls on them are recorded against
// the interface (`SubtleCrypto.encrypt`, `Crypto.getRandomValues`) so rules
// and contracts key on one name whatever the spelling.
const (
	nodeSubtleCryptoType = "SubtleCrypto"
	nodeCryptoType       = "Crypto"
	// nodeCryptoGlobalName is the global object's name, and the Node module's.
	nodeCryptoGlobalName = "crypto"
	// webCryptoGlobalRoute and webCryptoModuleRoute head the route a receiver
	// takes to WebCrypto: the global crypto object or the Node crypto module.
	webCryptoGlobalRoute = "global"
	webCryptoModuleRoute = "module"
	// webCryptoGlobalObjectRoute is the global object itself (globalThis,
	// window, self, global), which only its crypto property leads on from.
	webCryptoGlobalObjectRoute = "globalObject"
)

// nodeGlobalObjects are the names a script reaches the global object through.
var nodeGlobalObjects = map[string]bool{"globalThis": true, "window": true, "self": true, webCryptoGlobalRoute: true}

// nodeGlobalCryptoProperties are the properties of the global object that hold
// the Crypto object: crypto, and msCrypto, its vendor-prefixed name in old
// Internet Explorer.
var nodeGlobalCryptoProperties = map[string]bool{nodeCryptoGlobalName: true, "msCrypto": true}

// nodeCryptoMethods are the Crypto methods. On the Node crypto module only
// getRandomValues is the WebCrypto one: randomUUID there is the module's own.
var nodeCryptoMethods = map[string]bool{"getRandomValues": true, "randomUUID": true}

// webCryptoScope says how a receiver's root name is bound: through an import,
// or as a declaration of the code being parsed.
type webCryptoScope struct {
	bound    func(name string) (nodeBinding, bool)
	declared func(name string) bool
	// held, when set, reads a name the code declares as the route its
	// declaration holds at the use (`const { crypto } = globalThis`, `const
	// c = nodeCrypto.webcrypto`); declared is false when the name has no
	// declaration of the file's own, and bound and declared then decide.
	held func(name *sitter.Node) (path string, ok, declared bool)
}

// nodeWebCryptoInterface returns the WebCrypto interface an expression
// evaluates to: SubtleCrypto for `crypto.subtle` and its spellings, Crypto
// for the crypto object.
func nodeWebCryptoInterface(expr *sitter.Node, src []byte, scope webCryptoScope) (string, bool) {
	path, ok := nodeWebCryptoPath(expr, src, scope)
	if !ok {
		return "", false
	}
	switch path {
	case webCryptoGlobalRoute, "global.webcrypto", "module.webcrypto":
		return nodeCryptoType, true
	case "global.subtle", "module.subtle", "module.webcrypto.subtle":
		return nodeSubtleCryptoType, true
	}
	return "", false
}

// nodeWebCryptoCallInterface returns the interface a call `<object>.<method>(..)`
// is made on, when it is a WebCrypto call.
func nodeWebCryptoCallInterface(object *sitter.Node, src []byte, method string, scope webCryptoScope) (string, bool) {
	if iface, ok := nodeWebCryptoInterface(object, src, scope); ok {
		if iface == nodeCryptoType && !nodeCryptoMethods[method] {
			return "", false
		}
		return iface, true
	}
	if path, ok := nodeWebCryptoPath(object, src, scope); ok && path == webCryptoModuleRoute && method == "getRandomValues" {
		return nodeCryptoType, true
	}
	return "", false
}

// nodeWebCryptoPath spells a receiver as the route it takes to WebCrypto:
// "global" for the global crypto object, "module" for the Node crypto module,
// each followed by the properties read from it.
func nodeWebCryptoPath(expr *sitter.Node, src []byte, scope webCryptoScope) (string, bool) {
	if expr == nil {
		return "", false
	}
	switch expr.Type() {
	case goNodeIdentifier:
		if scope.held != nil {
			if path, ok, declared := scope.held(expr); declared {
				return path, ok
			}
		}
		return nodeWebCryptoRoot(expr.Content(src), scope)
	case nodeMemberExpression:
		return nodeWebCryptoMemberPath(expr, src, scope)
	}
	return "", false
}

// nodeWebCryptoValuePath spells the value a declaration holds as a route:
// the expression itself, or a conditional whose every branch is one route
// or empty (`'crypto' in globalThis ? globalThis.crypto : undefined`,
// `typeof window !== 'undefined' ? window : {}`), or a
// `||` / `??` whose every operand is one route (`g.crypto || g.msCrypto`).
func nodeWebCryptoValuePath(expr *sitter.Node, src []byte, scope webCryptoScope) (string, bool) {
	expr = unwrapNodeValue(expr)
	if expr == nil {
		return "", false
	}
	var branches []*sitter.Node
	switch expr.Type() {
	case "ternary_expression":
		branches = []*sitter.Node{expr.ChildByFieldName("consequence"), expr.ChildByFieldName("alternative")}
	case "binary_expression":
		switch op := expr.ChildByFieldName("operator"); {
		case op == nil:
			return "", false
		case op.Type() == "||" || op.Type() == "??":
			branches = []*sitter.Node{expr.ChildByFieldName("left"), expr.ChildByFieldName("right")}
		default:
			return "", false
		}
	default:
		return nodeWebCryptoPath(expr, src, scope)
	}
	route := ""
	for _, branch := range branches {
		branch = unwrapNodeValue(branch)
		if branch == nil {
			return "", false
		}
		if nodeIsEmptyValue(branch, src) {
			continue
		}
		path, ok := nodeWebCryptoValuePath(branch, src, scope)
		if !ok || route != "" && path != route {
			return "", false
		}
		route = path
	}
	return route, route != ""
}

// nodeIsEmptyValue reports a fallback that holds no route and no property:
// null, undefined and the empty object literal.
func nodeIsEmptyValue(expr *sitter.Node, src []byte) bool {
	switch expr.Type() {
	case "null", "undefined":
		return true
	case goNodeIdentifier:
		return expr.Content(src) == "undefined"
	case nodeObjectLiteral:
		return expr.NamedChildCount() == 0
	}
	return false
}

// nodeWebCryptoRoot spells a bare name: an import of the Node crypto module
// or one of its members, or the global crypto object when nothing in scope
// declares the name.
func nodeWebCryptoRoot(name string, scope webCryptoScope) (string, bool) {
	if binding, ok := scope.bound(name); ok {
		if !nodeIsCryptoModule(binding.module) || binding.isDefault && binding.member != "" {
			return "", false
		}
		if binding.member == "" || binding.member == nodeDefaultKeyword {
			return webCryptoModuleRoute, true
		}
		return webCryptoModuleRoute + "." + binding.member, true
	}
	if scope.declared(name) {
		return "", false
	}
	if name == nodeCryptoGlobalName {
		return webCryptoGlobalRoute, true
	}
	if nodeGlobalObjects[name] {
		return webCryptoGlobalObjectRoute, true
	}
	return "", false
}

// nodeWebCryptoMemberPath spells `<object>.<property>`: the global crypto
// object read off globalThis, window, self or global, a member of an inline
// require('crypto'), or a property read from a WebCrypto route.
func nodeWebCryptoMemberPath(expr *sitter.Node, src []byte, scope webCryptoScope) (string, bool) {
	object := expr.ChildByFieldName("object")
	property := expr.ChildByFieldName("property")
	if object == nil || property == nil {
		return "", false
	}
	name := property.Content(src)
	if object.Type() == nodeCallExpression {
		binding, ok := nodeRequireBinding(object, src)
		if !ok || binding.member != "" || !nodeIsCryptoModule(binding.module) {
			return "", false
		}
		return webCryptoModuleRoute + "." + name, true
	}
	base, ok := nodeWebCryptoPath(object, src, scope)
	if !ok {
		return "", false
	}
	return nodeWebCryptoMember(base, name)
}

// nodeWebCryptoMember is the route of a property read from the route base:
// the global object leads on only to the Crypto object.
func nodeWebCryptoMember(base, name string) (string, bool) {
	if base != webCryptoGlobalObjectRoute {
		return base + "." + name, true
	}
	if nodeGlobalCryptoProperties[name] {
		return webCryptoGlobalRoute, true
	}
	return "", false
}

func nodeIsCryptoModule(module string) bool {
	return module == nodeCryptoGlobalName || module == "node:crypto"
}

// webCryptoScope is the scope resolveNodeMember reads a receiver in, with the
// file's own declarations followed to the WebCrypto route they hold.
func (p *NodeParser) webCryptoScope(imports nodeBindings, locals map[string]bool) webCryptoScope {
	scope := imports.webCryptoScope(locals)
	scope.held = func(name *sitter.Node) (string, bool, bool) { return p.webCryptoHeld(imports, name, 0) }
	return scope
}

// webCryptoHeld reads a name as the WebCrypto route its declaration holds at
// the use: a const, let or var holding its initializer (nodeWebCryptoValuePath),
// or a name destructured from a route (`const { crypto } = globalThis`,
// `const { webcrypto } = nodeCrypto`). declared is false for a name with no
// declaration of the file's own, an import or a require included, which the
// scope's bindings resolve instead.
func (p *NodeParser) webCryptoHeld(imports nodeBindings, name *sitter.Node, depth int) (path string, ok, declared bool) {
	x := p.values
	if x == nil {
		return "", false, false
	}
	d := x.resolve(name.Content(x.src), name)
	if d == nil || d.hasRequired || d.kind == nodeDeclImport || nodeDeclaredByImport(d.name) {
		return "", false, false
	}
	if d.writes != 0 || depth >= nodeValueMaxDepth {
		return "", false, true
	}
	scope := webCryptoScope{
		bound:    func(name string) (nodeBinding, bool) { return imports.lookup(nil, name) },
		declared: func(string) bool { return false },
		held: func(name *sitter.Node) (string, bool, bool) {
			return p.webCryptoHeld(imports, name, depth+1)
		},
	}
	switch {
	case d.from != nil:
		if d.fromVar && !x.varHoldsAt(d, name) {
			return "", false, true
		}
		base, ok := nodeWebCryptoValuePath(d.from, x.src, scope)
		if !ok {
			return "", false, true
		}
		path, ok = nodeWebCryptoMember(base, d.fromMember)
		return path, ok, true
	case x.holdsInitializer(d, name):
		if p.callsGlobalObjectGetter(d.value) {
			return webCryptoGlobalObjectRoute, true, true
		}
		path, ok = nodeWebCryptoValuePath(d.value, x.src, scope)
		return path, ok, true
	}
	return "", false, true
}

// callsGlobalObjectGetter reports `getGlobal()`, a call with no arguments of a
// function the file declares once and never reassigns, every return of which
// is a global object name nothing declares (`return self;`, `return window;`):
// the shim libraries write to find the global object on any platform.
func (p *NodeParser) callsGlobalObjectGetter(value *sitter.Node) bool {
	x := p.values
	value = unwrapNodeValue(value)
	if value == nil || value.Type() != nodeCallExpression || len(nodeArgumentNodes(value)) != 0 {
		return false
	}
	callee := value.ChildByFieldName("function")
	if callee == nil || callee.Type() != goNodeIdentifier {
		return false
	}
	d := x.resolve(callee.Content(x.src), callee)
	if d == nil || d.writes != 0 || d.name.Parent() == nil || d.name.Parent().Type() != nodeFunctionDeclaration {
		return false
	}
	body := d.name.Parent().ChildByFieldName("body")
	returns := 0
	var walk func(n *sitter.Node) bool
	walk = func(n *sitter.Node) bool {
		if isNodeFunctionLike(n.Type()) {
			return true
		}
		if n.Type() == nodeReturnStatement {
			returns++
			if n.NamedChildCount() != 1 {
				return false
			}
			returned := unwrapNodeValue(n.NamedChild(0))
			return returned != nil && returned.Type() == goNodeIdentifier && nodeGlobalObjects[returned.Content(x.src)] && x.resolve(returned.Content(x.src), returned) == nil
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			if !walk(n.NamedChild(i)) {
				return false
			}
		}
		return true
	}
	return body != nil && walk(body) && returns > 0
}
