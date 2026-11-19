// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// node_export_getters.go reads the exports a compiler writes as property
// definitions instead of assignments. tsc re-exports a binding through a
// getter, and esbuild (tsup, Rollup's CommonJS interop) collects every export
// of a bundle in one object of getters:
//
//	Object.defineProperty(exports, "importJWK", { enumerable: true, get: function () { return import_js_1.importJWK; } });
//
//	var index_exports = {};
//	__export(index_exports, { rateLimit: () => rate_limit_default, default: () => index_default });
//	module.exports = __toCommonJS(index_exports);
//
// Read as written, neither names a value: the first is a call, the second an
// object no assignment fills. A module built this way then exported nothing a
// caller's call could join, which is every entry module of a package compiled
// from TypeScript to CommonJS.

// nodeToCommonJSHelper is the helper esbuild wraps a bundle's export object
// in for module.exports.
const nodeToCommonJSHelper = "__toCommonJS"

// nodeGetterExports returns, for each export of the module a property
// definition declares, the expression its getter returns (or its `value`),
// with the statement that declares it.
func nodeGetterExports(statements []*sitter.Node, src []byte) (values, sites map[string]*sitter.Node) {
	values, sites = make(map[string]*sitter.Node), make(map[string]*sitter.Node)
	bundles := nodeBundleExportObjects(statements, src)
	nodeDefinedProperties(statements, src, func(target, name string, value, site *sitter.Node) {
		if !isNodeExportsObject(target) && !bundles[target] {
			return
		}
		if _, seen := values[name]; !seen {
			values[name], sites[name] = value, site
		}
	})
	return values, sites
}

// nodeDefinedProperties calls visit for each property the module's top-level
// statements define on a named object with a property definition:
// `Object.defineProperty(target, "name", { get })` and esbuild's
// `__export(target, { name: () => value })`. value is what the property
// reads.
func nodeDefinedProperties(statements []*sitter.Node, src []byte, visit func(target, name string, value, site *sitter.Node)) {
	for _, stmt := range statements {
		if stmt.Type() != nodeExpressionStatement || stmt.NamedChildCount() == 0 {
			continue
		}
		call := stmt.NamedChild(0)
		if call.Type() != nodeCallExpression {
			continue
		}
		fn, args := call.ChildByFieldName("function"), call.ChildByFieldName("arguments")
		if fn == nil || args == nil || args.NamedChildCount() < 2 {
			continue
		}
		target := args.NamedChild(0).Content(src)
		switch {
		case fn.Content(src) == nodeObjectDefineProperty && args.NamedChildCount() >= 3 && args.NamedChild(1).Type() == nodeStringNode:
			if value := nodeDescriptorValue(args.NamedChild(2), src); value != nil {
				visit(target, unquoteNodeString(args.NamedChild(1).Content(src)), value, call)
			}
		case fn.Type() == goNodeIdentifier && strings.HasPrefix(fn.Content(src), "__export") && args.NamedChild(1).Type() == nodeObjectLiteral:
			nodeEachNamedChild(args.NamedChild(1), func(member *sitter.Node) {
				if member.Type() != nodePair {
					return
				}
				key, value := member.ChildByFieldName(nodeFieldKey), nodeGetterResult(member.ChildByFieldName("value"))
				if key != nil && key.Type() != "computed_property_name" && value != nil {
					visit(target, unquoteNodeString(key.Content(src)), value, member)
				}
			})
		}
	}
}

// nodeBundleExportObjects names the objects a module passes to __toCommonJS
// for module.exports: the export object of a bundle.
func nodeBundleExportObjects(statements []*sitter.Node, src []byte) map[string]bool {
	var out map[string]bool
	for _, stmt := range statements {
		if stmt.Type() != nodeExpressionStatement || stmt.NamedChildCount() == 0 {
			continue
		}
		if object := nodeToCommonJSObject(stmt.NamedChild(0), src); object != "" {
			if out == nil {
				out = make(map[string]bool)
			}
			out[object] = true
		}
	}
	return out
}

// nodeToCommonJSObject returns the object of `module.exports =
// __toCommonJS(object)`, "" for any other expression.
func nodeToCommonJSObject(expr *sitter.Node, src []byte) string {
	if expr == nil || expr.Type() != nodeAssignmentExpression {
		return ""
	}
	left, right := expr.ChildByFieldName("left"), expr.ChildByFieldName("right")
	if left == nil || right == nil || left.Content(src) != nodeModuleExportsTarget || right.Type() != nodeCallExpression {
		return ""
	}
	fn, args := right.ChildByFieldName("function"), right.ChildByFieldName("arguments")
	if fn == nil || args == nil || fn.Content(src) != nodeToCommonJSHelper || args.NamedChildCount() != 1 || args.NamedChild(0).Type() != goNodeIdentifier {
		return ""
	}
	return args.NamedChild(0).Content(src)
}

// nodeDescriptorValue is what a property descriptor makes the property
// read: its `value`, or what its `get` returns.
func nodeDescriptorValue(descriptor *sitter.Node, src []byte) *sitter.Node {
	if descriptor == nil || descriptor.Type() != nodeObjectLiteral {
		return nil
	}
	var value *sitter.Node
	nodeEachNamedChild(descriptor, func(member *sitter.Node) {
		if value != nil {
			return
		}
		switch member.Type() {
		case nodePair:
			key := member.ChildByFieldName(nodeFieldKey)
			if key == nil {
				return
			}
			switch unquoteNodeString(key.Content(src)) {
			case "value":
				value = member.ChildByFieldName("value")
			case "get":
				value = nodeGetterResult(member.ChildByFieldName("value"))
			}
		case nodeMethodDefinition:
			if name := member.ChildByFieldName(nodeFieldName); name != nil && name.Content(src) == "get" {
				value = nodeGetterResult(member)
			}
		}
	})
	return value
}

// nodeGetterResult is the expression a getter with a single return yields:
// `() => x`, `function () { return x; }`.
func nodeGetterResult(getter *sitter.Node) *sitter.Node {
	if getter == nil {
		return nil
	}
	switch getter.Type() {
	case nodeArrowFunction, nodeFunctionExpression, nodeMethodDefinition:
	default:
		return nil
	}
	body := getter.ChildByFieldName("body")
	if body == nil {
		return nil
	}
	if body.Type() != nodeStatementBlock {
		return body
	}
	if body.NamedChildCount() != 1 || body.NamedChild(0).Type() != goNodeReturnStatement || body.NamedChild(0).NamedChildCount() != 1 {
		return nil
	}
	return body.NamedChild(0).NamedChild(0)
}

// getters indexes the module's property-defined exports on first use.
func (m *nodeShapeModule) getters() map[string]*sitter.Node {
	if m.getterValues == nil {
		m.getterValues, _ = nodeGetterExports(m.topLevel(), m.src)
	}
	return m.getterValues
}

// definedMembers indexes, by the name of the object, the members the module
// defines on it with property definitions: the namespaces of a bundle
// (`var nip59_exports = {}; __export(nip59_exports, { wrapEvent: () =>
// wrapEvent })`).
func (m *nodeShapeModule) definedMembers() map[string]map[string]*sitter.Node {
	if m.defined == nil {
		m.defined = make(map[string]map[string]*sitter.Node)
		nodeDefinedProperties(m.topLevel(), m.src, func(target, name string, value, _ *sitter.Node) {
			members := m.defined[target]
			if members == nil {
				members = make(map[string]*sitter.Node)
				m.defined[target] = members
			}
			if _, seen := members[name]; !seen {
				members[name] = value
			}
		})
	}
	return m.defined
}
