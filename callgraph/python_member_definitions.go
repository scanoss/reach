// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import sitter "github.com/smacker/go-tree-sitter"

// pythonDefinitionBlocks are the compound statements whose bodies run in the
// scope that holds them. A def or class inside one is a member of that scope,
// like a direct statement: `if has_crypto: class RSAAlgorithm(...)` defines
// the module's RSAAlgorithm, and `try: def f(): ... except ImportError: def
// f(): ...` the module's f.
var pythonDefinitionBlocks = map[string]bool{
	"block":               true,
	"if_statement":        true,
	"elif_clause":         true,
	"else_clause":         true,
	"try_statement":       true,
	"except_clause":       true,
	"except_group_clause": true,
	"finally_clause":      true,
	"with_statement":      true,
}

// forEachPythonMemberDefinition calls visit with each function, class and
// decorated definition that is a member of the scope whose body is node (a
// module or a class body): its direct statements and those inside if / try /
// with blocks, in source order. Function and class bodies are not entered.
func forEachPythonMemberDefinition(node *sitter.Node, visit func(*sitter.Node)) {
	count := int(node.NamedChildCount())
	for i := 0; i < count; i++ {
		child := node.NamedChild(i)
		switch kind := child.Type(); {
		case kind == pythonNodeFunctionDefinition || kind == pythonNodeClassDefinition || kind == pythonDecoratedDefinition:
			visit(child)
		case pythonDefinitionBlocks[kind]:
			forEachPythonMemberDefinition(child, visit)
		}
	}
}
