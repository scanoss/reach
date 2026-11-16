// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// pythonBuiltinClassNames are the builtin classes whose instances a program
// annotates and calls methods on. A builtin function (len, open) or an
// exception is never an annotation's class here.
var pythonBuiltinClassNames = map[string]bool{
	"bool": true, "bytearray": true, "bytes": true, "complex": true, "dict": true, "float": true,
	"frozenset": true, "int": true, "list": true, "memoryview": true, "set": true, "str": true, "tuple": true,
}

// pythonAnnotationModules are the modules whose names are typing constructs
// (Any, Callable, Mapping, TypeVar, aliases), never a class whose methods a
// call reaches.
var pythonAnnotationModules = []string{"typing", "typing_extensions", "collections.abc"}

// pythonClassRef is a class an annotation names: the module that declares it
// and its name in that module (`Outer.Inner` for a nested class), the
// Package and Type its methods are keyed by.
type pythonClassRef struct {
	pkg, typ string
}

func (r pythonClassRef) fqn() string { return r.pkg + "." + r.typ }

// pythonAnnotationClass resolves the class a normalized annotation names
// (pythonNormalizeAnnotation: `Signer`, `hashes.Hash`, `Outer.Inner`), the
// way Python looks the name up where the annotation is written:
//
//   - a class of the enclosing class bodies (outer), then of the module
//     (declared holds the file's classes, `Outer.Inner` for nested ones);
//   - an import: `from m import C` gives m.C, `import a.b` then `a.b.C` gives
//     a.b.C, `import m as x` then `x.C` gives m.C;
//   - a builtin class: builtins.bytes.
//
// Anything else names no class: a module global bound some other way (a type
// alias, a TypeVar, a star import), a typing construct, a dotted name whose
// head is not imported. ok is false then, and nothing is typed.
func pythonAnnotationClass(name, outer, modulePath string, declared map[string]bool, analysis *FileAnalysis) (pythonClassRef, bool) {
	if !pythonDottedIdentifier(name) {
		return pythonClassRef{}, false
	}
	for scope := outer; scope != ""; {
		if declared[scope+"."+name] {
			return pythonClassRef{pkg: modulePath, typ: scope + "." + name}, true
		}
		cut := strings.LastIndex(scope, ".")
		if cut < 0 {
			break
		}
		scope = scope[:cut]
	}
	if declared[name] {
		return pythonClassRef{pkg: modulePath, typ: name}, true
	}
	head, rest, dotted := strings.Cut(name, ".")
	if module, ok := analysis.Imports[head]; ok {
		qualified := module
		if analysis.FromImports[head] {
			qualified = module + "." + pythonImportedName(analysis, head)
		}
		if dotted {
			qualified += "." + rest
		}
		cut := strings.LastIndex(qualified, ".")
		if cut <= 0 || pythonTypingName(qualified) {
			return pythonClassRef{}, false
		}
		return pythonClassRef{pkg: qualified[:cut], typ: qualified[cut+1:]}, true
	}
	if !dotted && pythonBuiltinClassNames[name] {
		return pythonClassRef{pkg: pythonBuiltinsModule, typ: name}, true
	}
	return pythonClassRef{}, false
}

func pythonTypingName(qualified string) bool {
	for _, module := range pythonAnnotationModules {
		if strings.HasPrefix(qualified, module+".") {
			return true
		}
	}
	return false
}

func pythonDottedIdentifier(name string) bool {
	for _, part := range strings.Split(name, ".") {
		if !isPythonIdentifier(part) {
			return false
		}
	}
	return name != ""
}

// pythonFileClassNames lists the classes a file declares, the way
// processClass names them: module members (inside if / try / with blocks
// too) and, qualified `Outer.Inner`, the members of their bodies. A class
// declared inside a function is not one of them.
func pythonFileClassNames(root *sitter.Node, src []byte) map[string]bool {
	names := make(map[string]bool)
	var visit func(body *sitter.Node, outer string)
	visit = func(body *sitter.Node, outer string) {
		forEachPythonMemberDefinition(body, func(child *sitter.Node) {
			class := child
			if child.Type() == pythonDecoratedDefinition {
				class = child.ChildByFieldName("definition")
			}
			if class == nil || class.Type() != pythonNodeClassDefinition {
				return
			}
			nameNode, body := class.ChildByFieldName("name"), class.ChildByFieldName("body")
			if nameNode == nil || body == nil {
				return
			}
			name := nameNode.Content(src)
			if outer != "" {
				name = outer + "." + name
			}
			names[name] = true
			visit(body, name)
		})
	}
	visit(root, "")
	return names
}
