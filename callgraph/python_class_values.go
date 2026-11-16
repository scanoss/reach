// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// python_class_values.go records the classes a Python function hands around
// as values: `{"RSA": RSAKey}`, `register(Handler)`, `return Algorithm`,
// `cls = modes.CTR`, `raise Error`. Whatever holds the class may instantiate
// it or call its class methods later (`table[name](..)`, `key_cls.import_key(..)`)
// through a value no call names. The function gets a name_only edge to
// `pkg.(K).<class>`, the class object: never traversed, it says K may be
// instantiated there, so a stitch that only admits a method of a class
// something instantiates or names keeps K, and reads a finding in K's
// `__init__` unknown rather than unreachable.
//
// A class only tested (isinstance / issubclass), caught (`except E`), written
// in an annotation, a decorator or a class's bases is not handed around. A
// stub's names never run.

// pythonClassValueName is the method of a class-value edge's target,
// `pkg.(K).<class>`: no function bears it, so nothing that reads the graph's
// calls (the cards matcher, a tracer) takes the reference for a call of K.
const pythonClassValueName = "<class>"

// addPythonClassValueRefs adds the class-value edges of one parsed file:
// classes the file declares, from-imported names spelled like a class, and
// attribute chains rooted in an import whose last part is spelled like one.
func addPythonClassValueRefs(root *sitter.Node, src []byte, filePath, modulePath string, analysis *FileAnalysis, classNames map[string]bool) {
	if strings.HasSuffix(filePath, ".pyi") {
		return
	}
	type ref struct {
		callee FunctionID
		line   int
	}
	var refs []ref
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		switch n.Type() {
		case goNodeIdentifier, pythonNodeAttribute:
			if id, ok := pythonClassValue(n, src, modulePath, analysis, classNames); ok {
				refs = append(refs, ref{callee: id, line: int(n.StartPoint().Row) + 1})
			}
			if n.Type() == pythonNodeAttribute {
				return // its object is no value of its own
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	seen := make(map[[2]string]bool)
	for _, r := range refs {
		decl := innermostPythonDecl(analysis.Functions, r.line)
		if decl < 0 {
			decl = pythonModuleDecl(root, filePath, modulePath, analysis)
		}
		fn := &analysis.Functions[decl]
		key := [2]string{fn.ID.String(), r.callee.String()}
		if seen[key] {
			continue
		}
		seen[key] = true
		fn.ImplicitCalls = append(fn.ImplicitCalls, FunctionCall{
			Callee: r.callee, Raw: r.callee.Type, FilePath: filePath, Line: r.line, pythonClassValue: true,
		})
	}
}

// pythonClassValue is the class-value target of the class n names when n
// reads a class as a value.
func pythonClassValue(n *sitter.Node, src []byte, modulePath string, analysis *FileAnalysis, classNames map[string]bool) (FunctionID, bool) {
	parent := n.Parent()
	if parent == nil || !pythonHandedAround(n, parent) || pythonInAnnotationOrDecorator(n) || pythonTypeCheckArg(n, src) {
		return FunctionID{}, false
	}
	text := strings.Join(strings.Fields(n.Content(src)), "")
	if n.Type() == goNodeIdentifier {
		if classNames[text] {
			return FunctionID{Package: modulePath, Type: text, Name: pythonClassValueName}, true
		}
		module, imported := analysis.Imports[text]
		original := pythonImportedName(analysis, text)
		if !imported || !analysis.FromImports[text] || !looksLikePythonTypeName(original) {
			return FunctionID{}, false
		}
		return FunctionID{Package: module, Type: original, Name: pythonClassValueName}, true
	}
	for _, part := range strings.Split(text, ".") {
		if !pythonIdentifierLike(part) {
			return FunctionID{}, false
		}
	}
	head, rest, _ := strings.Cut(text, ".")
	module, imported := analysis.Imports[head]
	middle, last := "", rest
	if dot := strings.LastIndex(rest, "."); dot >= 0 {
		middle, last = rest[:dot], rest[dot+1:]
	}
	if !imported || !looksLikePythonTypeName(last) {
		return FunctionID{}, false
	}
	pkg := module
	if analysis.FromImports[head] {
		pkg = module + "." + pythonImportedName(analysis, head)
	}
	if middle != "" {
		pkg += "." + middle
	}
	return FunctionID{Package: pkg, Type: last, Name: pythonClassValueName}, true
}

// pythonHandedAround reports a class read where it is handed to other code
// or stored: an argument, a returned or raised value, a collection element
// or dict entry, an assigned value, a branch of a conditional.
func pythonHandedAround(n, parent *sitter.Node) bool {
	if parent.Type() == "raise_statement" {
		return true
	}
	if parent.Type() == "comparison_operator" {
		return false
	}
	return pythonValuePosition(n, parent)
}

func pythonIdentifierLike(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (i == 0 || r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// pythonModuleDecl returns the index of the file's `<module>`, creating it
// when the file has none.
func pythonModuleDecl(root *sitter.Node, filePath, modulePath string, analysis *FileAnalysis) int {
	for i := range analysis.Functions {
		if fn := &analysis.Functions[i]; fn.ID.Name == moduleInitMethodName && fn.ID.Type == "" && fn.ID.Package == modulePath {
			return i
		}
	}
	analysis.Functions = append(analysis.Functions, FunctionDecl{
		ID:           FunctionID{Package: modulePath, Name: moduleInitMethodName},
		FilePath:     filePath,
		StartLine:    int(root.StartPoint().Row) + 1,
		EndLine:      int(root.EndPoint().Row) + 1,
		StartCol:     int(root.StartPoint().Column) + 1,
		EndCol:       int(root.EndPoint().Column) + 1,
		OwnerType:    pythonOwnerTypeModule,
		OwnerName:    modulePath,
		FunctionType: functionTypeModuleInit,
	})
	return len(analysis.Functions) - 1
}
