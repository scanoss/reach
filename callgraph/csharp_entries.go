// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"

	"github.com/scanoss/reach/callgraph/entrypoints"
)

// C# entry points the parser recognizes from the framework catalog
// (entrypoints/csharp): attribute routing, which marks a method or a whole
// controller type, and the method groups a minimal-API registration call
// hands to the framework.

// csharpTypeEntryAttributes are the catalog attributes that, on a type, make
// its actions entry points: they declare the type a controller. Every
// catalog attribute marks the method it sits on.
var csharpTypeEntryAttributes = map[string]bool{"ApiController": true, "Controller": true, "Route": true}

// csharpAttributeEntryMark returns the mark of the first written attribute
// the catalog names and accepts reports true for. An attribute resolves to
// its type the way the compiler does: qualified as written, else through a
// using alias, else through each namespace a using brings in (written or the
// project's), else the declaring namespace. [HttpGet] and [HttpGetAttribute]
// both name HttpGetAttribute.
func csharpAttributeEntryMark(written []string, namespace string, analysis *FileAnalysis, accepts func(string) bool) (EntryMark, bool) {
	catalog := entryCatalog()
	for _, name := range written {
		expanded := csharpExpandAlias(name, analysis)
		simple := csharpAttributeName(expanded)
		if !accepts(simple) || !catalog.Named(entryLanguageCSharp, entrypoints.ShapeDecorator, simple) {
			continue
		}
		packages := append(append([]string(nil), analysis.WildcardImports...), namespace)
		if dot := strings.LastIndex(expanded, csharpSeparator); dot >= 0 {
			packages = []string{expanded[:dot]}
		}
		for _, pkg := range packages {
			if entry, ok := catalog.Match(entryLanguageCSharp, entrypoints.ShapeDecorator, pkg, "", simple); ok {
				return catalogEntryMark(&entry), true
			}
		}
	}
	return EntryMark{}, false
}

// markCSharpControllerActions marks the actions of the types a catalog
// attribute declares controllers, by the type's full name.
func markCSharpControllerActions(analysis *FileAnalysis, controllers map[string]EntryMark) {
	if len(controllers) == 0 {
		return
	}
	for i := range analysis.Functions {
		decl := &analysis.Functions[i]
		if mark, ok := controllers[decl.OwnerName]; ok && csharpIsAction(decl) {
			markEntry(decl, mark)
		}
	}
}

// csharpRegisteredHandlers returns the method group a catalog registration
// call hands to the framework as its handler, its last argument:
// app.MapGet("/users/{id}", GetUser) or app.MapPost("/orders",
// OrderHandlers.Create). The call is the framework's when the namespace that
// declares the extension method is in scope for the file, or the receiver is
// declared with a type of it. A lambda handler names no method: its calls
// already belong to the function that registers it.
func csharpRegisteredHandlers(node *sitter.Node, src []byte, call *FunctionCall, namespace, typePath string, variableTypes, members map[string]string, analysis *FileAnalysis) []EntryRef {
	function := node.ChildByFieldName("function")
	if function == nil || function.Type() != csharpNodeMemberAccess {
		return nil
	}
	method := BaseFunctionName(call.Callee.Name)
	catalog := entryCatalog()
	if !catalog.Named(entryLanguageCSharp, entrypoints.ShapeRegistrationCall, method) {
		return nil
	}
	packages := analysis.WildcardImports
	if !call.StaticReceiver {
		packages = append(packages[:len(packages):len(packages)], call.Callee.Package)
	}
	var entry entrypoints.Entry
	found := false
	for _, pkg := range packages {
		if entry, found = catalog.Match(entryLanguageCSharp, entrypoints.ShapeRegistrationCall, pkg, "", method); found {
			break
		}
	}
	arguments := csharpArgumentExpressions(node.ChildByFieldName("arguments"))
	if !found || len(arguments) == 0 || (entry.Path == entrypoints.PathRequired && len(arguments) < 2) {
		return nil
	}
	mark := catalogEntryMark(&entry)
	var refs []EntryRef
	for _, owner := range csharpMethodGroupOwners(arguments[len(arguments)-1], src, namespace, typePath, variableTypes, members, analysis) {
		refs = append(refs, EntryRef{Function: owner, Overloads: true, Mark: mark})
	}
	return refs
}

// csharpArgumentExpressions are the expressions of a call's arguments, each
// without the name a named argument writes.
func csharpArgumentExpressions(list *sitter.Node) []*sitter.Node {
	if list == nil {
		return nil
	}
	var out []*sitter.Node
	for i := 0; i < int(list.NamedChildCount()); i++ {
		argument := list.NamedChild(i)
		if argument.Type() == csharpNodeArgument && argument.NamedChildCount() > 0 {
			out = append(out, argument.NamedChild(int(argument.NamedChildCount())-1))
		}
	}
	return out
}

// csharpMethodGroupOwners names the methods a method-group expression can
// denote, without their arity: a bare name is a method of the enclosing type
// (Program in top-level statements); Type.Name is a method of Type, under
// every namespace that could declare it; this.Name and a member typed by a
// local, a parameter or a field name a method of that type.
func csharpMethodGroupOwners(expression *sitter.Node, src []byte, namespace, typePath string, variableTypes, members map[string]string, analysis *FileAnalysis) []FunctionID {
	switch expression.Type() {
	case csharpNodeIdentifier:
		name := expression.Content(src)
		if _, local := variableTypes[name]; local {
			return nil
		}
		if _, member := members[name]; member {
			return nil
		}
		return []FunctionID{{Package: namespace, Type: typePath, Name: name}}
	case csharpNodeMemberAccess:
		receiver, name := expression.ChildByFieldName("expression"), expression.ChildByFieldName("name")
		if receiver == nil || name == nil || name.Type() != csharpNodeIdentifier {
			return nil
		}
		method := name.Content(src)
		written := csharpTypeName(receiver, src)
		switch declared, local := variableTypes[written]; {
		case written == "this":
			return []FunctionID{{Package: namespace, Type: typePath, Name: method}}
		case local:
			written = declared
		default:
			if member, ok := members[written]; ok {
				written = member
			}
		}
		pkg, typ := csharpOwner(written, namespace, analysis)
		owners := []FunctionID{{Package: pkg, Type: typ, Name: method}}
		if pkg == namespace && csharpExpandAlias(written, analysis) == written {
			for _, wildcard := range analysis.WildcardImports {
				owners = append(owners, FunctionID{Package: wildcard, Type: typ, Name: method})
			}
		}
		return owners
	}
	return nil
}

func csharpAnyAttribute(string) bool { return true }

func csharpTypeAttribute(name string) bool { return csharpTypeEntryAttributes[name] }
