// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	"github.com/scanoss/reach/callgraph/entrypoints"
)

// C# entry points the parser recognizes from the framework catalog
// (entrypoints/csharp): attribute routing, which marks a method or a whole
// controller type.

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

func csharpAnyAttribute(string) bool { return true }

func csharpTypeAttribute(name string) bool { return csharpTypeEntryAttributes[name] }
