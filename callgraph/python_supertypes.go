// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// pythonDeclaredClass is one class a file declares: its name qualified by the
// classes enclosing it (`Outer.Inner`), the enclosing class's ("" for a
// module member), and its bases as written.
type pythonDeclaredClass struct {
	name  string
	outer string
	bases []string
}

// recordPythonSupertypes stores each declared class's bases, fully
// qualified, in analysis.Supertypes, keyed `<module>.<Class>` the way the
// graph keys owners (declOwnerFQN). Every class gets an entry, an empty one
// when it names no base, so the graph knows the class even when it declares
// no method. A name resolves the way Python looks it up from the class
// statement:
//
//   - a class of the enclosing class bodies, then of the module;
//   - an import: `from m import B` gives m.B, `import a.b` then `a.b.C` gives
//     a.b.C, `from p import mod` then `mod.C` gives p.mod.C;
//   - a builtin: builtins.Exception (`object` is left out: every class has
//     it);
//   - otherwise a module global bound some other way (a star import): the
//     module's own name, <module>.B.
//
// Subscripted (`Generic[T]`) and keyword (`metaclass=`) bases are not bases
// the class inherits methods from and are not recorded (the parser does not
// collect them).
func recordPythonSupertypes(analysis *FileAnalysis, modulePath string, classes []pythonDeclaredClass) {
	if len(classes) == 0 {
		return
	}
	declared := make(map[string]bool, len(classes))
	for _, class := range classes {
		declared[class.name] = true
	}
	if analysis.Supertypes == nil {
		analysis.Supertypes = make(map[string][]string, len(classes))
	}
	for _, class := range classes {
		owner := modulePath + "." + class.name
		resolved := analysis.Supertypes[owner]
		if resolved == nil {
			resolved = []string{}
		}
		for _, base := range class.bases {
			if qualified, ok := pythonQualifiedBase(base, class.outer, modulePath, declared, analysis); ok && !stringSliceContains(resolved, qualified) {
				resolved = append(resolved, qualified)
			}
		}
		analysis.Supertypes[owner] = resolved
	}
}

// pythonQualifiedBase resolves one base as written to its qualified name; ok
// is false for `object`.
func pythonQualifiedBase(base, outer, modulePath string, declared map[string]bool, analysis *FileAnalysis) (string, bool) {
	for scope := outer; scope != ""; {
		if declared[scope+"."+base] {
			return modulePath + "." + scope + "." + base, true
		}
		cut := strings.LastIndex(scope, ".")
		if cut < 0 {
			break
		}
		scope = scope[:cut]
	}
	if declared[base] {
		return modulePath + "." + base, true
	}
	head, rest, dotted := strings.Cut(base, ".")
	if module, ok := analysis.Imports[head]; ok {
		prefix := module
		if analysis.FromImports[head] {
			prefix = module + "." + pythonImportedName(analysis, head)
		}
		if dotted {
			return prefix + "." + rest, true
		}
		return prefix, true
	}
	if !dotted && pythonBuiltinNames[base] {
		if base == "object" {
			return "", false
		}
		return pythonBuiltinsModule + "." + base, true
	}
	return modulePath + "." + base, true
}
