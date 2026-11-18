// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

// resolveGoDotImportCalls keys a bare call through a dot import (`import .
// "p"`; `Sign()`) to the imported package. The parser keys every bare call
// to the caller's own package, since one file cannot see the rest of its
// package; once the graph holds the whole package, a bare call to a name the
// package does not declare, in a file with exactly one dot import, can only
// be that import's (go-port audit E4b). With several dot imports the call
// stays as parsed: which package declares the name is not known.
func resolveGoDotImportCalls(graph *CallGraph, ecosystem string) {
	if ecosystem != ecosystemGo || len(graph.GoImports) == 0 {
		return
	}
	for _, fn := range graph.Functions {
		dot := goSoleDotImport(graph.GoImports[fn.FilePath])
		if dot == "" {
			continue
		}
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if call.Callee.Type != "" || call.Raw != call.Callee.Name || call.ReceiverVar != "" || call.StaticReceiver ||
				call.FieldReceiver != nil || call.Callee.Package != fn.ID.Package || goPredeclaredIdentifiers[call.Callee.Name] {
				continue
			}
			if _, declared := graph.Functions[call.Callee.String()]; declared {
				continue
			}
			call.Callee.Package = dot
		}
	}
}

// goSoleDotImport is the path of a file's only dot import, "" when it has
// none or several.
func goSoleDotImport(imports []GoImport) string {
	dot := ""
	for _, imp := range imports {
		if imp.Alias != "." {
			continue
		}
		if dot != "" {
			return ""
		}
		dot = imp.Path
	}
	return dot
}
