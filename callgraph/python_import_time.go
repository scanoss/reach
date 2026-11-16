// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// python_import_time.go gives a Python module's import-time code its callers.
// Importing a module runs its top level, and the top level of every package
// on its dotted path; a class body runs when its `class` statement does. So
// the module's `<module>` reaches each module it imports, a function reaches
// each module it imports in its body, and `<module>` reaches the `<clinit>`
// of each class it defines (an outer class's `<clinit>` that of a nested
// one), unless an entry rule made that class body a root of its own (a
// Django migration's, which the framework loads). Without these edges code that runs at import (`JWS_ALGORITHMS =
// [RSAAlgorithm(..)]`, `_OID_NAMES = {...}`) has no caller and reads
// unreachable even when the client imports its module.
//
// An import under `if TYPE_CHECKING:` never runs and has no edge, nor does
// one in a stub (`.pyi`): importing the module it describes, often a native
// extension, never runs the stub. Standard
// library modules get none either: no fragment declares them, and the edges
// would only grow the fragments.

// addPythonImportTimeCalls adds the import edges of one parsed file to its
// declarations, creating the module's `<module>` when a module-level import
// or class needs one.
func addPythonImportTimeCalls(root *sitter.Node, src []byte, filePath, modulePath string, analysis *FileAnalysis) {
	if strings.HasSuffix(filePath, ".pyi") {
		return
	}
	guarded := pythonTypeCheckingBlocks(root, src)
	moduleIndex := -1
	for i := range analysis.Functions {
		if analysis.Functions[i].ID.Name == moduleInitMethodName && analysis.Functions[i].ID.Type == "" {
			moduleIndex = i
		}
	}
	type edge struct {
		decl   int // index into analysis.Functions; -1 for the module's
		target string
		line   int
	}
	var edges []edge
	for _, imp := range analysis.PythonImports {
		if pythonLineIn(guarded, imp.Line) {
			continue
		}
		decl := -1
		if imp.Local {
			decl = innermostPythonDecl(analysis.Functions, imp.Line)
		}
		for _, target := range pythonImportRuns(imp) {
			if target != modulePath && !pythonStdlibModule(target) {
				edges = append(edges, edge{decl: decl, target: target, line: imp.Line})
			}
		}
	}
	var clinits []edge
	for i := range analysis.Functions {
		fn := &analysis.Functions[i]
		if fn.ID.Name != clinitMethodName || fn.ID.Package != modulePath || fn.EntryKind != "" {
			continue
		}
		parent := -1
		if dot := strings.LastIndex(fn.ID.Type, "."); dot > 0 {
			outer := FunctionID{Package: modulePath, Type: fn.ID.Type[:dot], Name: clinitMethodName}
			for j := range analysis.Functions {
				if analysis.Functions[j].ID == outer {
					parent = j
				}
			}
		}
		clinits = append(clinits, edge{decl: parent, target: fn.ID.String(), line: fn.StartLine})
	}
	if len(edges) == 0 && len(clinits) == 0 {
		return
	}
	if moduleIndex < 0 {
		moduleIndex = pythonModuleDecl(root, filePath, modulePath, analysis)
	}
	seen := make(map[[2]string]bool)
	add := func(decl int, callee FunctionID, line int) {
		if decl < 0 {
			decl = moduleIndex
		}
		fn := &analysis.Functions[decl]
		key := [2]string{fn.ID.String(), callee.String()}
		if seen[key] {
			return
		}
		seen[key] = true
		fn.ImplicitCalls = append(fn.ImplicitCalls, FunctionCall{
			Callee: callee, Raw: callee.Name, FilePath: filePath, Line: line, pythonImport: true,
		})
	}
	for _, e := range edges {
		add(e.decl, FunctionID{Package: e.target, Name: moduleInitMethodName}, e.line)
	}
	for _, c := range clinits {
		id, _ := ParseFunctionID(c.target)
		add(c.decl, id, c.line)
	}
}

// pythonImportRuns lists the modules an import binding runs: every
// package on the module's dotted path and the module itself, plus the named
// member of a from-import, which may be a submodule (`from pkg import sub`).
// A member that is not a module names a `<module>` no fragment declares, an
// edge the stitch resolves to nothing.
func pythonImportRuns(imp PythonImport) []string {
	var out []string
	parts := strings.Split(imp.Module, ".")
	for i := range parts {
		if parts[i] == "" {
			return nil
		}
		out = append(out, strings.Join(parts[:i+1], "."))
	}
	if imp.Name != "" && imp.Name != pythonWildcardImport {
		out = append(out, imp.Module+"."+imp.Name)
	}
	return out
}

// innermostPythonDecl is the index of the narrowest declaration other than
// `<module>` whose lines hold line, -1 when none does.
func innermostPythonDecl(functions []FunctionDecl, line int) int {
	best := -1
	for i := range functions {
		fn := &functions[i]
		if fn.ID.Name == moduleInitMethodName || line < fn.StartLine || line > fn.EndLine {
			continue
		}
		if best < 0 || fn.EndLine-fn.StartLine < functions[best].EndLine-functions[best].StartLine {
			best = i
		}
	}
	return best
}

// pythonTypeCheckingBlocks returns the line spans of the bodies of the
// file's `if TYPE_CHECKING:` / `if typing.TYPE_CHECKING:` statements, which
// run only under a type checker.
func pythonTypeCheckingBlocks(root *sitter.Node, src []byte) [][2]int {
	var out [][2]int
	var walk func(n *sitter.Node)
	walk = func(n *sitter.Node) {
		if n.Type() == "if_statement" {
			condition := n.ChildByFieldName("condition")
			if condition != nil {
				text := condition.Content(src)
				if text == "TYPE_CHECKING" || strings.HasSuffix(text, ".TYPE_CHECKING") {
					if body := n.ChildByFieldName("consequence"); body != nil {
						out = append(out, [2]int{int(body.StartPoint().Row) + 1, int(body.EndPoint().Row) + 1})
					}
				}
			}
		}
		for i := 0; i < int(n.NamedChildCount()); i++ {
			walk(n.NamedChild(i))
		}
	}
	walk(root)
	return out
}

func pythonLineIn(spans [][2]int, line int) bool {
	for _, s := range spans {
		if line >= s[0] && line <= s[1] {
			return true
		}
	}
	return false
}

// settlePythonImportCalls drops, once the build is parsed, the import edges
// the build's own modules answer without a `<module>`: into a module of its
// own that declares none (it runs no code), or naming a member of one that is
// not a module (`from pkg.core import Signer`). Either would leave the
// fragment as a call into a dependency.
func settlePythonImportCalls(graph *CallGraph, analyses []*FileAnalysis) {
	own := make(map[string]bool, len(analyses))
	for _, a := range analyses {
		own[a.PackagePath] = true
	}
	for _, fn := range graph.Functions {
		calls := fn.ImplicitCalls[:0]
		for _, call := range fn.ImplicitCalls {
			if call.pythonImport && graph.Functions[call.Callee.String()] == nil && pythonOwnModulePath(own, call.Callee.Package) {
				continue
			}
			calls = append(calls, call)
		}
		fn.ImplicitCalls = calls
	}
}

// pythonOwnModulePath reports a module path, or a name in one, under a
// module of own.
func pythonOwnModulePath(own map[string]bool, path string) bool {
	for path != "" {
		if own[path] {
			return true
		}
		dot := strings.LastIndex(path, ".")
		if dot < 0 {
			return false
		}
		path = path[:dot]
	}
	return false
}

// pythonStdlibModule reports a module of the standard library (Python 3.12's
// sys.stdlib_module_names, private ones left out, plus __future__).
func pythonStdlibModule(module string) bool {
	top, _, _ := strings.Cut(module, ".")
	return pythonStdlibModules[top]
}

var pythonStdlibModules = func() map[string]bool {
	out := map[string]bool{"__future__": true}
	for _, m := range strings.Fields(`abc aifc antigravity argparse array ast asyncio atexit audioop base64 bdb
		binascii bisect builtins bz2 cProfile calendar cgi cgitb chunk cmath cmd code codecs codeop collections
		colorsys compileall concurrent configparser contextlib contextvars copy copyreg crypt csv ctypes curses
		dataclasses datetime dbm decimal difflib dis doctest email encodings ensurepip enum errno faulthandler
		fcntl filecmp fileinput fnmatch fractions ftplib functools gc genericpath getopt getpass gettext glob
		graphlib grp gzip hashlib heapq hmac html http idlelib imaplib imghdr importlib inspect io ipaddress
		itertools json keyword lib2to3 linecache locale logging lzma mailbox mailcap marshal math mimetypes mmap
		modulefinder msilib msvcrt multiprocessing netrc nis nntplib nt ntpath nturl2path numbers opcode operator
		optparse os ossaudiodev pathlib pdb pickle pickletools pipes pkgutil platform plistlib poplib posix
		posixpath pprint profile pstats pty pwd py_compile pyclbr pydoc pydoc_data pyexpat queue quopri random re
		readline reprlib resource rlcompleter runpy sched secrets select selectors shelve shlex shutil signal site
		smtplib sndhdr socket socketserver spwd sqlite3 sre_compile sre_constants sre_parse ssl stat statistics
		string stringprep struct subprocess sunau symtable sys sysconfig syslog tabnanny tarfile telnetlib
		tempfile termios textwrap this threading time timeit tkinter token tokenize tomllib trace traceback
		tracemalloc tty turtle turtledemo types typing unicodedata unittest urllib uu uuid venv warnings wave
		weakref webbrowser winreg winsound wsgiref xdrlib xml xmlrpc zipapp zipfile zipimport zlib zoneinfo`) {
		out[m] = true
	}
	return out
}()
