// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

// pythonBuiltinsModule is the module Python's builtin names live in.
const pythonBuiltinsModule = "builtins"

// pythonBuiltinNames are the public names of the builtins module (CPython
// 3.12, plus 3.13's PythonFinalizationError) that a program can call or
// subclass. A bare name a module neither defines nor imports is one of these
// at run time.
var pythonBuiltinNames = map[string]bool{
	"ArithmeticError": true, "AssertionError": true, "AttributeError": true, "BaseException": true,
	"BaseExceptionGroup": true, "BlockingIOError": true, "BrokenPipeError": true, "BufferError": true,
	"BytesWarning": true, "ChildProcessError": true, "ConnectionAbortedError": true, "ConnectionError": true,
	"ConnectionRefusedError": true, "ConnectionResetError": true, "DeprecationWarning": true, "EOFError": true,
	"EncodingWarning": true, "EnvironmentError": true, "Exception": true, "ExceptionGroup": true,
	"FileExistsError": true, "FileNotFoundError": true, "FloatingPointError": true, "FutureWarning": true,
	"GeneratorExit": true, "IOError": true, "ImportError": true, "ImportWarning": true,
	"IndentationError": true, "IndexError": true, "InterruptedError": true, "IsADirectoryError": true,
	"KeyError": true, "KeyboardInterrupt": true, "LookupError": true, "MemoryError": true,
	"ModuleNotFoundError": true, "NameError": true, "NotADirectoryError": true, "NotImplementedError": true,
	"OSError": true, "OverflowError": true, "PendingDeprecationWarning": true, "PermissionError": true,
	"ProcessLookupError": true, "PythonFinalizationError": true, "RecursionError": true, "ReferenceError": true,
	"ResourceWarning": true, "RuntimeError": true, "RuntimeWarning": true, "StopAsyncIteration": true,
	"StopIteration": true, "SyntaxError": true, "SyntaxWarning": true, "SystemError": true,
	"SystemExit": true, "TabError": true, "TimeoutError": true, "TypeError": true,
	"UnboundLocalError": true, "UnicodeDecodeError": true, "UnicodeEncodeError": true, "UnicodeError": true,
	"UnicodeTranslateError": true, "UnicodeWarning": true, "UserWarning": true, "ValueError": true,
	"Warning": true, "ZeroDivisionError": true,
	"abs": true, "aiter": true, "all": true, "anext": true, "any": true, "ascii": true, "bin": true,
	"bool": true, "breakpoint": true, "bytearray": true, "bytes": true, "callable": true, "chr": true,
	"classmethod": true, "compile": true, "complex": true, "copyright": true, "credits": true,
	"delattr": true, "dict": true, "dir": true, "divmod": true, "enumerate": true, "eval": true,
	"exec": true, "exit": true, "filter": true, "float": true, "format": true, "frozenset": true,
	"getattr": true, "globals": true, "hasattr": true, "hash": true, "help": true, "hex": true,
	"id": true, "input": true, "int": true, "isinstance": true, "issubclass": true, "iter": true,
	"len": true, "license": true, "list": true, "locals": true, "map": true, "max": true,
	"memoryview": true, "min": true, "next": true, "object": true, "oct": true, "open": true,
	"ord": true, "pow": true, "print": true, "property": true, "quit": true, "range": true,
	"repr": true, "reversed": true, "round": true, "set": true, "setattr": true, "slice": true,
	"sorted": true, "staticmethod": true, "str": true, "sum": true, "super": true, "tuple": true,
	"type": true, "vars": true, "zip": true,
}

// prunePythonBuiltinCalls drops the calls of Python builtins from the file's
// declarations: `len(x)`, `isinstance(..)`, `ValueError(..)`. The parser
// keys a bare name it cannot resolve under the caller's module, so a
// builtin call read as `<module>.len`, a package call to a function no
// component declares, in every fragment (cryptography: 889 sites). A name
// the module binds itself (a def, a class, an assignment; module is its
// binding layer) or the function binds (a parameter, a local, a nested def)
// is not the builtin and is kept. Runs
// after addPythonCallbackReferences, which reads `map(f, xs)` and its kin.
func prunePythonBuiltinCalls(analysis *FileAnalysis, module *pythonBindingLayer) {
	shadowed := make(map[string]bool)
	if module != nil {
		for name := range module.names {
			shadowed[name] = true
		}
	}
	for i := range analysis.Functions {
		if decl := &analysis.Functions[i]; decl.ID.Type == "" {
			shadowed[decl.ID.Name] = true
		}
	}
	for i := range analysis.Functions {
		decl := &analysis.Functions[i]
		kept := decl.Calls[:0]
		for _, call := range decl.Calls {
			if !pythonIsBuiltinCall(&call, analysis.PackagePath, decl, shadowed) {
				kept = append(kept, call)
			}
		}
		decl.Calls = kept
	}
}

// pythonIsBuiltinCall reports whether call is a bare-name call of a builtin
// the module and the calling function do not rebind.
func pythonIsBuiltinCall(call *FunctionCall, modulePath string, decl *FunctionDecl, shadowed map[string]bool) bool {
	name := call.Callee.Name
	if call.Callee.Package != modulePath || call.Callee.Type != "" || call.Raw != name || !pythonBuiltinNames[name] {
		return false
	}
	return !shadowed[name] && !decl.boundNames[name]
}
