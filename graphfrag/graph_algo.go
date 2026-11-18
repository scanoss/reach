// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "strings"

// GraphAlgoVersionPython identifies the callgraph-construction algorithm of
// Python graphs. Python has its own id so a change to Python graph
// construction never marks a Java graph stale: consumers compare a stored
// graph's graph_algo_version with GraphAlgoVersionFor of its ecosystem.
//
// graph-algo-py-1: the Python graphs of graph-algo-37, under their own id.
// graph-algo-py-2: defs and classes inside module-level if / try / with
// blocks, and classes nested in a class body, are in the graph; a name
// defined twice in one file keeps both bodies' calls.
// graph-algo-py-3: Python classes carry their resolved bases as supertypes.
// graph-algo-py-4: self / cls / super() calls and class instantiations are
// edges to the declaration the method resolution order gives.
// graph-algo-py-5: dunder methods whose body makes a call are graph functions.
// graph-algo-py-6: calls of builtins (len, isinstance, ValueError, ...) are
// not exported as calls of the caller's module.
// graph-algo-py-7: a method called on an imported class object
// (`Signer.default()`) is an edge to its declaration.
// graph-algo-py-8: a method called on a local typed after the caller index
// (`key = ec.generate_private_key(..)` then `key.sign(..)`) has one site, at
// the typed key, with its text, receiver and arguments.
// graph-algo-py-9: a comment inside a call's argument list is not glued onto
// an argument.
// graph-algo-py-10: a call nothing typed (a method on a duck-typed receiver,
// a call of a parameter) is name_only, and a subclass-dispatch edge is
// interface_dispatch.
// graph-algo-py-11: super() calls and class instantiations do not dispatch to
// subclass overrides.
// graph-algo-py-12: a call on a receiver whose text holds a call with
// arguments (`b64encode(x).decode("utf-8").replace(..)`) keeps its site's
// text, arguments and resolution.
// graph-algo-py-13: a generator expression passed as a call's only argument
// (`s.update(k for k in xs)`) is the call's argument.
// graph-algo-py-14: a call on `self.<field>` is typed with the class every
// write of the field that can reach self names (assignments, annotations,
// properties), across the methods of the class hierarchy.
// graph-algo-py-15: parameter and return annotations name the class where they
// are written (module classes, imports, builtin classes); a class, function or
// method named through another module's import links to its declaration; an
// `async def` call types no local.
// graph-algo-py-16: a local built from a class that declares no method of its
// own is typed with that class.
// graph-algo-py-17: a field's own annotation decides its class; a field
// assigned an attribute of a typed value, self or `cast(C, v)` is typed;
// `self.a.b` receivers are typed field by field; a write on an annotated
// receiver reaches only that class's fields.
// graph-algo-py-18: a keyword argument carries its keyword, apart from its
// value, at its place in the call.
// graph-algo-py-19: fragments list each file's import bindings (`imports`).
// graph-algo-py-20: fragments map the component's public names to the
// declarations they name (`exports`).
// graph-algo-py-21: a package's own binding of a name shadows its submodule
// of that name in the exports (github.GithubException is the class).
// graph-algo-py-22: a keyword argument whose value spans lines carries its
// keyword too.
// graph-algo-py-23: fragments list the constants Python code references
// outside a call (`constant_refs`: attribute chains rooted in an import,
// from-imported names, dotted case patterns) with their position and the
// operand a comparison, membership test or case compares them with; a
// module or class body with references and no call gets its synthetic
// function.
// graph-algo-py-24: fragments list the assignments to an attribute of an
// object (`attribute_stores`: `ctx.verify_mode = ssl.CERT_NONE`) with the
// value traced; a local or module name written more than once carries the
// string literals it may hold (`may_values`, exhaustive when every write is
// one).
// graph-algo-py-25: fragments list annotated assignments as declarations and
// `typing.cast(T, f(..))` as casts; methods decorated @abstractmethod, stubs
// of a Protocol class and bodies that only raise NotImplementedError are
// abstract, and scan_metadata.abstract_methods says so.
// graph-algo-py-26: fragments carry the graph-fragment-1.21 call data (call
// anchors with target, text, arguments and their provenance, parameter
// names, return provenance) and rebind_lines (1.23), so a source-free
// annotate rebuilds the calls a scan reads.
// graph-algo-py-27: `self.f = g(..)` is no attribute store: the call's
// assigned_var names the field.
// graph-algo-py-28: inside a branch guarded by `v == X`, `v in (X, Y)` or
// `case X` / `case X | Y` of `match v`, an argument or compared operand v
// traces to X (a VALUE, or the may-values X and Y); a dotted `case` pattern
// binds no name of its function.
// graph-algo-py-29: a method's parameter and a keyword-only parameter are
// PARAMETER sources: a method's at the position the caller writes it (self
// or cls left out), a keyword-only one at -1, read by its name.
// graph-algo-py-30: a subscript of a dispatch table (a dict display with
// literal keys, in place or through a name bound once to it) whose key
// resolves traces to the value of the entry the key selects.
// graph-algo-py-31: a field compared with a constant (`self.f == X`) carries
// the fixed values its class assigns to it.
// graph-algo-py-32: a local or module name bound once to a dotted name rooted
// in an import (`variant = Type.ID`) traces to that name, as one bound to a
// literal traces to the literal.
// graph-algo-py-33: a read of a table the function itself writes or binds,
// with a key that does not resolve, carries the values of the table's
// entries as may-values; a local bound once to a table read traces to it.
// graph-algo-py-34: a table handed to other code (passed as an argument,
// aliased, returned, put in a display) is no fixed table: its reads keep no
// value, as for one whose items the file writes.
// graph-algo-py-35: fragments list the bindings of each local a function
// binds more than once with a call among the values (`local_bindings`), so a
// reader tells which assignment of a local reaches a use; a name bound once
// to a list or tuple of literals (`algs = ["HS256"]`) traces to its display;
// each target of a tuple pattern assigned a call is listed with its element.
// graph-algo-py-36: a constant reference tested by isinstance / issubclass
// has the position type_check (E2.7-py.15).
// graph-algo-py-37: import-time edges: a module's `<module>` (created for a
// module that only imports or defines classes) calls the `<module>` of each
// module it imports and of the packages on its path, a function each module
// it imports in its body, and `<module>` the `<clinit>` of its classes; none
// under `if TYPE_CHECKING:`, from a stub, or into the standard library
// (E2.7-py.24).
// graph-algo-py-38: a class handed around as a value (stored in a table,
// passed, returned, raised, assigned; not tested, caught or annotated) gets
// a name_only edge from the function reading it to `pkg.(K).<class>`
// (E2.7-py.24).
// graph-algo-py-39: fragments map the names a package's `__init__.py`
// imports to the modules that declare them (`public_paths`), so annotate
// surfaces a library's API declared behind a re-export as a scan does
// (E2.7-py.21b; numbered 37 on its own branch).
// graph-algo-py-40: a module statement writing a field on a module-level
// object (`_obj.f = v`, the module binding _obj once, to a call) is a write
// on the instances of the object's class, and a module-level object as the
// value tells that class: the field stays typed when the writes agree
// (pyjwt's `self._jws`), instead of untyped for any write off self
// (E2.7-py.26).
const GraphAlgoVersionPython = pythonGraphAlgoPrefix + "40"

// pythonGraphAlgoPrefix starts every Python graph algorithm id: a fragment
// stamped with one is a Python graph.
const pythonGraphAlgoPrefix = "graph-algo-py-"

// GraphAlgoVersionRust identifies the callgraph-construction algorithm of
// Rust graphs, so a change to Rust graph construction never marks a Java
// graph stale.
//
// graph-algo-rs-1: the Rust graphs of graph-algo-39, under their own id.
// graph-algo-rs-2: fragments list each file's `use` and `extern crate`
// bindings as written, one per leaf of a grouped use, with the declaration's
// span and use tree (`imports`), and its inline modules, functions, impl
// blocks, traits, consts, statics, structs and `extern crate` items with
// their spans (`items`, graph-fragment-1.26).
// graph-algo-rs-3: fragments list the paths of two or more segments a body
// reads outside a callee (`constant_refs`, text as written, with the position
// kind: compare, case for a match arm pattern, return, assign, init, array,
// arg, other) and one declaration per name a `let` binds (`declarations`).
// graph-algo-rs-4: every call is a call of the graph, resolved or not: a call
// of a value the parser cannot name (`fs[0](x)`, `make()(x)`) is keyed
// `<pkg>.<value>`, `(f)(x)` calls f, and the initializers of const and static
// items outside function bodies make their calls and references in the
// file's synthetic `<varinit:<file>>`, as Go's package variables do.
// graph-algo-rs-5: call arguments carry their value sources (`source_nodes`)
// within the calling function, as Java's and Python's do: a literal (VALUE),
// a const or non-mut static item of the file, by bare name, `use`-shortened
// or by path (FIELD over its literal), a `let` traced to its initializer
// (VARIABLE; a let assigned again holds MayValues), a parameter (PARAMETER
// with its position among the call's arguments, `self` left out), a call
// (CALL_RESULT over the values of its receiver and arguments), and an
// operation or expression macro (EXPRESSION over its operands).
// graph-algo-rs-6: fragments list each file's type aliases among its items
// (kind type, `[pub] type A<T> = X;` in a module, a function body or an impl,
// whose associated type definitions are type aliases too), with the aliased
// type as written and the column of the `type` keyword
// (graph-fragment-1.27).
// graph-algo-rs-7: fragments list each file's binary expressions in function
// bodies (`binary_exprs`, the graph's RustBinaryExprs: operator, operands as
// written and their spans, the enclosing function's key), and each fn item
// carries its parameters as written (pattern, type, span, self receiver)
// (graph-fragment-1.30): a stored rs-6 graph has neither.
// graph-algo-rs-8: constant_refs also list a one-segment path a body reads as
// a value whose name starts with an upper-case letter (`&X25519`, `SysRng`;
// not None, Some, Ok, Err or Self), and the path of every struct literal, of
// one segment or more, in a new position kind struct (`acme::Key { .. }`)
// (graph-fragment-1.33): a stored rs-7 graph has neither.
// graph-algo-rs-9: such a one-segment name is listed wherever it is read,
// not only under the parents rs-8 named: a match scrutinee, an if or while
// condition, a closure body, a break value. It is left out only in a pattern
// (a binding, a match arm's name, a parameter), as a segment of a longer
// path, as a callee and as a macro's name.
const GraphAlgoVersionRust = rustGraphAlgoPrefix + "9"

// rustGraphAlgoPrefix starts every Rust graph algorithm id: a fragment
// stamped with one is a Rust graph.
const rustGraphAlgoPrefix = "graph-algo-rs-"

// GraphAlgoVersionNode identifies the callgraph-construction algorithm of
// Node (JavaScript and TypeScript) graphs. Node has its own id so a change to
// Node graph construction never marks a Java, Python or Rust graph stale.
//
// graph-algo-node-1: the Node graphs of graph-algo-39, under their own id.
// graph-algo-node-2: a call or `new` of a module binding itself is keyed by
// the module's default export, not the local name: `const kk =
// require('m'); kk(x)`, `import f from 'm'; f(x)`, `import * as ns from 'm';
// ns(x)` and `require('m')(x)` all call m.default (was m.kk, m.f, m.ns, no
// call), and `new X()` of such a binding constructs m.(default).<init> (was
// m.(X).<init>). `new (require('m'))()` and `new (require('m').K)()` are
// calls (they were none), and TypeScript's `import x = require('m')` binds x
// as `const x = require('m')` does.
// graph-algo-node-3: fragments list each file's imports (`imports`, the
// graph's NodeImports): import declarations, TypeScript `import x =
// require()`, require() at any level, import() and `export ... from`, with
// the module specifier as written and the import's kind.
// graph-algo-node-4: a module binding the file holds through its own
// declarations keys calls as the import does: an alias (`const s = sodium;
// s.f()`), a destructuring of a module binding (`const { sm2 } = smCrypto`),
// a require or destructured require inside a function body, an awaited or
// `.catch`-handled import() bound to a name, and an interop helper
// (`_interopNamespaceDefault` and the rest, `$1` copies included) called on a
// module binding all call m.f (were caller-local), and a member chain on an
// inline require (`require('m').Gen.create()`) calls m.Gen.create (was
// caller-local create).
// graph-algo-node-5: fragments list each file's outermost object literals
// (`object_literals`, the graph's NodeObjectLiterals, graph-fragment-1.28):
// a stored node-4 graph has none.
// graph-algo-node-6: fragments list each file's property reads
// (`property_reads`, the graph's NodePropertyReads, graph-fragment-1.29):
// a stored node-5 graph has none. A call the KB re-keys (an assigned-variable
// receiver or a fluent chain link) no longer leaves its site under the
// caller-local key it shared with other calls of the method name, where an
// export listed it again with another call's raw, columns and variables.
// An object literal carries the variable a declarator or an assignment binds
// it to (AssignedVar, AssignStartCol, AssignLine). A call through a
// string-literal index (`hash['sha256']()`, `acme['mode'].CTR.create()`) is
// a call site keyed as its dotted spelling is (was none, or caller-local), and
// a read through one keys as the dotted read does. A var destructuring of a
// module binding (`var { sm2: signer } = smCrypto`, renamed or not) keys the
// name's calls as the member's, as const and let ones did (was caller-local).
// A call or read on a variable bound to an object merging several modules
// (`Object.assign({}, require('a'), require('b'))`, `{ ...a, ...b }`) keeps
// its caller-local key and lists the modules (CandidateModules), and so does
// every call or read on a chain the variable heads (`H.sha256.create()`,
// `H.sha256.outputLen`). A call or read made directly on `new X(...)` of an
// imported class whose constructor the KB contracts (`new m.X(p).verify()`,
// `new m.X(p).fingerprint`) keys as on a variable the instance is assigned to
// (`m.(X).verify`, was caller-local). Rollup's `_interopDefaultLegacy` (and
// its `$N` copies) passes a module through as the other interop helpers do, so
// `x['default'].init()` and `x.default.CURVE` on its result key as
// `require('m').default.init()` and its read do (were caller-local).
const GraphAlgoVersionNode = nodeGraphAlgoPrefix + "6"

// nodeGraphAlgoPrefix starts every Node graph algorithm id: a fragment
// stamped with one is a Node graph.
const nodeGraphAlgoPrefix = "graph-algo-node-"

// GraphAlgoVersionGo identifies the callgraph-construction algorithm of Go
// graphs, so a change to Go graph construction never marks a Java graph stale.
//
// graph-algo-go-1: the Go graphs of graph-algo-39, under their own id.
// graph-algo-go-2: an unaliased /vN import (N >= 2) also binds vN, so calls
// through a module that declares `package vN` resolve to its path.
// graph-algo-go-3: a call nothing typed (a method on an untyped local or on a
// call's result, a call of a func value) is exported name_only, not exact.
// graph-algo-go-4: a method called on a value the expression constructs
// (`T{}`, `&T{}`, `new(T)`) links to the type's method.
// graph-algo-go-5: fragments list the values Go code reads through an import
// outside a call (`constant_refs`, text `<import path>.<name>`) with their
// position kind and, in a comparison or case, the operand; a package-level
// data var's references go to the file's <varinit>.
// graph-algo-go-6: fragments list the var declarations of an imported type
// (`declarations`, type written `<import path>.<name>`, with `*`, `[]`).
// graph-algo-go-7: fragments carry the call data (call anchors, rebind
// lines) a source-free annotate rebuilds Go calls from, as Java and Python.
// graph-algo-go-8: with a GoSourceTypeResolver, a call on an imported package
// value or on a local bound from a call into a read package is typed from
// that package's declarations.
// graph-algo-go-9: a call on an interface value of a read package outside the
// graph (`aead.Seal` on a crypto/cipher.AEAD) is exported name_only.
// graph-algo-go-10: a call's arguments are its argument nodes (`1<<15` no
// longer splits them); builtin calls are pruned in a package without an import
// path too; a call a pass retypes leaves no site under its former callee.
// graph-algo-go-11: a method named like a builtin (`s.c.close()`) is no longer
// pruned; a type parameter types no call; a `package main` file beside a read
// package lends it nothing; GoUnreadTypeCall tells calls on a type of an
// unread package.
// graph-algo-go-12: an unaliased import whose last element is not an
// identifier also binds the name Go tooling assumes for it (go-jose/v4 binds
// jose); a bare call through a file's only dot import is keyed to that
// import's package; the graph lists each project file's import specs.
const GraphAlgoVersionGo = goGraphAlgoPrefix + "12"

// goGraphAlgoPrefix starts every Go graph algorithm id: a fragment stamped
// with one is a Go graph.
const goGraphAlgoPrefix = "graph-algo-go-"

// GraphAlgoVersionFor is the graph algorithm id a fragment of ecosystem
// (crypto-finder's ecosystem name, as scan_metadata.ecosystem holds it) is
// stamped with and checked against. Java and every ecosystem without an id
// of its own get GraphAlgoVersion; so does "", the ecosystem of a fragment
// written before scan_metadata named one.
func GraphAlgoVersionFor(ecosystem string) string {
	switch ecosystem {
	case "python":
		return GraphAlgoVersionPython
	case "rust":
		return GraphAlgoVersionRust
	case "node":
		return GraphAlgoVersionNode
	case "go":
		return GraphAlgoVersionGo
	}
	return GraphAlgoVersion
}

// ecosystemOfGraphAlgo is the ecosystem an ecosystem's own graph algorithm id
// names, or "" for the shared id.
func ecosystemOfGraphAlgo(id string) string {
	switch {
	case strings.HasPrefix(id, pythonGraphAlgoPrefix):
		return "python"
	case strings.HasPrefix(id, rustGraphAlgoPrefix):
		return "rust"
	case strings.HasPrefix(id, nodeGraphAlgoPrefix):
		return "node"
	case strings.HasPrefix(id, goGraphAlgoPrefix):
		return "go"
	}
	return ""
}

// GraphAlgoVersionForPurl is GraphAlgoVersionFor of the purl's ecosystem.
func GraphAlgoVersionForPurl(purl string) string {
	return GraphAlgoVersionFor(EcosystemForPurl(purl))
}

// EcosystemForPurl is crypto-finder's ecosystem name for a purl's type, or ""
// for a type crypto-finder has no ecosystem for.
func EcosystemForPurl(purl string) string {
	switch {
	case strings.HasPrefix(purl, "pkg:maven/"):
		return "java"
	case strings.HasPrefix(purl, "pkg:golang/"):
		return "go"
	case strings.HasPrefix(purl, "pkg:pypi/"):
		return "python"
	case strings.HasPrefix(purl, "pkg:cargo/"):
		return "rust"
	case strings.HasPrefix(purl, "pkg:npm/"):
		return "node"
	default:
		return ""
	}
}

// GraphEcosystem is the ecosystem of the graph the export carries: the one its
// scan metadata names, else the one its graph algorithm id names when that id
// is an ecosystem's own (Python, Rust, Node, Go), else "" (a graph written
// before scan metadata named an ecosystem: Java's).
func (e *GraphFragmentExport) GraphEcosystem() string {
	if e.ScanMetadata.Ecosystem != "" {
		return e.ScanMetadata.Ecosystem
	}
	return ecosystemOfGraphAlgo(e.ScanMetadata.GraphAlgoVersion)
}

// fragmentEcosystem is the ecosystem of the graph a fragment carries: the one
// its graph algorithm id names when that id is an ecosystem's own (Python,
// Rust, Node, Go), else its component's purl's.
func fragmentEcosystem(fragment Fragment) string {
	if ecosystem := ecosystemOfGraphAlgo(fragment.GraphAlgoVersion); ecosystem != "" {
		return ecosystem
	}
	return EcosystemForPurl(fragment.Component.Purl)
}
