// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
)

// SchemaVersion is the current graph-fragment export schema version.
//
// 1.1 added per-edge resolution metadata (resolution / declared_type /
// method_name / arity) on internal_edges and external_calls. The fields are
// additive: a 1.0 fragment decodes with an empty resolution, which the stitcher
// treats as untrusted (fail-closed).
//
// 1.2 adds per-edge call-site data-flow (entry_call on internal_edges and
// external_calls) and full crypto-call identity + asset metadata on
// crypto_annotations. All additions are additive: a 1.1 fragment decodes with
// nil entry_call / nil CryptoCall fields, which the stitcher degrades to
// structural-only chains (safe fail-closed behavior).
//
// 1.3 adds customer-facing reachability projections: crypto_entry_points,
// supporting_calls, and display aliases for constructor symbols. Canonical
// function keys still use the internal <init> identity for joins.
//
// 1.6 adds resolved_receiver_type on internal_edges/external_calls: the
// concrete receiver type the producer's KB-contract/return-type inference
// resolved for an interface-dispatch call site, when available. The stitcher
// uses it to disambiguate a dispatch group that has more than one candidate
// target in closure, without changing the fail-closed default for call sites
// inference did not resolve. Additive: a 1.5 fragment decodes with an empty
// resolved_receiver_type, which the stitcher treats exactly as before.
//
// 1.7 adds internal_edges_compact plus internal_edge_strings. It carries the
// same internal edge fields as internal_edges, but indexes repeated strings and
// function keys to keep large dependency fragments small.
//
// 1.9 adds generic-erased function join signatures for Java source-type
// hierarchy stitching. 1.10 adds optional occurrence_key propagation for
// canonical crypto annotations. 1.11 adds resolved key-length call evidence.
// 1.12 adds the rule-vs-callgraph key-length conflict marker on that evidence.
//
// 1.14 adds entry_kind on a function the producing scan recognized as an entry
// point (main or framework_entry) and scan_metadata.entry_kinds, which says the
// producer recorded entry kinds at all. The stitched export reads them to give
// a chain root its root_kind and a finding its no_callers_only. A fragment
// without scan_metadata.entry_kinds (1.13 and older) decodes with no entry
// kinds and the stitcher claims neither for its functions.
//
// 1.15 adds returns_calls on a function: the callees of the calls whose result
// it returns. Annotate reads it to follow a crypto object a helper returns into
// the callers that configure it, as a scan does. A fragment without it (1.14
// and older) decodes with no returned calls, and annotate follows none.
//
// 1.16 adds what a detector needs to report a call site without the source:
// end_line on a call written over several lines (internal_edges,
// external_calls, and a 14th integer of internal_edges_compact, before
// entry_call), source_lines (the text of every line a call site covers, by
// file), and supertypes (each declared type's extends/implements clauses,
// resolved against the scan's known types where a wildcard import left
// candidates), and may_values on a source node (the string literals a
// variable written more than once is assigned). A 1.15 fragment decodes with
// none of them: a detector then
// reads the lines from the source, and a call's end line is its line.
//
// 1.17 adds constant_refs: every reference to a qualified constant
// (`Owner.NAME`, `a.b.Owner.NAME`, a name imported with `import static`) a
// function body writes, at any position, with its function, span, text and
// position kind (GraphFragmentConstantRef), and the lines they stand on in
// source_lines. A detector reports a rule that names a constant at the
// reference, as OpenGrep does, also outside a call: in a comparison, a `case`
// label, a return, an assignment, an initializer or an array. Every call is
// one site of internal_edges / external_calls (graph-algo-27). The compact
// edge keeps the 1.16 layout. A 1.16 fragment decodes with no constant_refs:
// a detector then sees a constant only as the argument of a call.
//
// 1.18 adds declarations and casts: the local variable and field declarations
// (GraphFragmentDeclaration: function, span of the whole declaration, declared
// type, name, initializer kind) and the casts of a call
// (GraphFragmentCast: function, span, target type, and where the call starts,
// the position of its site), with the lines they stand on in source_lines. A detector reports a rule
// that names a declared type (`T $X = $E;`) at the declaration and a rule that
// names a cast (`(T) $F.m(...)`) at the cast, as OpenGrep does, whatever the
// initializer is and wherever the cast value goes; and it tells a declaration
// from a plain assignment. Declarations of a primitive type, an array of one,
// `var`, String or Object are left out, as are casts of anything but a call
// (graph-algo-28). A 1.17 fragment decodes with
// neither: a detector then sees a declared type or a cast only in the
// expressions of a call's arguments and of a variable's initializer.
//
// 1.19 adds the compared operand to a constant reference in a comparison
// (compare, equals, case): the other operand of == / !=, the other side of
// equals, or the switch subject, as a parameter object (argument_expression,
// resolved_value, source_nodes) traced like a call argument. A detector
// reports such a constant only when the value reaching the comparison can be
// it. A 1.18 fragment decodes with no operands: a detector cannot tell, and
// reports the constant as before.
//
// 1.20 adds call_anchors: for every call a function makes, in the parser's
// order, the kind of its syntax node, the path of named nodes from the
// function to it and the fluent chain it is a link of
// (GraphFragmentCallAnchor), which pick and key the occurrence of an asset
// on that call. Re-detecting a stored fragment then gives each asset the occurrence
// key the scan gave it. A 1.19 fragment decodes with none: an asset on a call
// is then keyed by its function and position.
//
// 1.21 makes the fragment hold the call graph a scan's crypto export reads,
// so re-annotating a stored fragment writes what the scan wrote: a call
// anchor stands for every call, also one without a syntax node kind, and
// carries the call's target as the parser named it, its text, its argument
// expressions and their untraced provenance (GraphFragmentRawSource); a
// function carries its parameter names and return provenance
// (parameter_names, return_sources); and
// external_signatures holds the signatures the scan read for the methods
// outside the graph its calls target. A 1.20 fragment decodes with none.
//
// 1.22 writes once what 1.21 repeated, and scan_metadata says what was left
// out: the entry call of a call to several targets goes on the first of its
// edges (shared_entry_calls), a source location in the file of the function
// it belongs to leaves the file out (implicit_source_files), and a function
// leaves out the names its key gives and the display symbol and erased
// signature equal to its function name and canonical signature
// (derived_function_names), and an external call the target name its target
// key gives (derived_target_names). RestoreElided and ToFragment restore them
// (elide.go), so readers see the 1.21 form; the crypto sections are never
// elided. The graph is the same: a 1.21 fragment still reads as before. The
// 1.21 call data (anchored calls, parameter_names, return_sources,
// external_signatures) is written for Java and Python (no schema bump for
// Python), the languages the cards scanner re-annotates without source;
// another language's fragment reads as a 1.20 one there.
//
// 1.23 adds rebind_lines (GraphFragmentRebind) and scan_metadata.rebind_lines:
// for each variable a function passes to a call as a bare argument, the lines
// of its body that may give it another value or overwrite its buffer. The
// related-material pass reads them, without the source, to follow a buffer
// `random.nextBytes(iv)` fills to its use over lines source_lines does not
// hold. A 1.22 fragment decodes with none: the pass then reads the source,
// and without it follows a buffer only to a use on the next line.
//
// 1.24 adds abstract on a function declared without a body (a Java interface
// method that is not default or static, an abstract method) and
// scan_metadata.abstract_methods, which says the producer marked every such
// function (Java; Python from graph-algo-py-25). The stitch then reads a method that is not abstract as
// a body a call on its type may run, so an override of it is one more
// candidate, not the call's target. A 1.23 fragment decodes with none, and the
// stitch reads its methods as before.
//
// 1.25 adds service_providers: the classes the component registers for
// java.util.ServiceLoader in META-INF/services/<service type>, keyed by the
// service type (Java only). The stitch dispatches a call on a service type's
// method to the registered implementations present in the closure, a
// dispatch no call graph edge records. A 1.24 fragment decodes with none.
//
// 1.26 gives a Rust fragment its scope facts, as written: imports lists the
// bindings of each file's `use` and `extern crate` declarations (one per leaf
// of a grouped use), each with the declaration's span (start_col, end_col,
// end_line) and use tree (text), and items lists each file's inline modules,
// functions, impl blocks, traits, consts, statics, structs and `extern crate`
// items with their spans (GraphFragmentItem). A detector reads which `use`
// precedes a call in its scope, and which item encloses it, without the
// source. A 1.25 fragment decodes with neither: a Rust detector then cannot
// tell a call's scope. A Rust fragment also fills constant_refs (every path of
// two or more segments a body reads outside a callee, `acme::Mode::Cbc`) and
// declarations (one per name a `let` binds, any type, the statement's span),
// in their 1.17 and 1.18 forms.
//
// 1.27 adds type alias items to a Rust fragment's items (kind type, `type A
// = X;` at any depth, an impl's associated type definitions included), each
// with two trailing fields: the aliased type as written and the column of the
// `type` keyword (GraphFragmentItem). A 1.26 fragment decodes with none; a
// 1.26 reader rejects the longer item array, which is why this is a bump and
// not an optional field.
//
// 1.28 adds object_literals (Node): by file path, every outermost non-empty
// object expression of each scanned file, wherever it stands (a call
// argument, an initializer, a return value, an array element), with its span,
// its exact source text and the key of the function that holds it
// (GraphFragmentObjectLiteral). A detector matches a rule whose pattern is a
// bare object literal against the text, without the source. A 1.27 fragment
// decodes with none: such a rule then matches nothing.
//
// 1.29 adds property_reads (Node): by file path, every member expression of
// each scanned file whose value is read, not called (`acme.enums.hash.md5`,
// `cert.fingerprint`), outermost of its chain, in source order, with its span,
// its text, the key of the function that holds it and the target key a call
// of the expression would have in the same place, with that call's receiver
// and assigned variables (GraphFragmentPropertyRead). A detector matches a
// rule whose pattern is a bare member expression against them, without the
// source. A 1.28 fragment decodes with none: such a rule then matches nothing.
// 1.29 also gives an object literal the variable it is bound to
// (assigned_var, assign_start_col, assign_line), so a detector matches a rule
// that names the variable an object is assigned to (`$X = {...}`); a 1.28
// object decodes with none. 1.29 also adds candidate_modules to an external
// call and a property read (Node): the modules a receiver bound to an object
// merging several modules (Object.assign of modules, or a spread of them) may
// hold the member from, its key left caller-local, on a member of the
// variable or on any longer chain it heads (`H.sha256.create()`).
//
// 1.30 gives a Rust fragment two facts for rules that match operators and
// typed parameters. binary_exprs lists, by file path, every binary
// expression of each file's function bodies (`s * base`, `&s * &p`, `a ==
// b`), nested ones included, with its span, its operator, both operands as
// written with their spans, and the key of the function that holds it
// (GraphFragmentBinaryExpr). A fn item gains a trailing params field, its
// parameters as written, each with its pattern, its type, its span and
// whether it is a self receiver (GraphFragmentParam). A 1.29 fragment decodes
// with neither; a 1.29 reader rejects the longer item array of a fn with
// parameters, which is why this is a bump and not an optional field.
//
// 1.32 (1.31 is reserved for Node) gives a Go fragment its import specs
// under imports: by file path, each spec of each file's import declarations
// as written, its path as module and the name written before it as alias
// ("" for none, "." for a dot import, "_" for a blank one), with the spec's
// span. A detector tells a rule's `import $P "p"`, which binds only an
// aliased import, from `import "p"`. A 1.30 Go fragment decodes with none;
// such a rule then cannot tell the two apart.
//
// 1.33 widens a Rust fragment's constant_refs: a one-segment path a body
// reads as a value (anywhere but a pattern, a callee or a macro's name, since
// graph-algo-rs-9) whose name starts with an upper-case letter (`&X25519`
// after `use ring::agreement::X25519`, `SysRng`; the prelude's None, Some,
// Ok, Err and Self are left out), and the path of every struct literal, of
// one segment or more, in the position kind struct (`acme::Key { bits: 1 }`).
// The arrays keep their layout; a detector reads the version to know that a
// one-segment name it does not find is not read as a value, where a 1.30
// fragment leaves that undecided. (1.31 is reserved for Node.)
//
// 1.34 gives a Go fragment go_values: by file path, the composite literals
// (`tls.Config{MinVersion: v}`, `&rsa.PSSOptions{...}`), new(T) expressions
// and field stores (`cfg.CipherSuites = v`) of each file, nested ones
// included, each with its kind, span (a literal's `&` at addr_col), type as
// written and qualified, a store's receiver, its fields or elements as
// written with their spans, and the key of the function that holds it
// (GraphFragmentGoValue). A detector matches a rule written as such an
// expression without the source. A 1.33 fragment decodes with none: such a
// rule then matches nothing.
//
// 1.35 widens a Rust fragment's constant_refs with the paths written as a
// whole type, in the position kind type: a struct, tuple struct, union or
// variant field, a parameter, a return type (fn, trait or extern fn, closure,
// fn pointer), a let annotation, a cast's target, a type alias, an impl's
// self type, a const or static item's type, a generic argument (turbofish
// and `Item = T` included), the referent of a reference or pointer, a tuple
// or array element, a `dyn` or `impl` trait and a generic parameter's
// default; text is the path as written (`SysRng`, `acme::Key`), one-segment
// names under the rule of 1.33 (upper-case, not the prelude's types nor
// Self). A generic type's head (`Key<u8>`), a trait bound or where predicate
// (with its generic arguments), an impl's trait and a qualified path
// (`<X as T>::Out`) are left out: OpenGrep matches a path pattern in none.
// A reference in a fn's signature belongs to that fn; one outside any fn (a
// field, an alias, an impl header, a const's type, a trait or extern fn's
// signature) to the file's <varinit:<file>> function. The arrays keep their
// layout; a detector reads the version to know that a type it does not find
// is not written, where a 1.34 fragment lists no type at all.
const SchemaVersion = "graph-fragment-1.35"

// GraphAlgoVersion identifies the callgraph-CONSTRUCTION algorithm version. It
// is independent of the binary version (cf_version) and the wire schema
// (SchemaVersion): it bumps ONLY when callgraph/inference construction changes
// in a way that alters the structural graph. Consumers key their cached
// structural graphs on this so a routine binary release does not invalidate the
// cache — only a graph-affecting change does. Stamped into scan_metadata.
// TestGraphAlgoVersionGuard fails when the structural graph changes without a
// bump (see docs/ARCHITECTURE.md, Schema Versioning).
//
// It is the id of Java graphs and of every ecosystem without an id of its own
// (GraphAlgoVersionFor); Python graphs carry GraphAlgoVersionPython, Rust
// graphs GraphAlgoVersionRust, Node graphs GraphAlgoVersionNode and Go graphs
// GraphAlgoVersionGo (from graph-algo-39 on). Bump the id of the ecosystem
// whose graphs changed, never this one for another ecosystem's change: every stored Java graph under an
// old id is mined again.
//
// graph-algo-6: Go dependencies contribute only their imported packages, on
// top of the Go, Node and Python call resolution and Go interface dispatch
// changes merged since graph-algo-5.
//
// graph-algo-7: functions carry the entry kind the scan recognized (main or
// framework_entry), so a stitched export can give a chain root its root_kind.
// A structural graph cached under graph-algo-6 has none.
//
// graph-algo-8: Python symbols are no longer prefixed with the pyproject name.
//
// graph-algo-9: Python standard-library contracts type the objects hashlib,
// hmac, ssl and random.SystemRandom return, so a method chained on such a call
// (hashlib.sha256(d).hexdigest()) resolves to its stdlib class instead of a
// local name.
//
// graph-algo-10: a Node call on the WebCrypto API resolves to its WebIDL
// interface (SubtleCrypto.encrypt, Crypto.getRandomValues) under every
// spelling: the global crypto object, Node's crypto.webcrypto, and a subtle
// object held in a variable. It was an unbound member named after the calling
// module.
//
// graph-algo-11: a class assigned to Node exports (`module.exports = class Key
// {..}`, `exports.Key = class {..}`) declares its methods, which were missing.
//
// graph-algo-12: C++ calls on an `auto` variable take the type the producing
// call's contract returns, a direct initializer (`T v(f())`, `auto v{f()}`)
// binds its variable, and a templated callee is recorded without its template
// arguments (`std::make_unique<T>()` calls std::make_unique).
//
// graph-algo-13: a Rust call written inside a macro's parenthesized or
// bracketed expression arguments (`println!("{:?}", f(x))`) is an edge from
// the enclosing function.
//
// graph-algo-14: the default exclusions (node_modules, venv, build, ...) match
// only directories inside the project or dependency being graphed, so npm
// packages, packages in a virtualenv named venv and checkouts under such a
// directory enter the graph; and a Node call made through a package name
// (`require('pkg').fn()`, `import { fn } from 'pkg'`) is an edge to the
// function the package's entry module exports.
//
// graph-algo-15: functions carry returns_calls, the calls whose result they
// return, so annotate can follow a returned crypto object into its callers. A
// structural graph cached under graph-algo-14 has none.
//
// graph-algo-16: a Cargo dependency or workspace member is keyed by its
// library name, the name source writes (my_lib for package my-lib, or its
// [lib] name), so calls into crates with a dashed package name are edges. A
// structural graph cached under graph-algo-15 keys them my-lib and lacks
// those edges.
// graph-algo-17: Rust functions the entry-point catalog recognizes (actix-web,
// axum, Rocket, warp, tonic, poem and Lambda handlers) carry entry_kind
// framework_entry. A Rust structural graph cached under graph-algo-16 has
// none for them.
//
// graph-algo-18: Python handlers registered by call (Flask and Blueprint
// add_url_rule, FastAPI and APIRouter add_api_route and
// add_api_websocket_route, Starlette add_route and add_websocket_route), with
// the handler positional or as view_func=, endpoint= or route=, carry entry_kind
// framework_entry. A Python structural graph cached under graph-algo-17 has
// none for them.
//
// graph-algo-19: a Rust parameter list that names a lifetime splits into its
// parameters (the lifetime's quote used to merge the rest of the list into one
// parameter), and Go and Rust parameters carry their names. Parameter
// pass-through dispatch matches a call's receiver to a parameter by name, so a
// Go wrapper that forwards its parameter to an ambiguous interface call can now
// gain the bypass edge Java and Python graphs already had. Rust gains none yet:
// a Rust method's parameters count self while its call arguments do not, and
// Rust calls record no argument sources.
//
// graph-algo-20: a Python call argument that names a positional parameter of
// a module-level function, a string local or a module string constant carries
// its PARAMETER or VALUE source. A Python structural graph cached under
// graph-algo-19 has none for them.
//
// graph-algo-21: a Java `Enum.C.name()` (and `toString()` the enum does not
// override), a Python module string constant read from another module, and a
// Python Enum member's `.value` / `.name` fold to the string they denote, as a
// cross-class Java String constant already did. A structural graph cached
// under graph-algo-20 keeps them unresolved.
//
// graph-algo-22: a no-argument getter that returns a field set from a
// constructor parameter, called on `new T(..)` / `T(..)` or on a local bound
// once to one, folds to the constructor argument, in Java and Python; a Java
// enum constant's such getter folds to the constant's argument. Getters now
// carry that FIELD{PARAMETER} return source. A structural graph cached under
// graph-algo-21 keeps them unresolved.
//
// graph-algo-23: JavaScript and TypeScript calls carry argument provenance:
// literals, plain parameters, stable locals and module constants, members of
// TypeScript enums and enum-like objects, and exports of other project
// modules, folded like the Java and Python ones. A getter of a field the
// constructor sets carries the FIELD{PARAMETER} return source and folds to
// the constructor argument. A structural graph cached under graph-algo-22
// has none for Node.
//
// graph-algo-24: a Java, Python and JavaScript argument read from an
// environment variable, a system or java.util.Properties property, or a
// program argument (System.getenv, os.environ[..], process.env.X, args[i],
// sys.argv[i], ...) is no longer a value: its key or default stops resolving
// as the argument, and Python and Node gain a source node for the read,
// directly or through a local bound to one. A structural graph cached under
// graph-algo-23 has none of them.
//
// graph-algo-25: a method called on a local bound once, by a call, to a
// function whose every return constructs one class links exactly to that
// class's method (Go T{}/&T{}/new(T), Java and JavaScript new T(), Python
// T(), Rust T or T {..}, also inside Box/Arc/Rc::new) instead of the
// declared interface, trait or base-class method. A structural graph cached
// under graph-algo-24 keeps the declared-return dispatch.
//
// graph-algo-27: an edge the call graph recorded no per-site resolution for is
// exported once per call that makes it, each with its line, columns, method
// name and arity, and two calls of one callee on one line keep their own
// columns. Java functions carry the qualified constants their body references
// (constant_refs). A structural graph cached under graph-algo-26 has one site
// for such an edge, without method name or arity, and no constant references.
//
// graph-algo-28: Java functions carry their local variable and field
// declarations and their cast expressions (declarations, casts). A structural
// graph cached under graph-algo-27 has none.
//
// graph-algo-29: a Java constant reference in a comparison carries the
// operand it is compared with, traced. A structural graph cached under
// graph-algo-28 has none.
//
// graph-algo-30: inside a Java branch guarded by `v == X`, `X.equals(v)`,
// `v.equals(X)` or `case X` of `switch (v)`, a call argument v traces to X. A
// structural graph cached under graph-algo-29 traces it to v's declaration.
//
// graph-algo-31: a compared field operand carries the constants its class
// assigns to it. A structural graph cached under graph-algo-30 has none.
// graph-algo-32: fragments carry call_anchors (graph-fragment-1.20). A cards
// re-annotation without source needs them for occurrence keys, so a stored
// graph without them must be mined again.
//
// graph-algo-33: fragments carry every call with its target, text, arguments
// and their provenance, return provenance and external signatures
// (graph-fragment-1.21). A cards re-annotation without source needs them to
// write the crypto sections a scan writes, so a stored graph without them
// must be mined again.
//
// graph-algo-34: Java chain links on a value a dependency or the JDK returns
// are typed from the bytecode return types instead of left name_only.
//
// graph-algo-35: fragments carry rebind_lines (graph-fragment-1.23). A cards
// re-annotation without source needs them to report the related material a
// random fill reaches over lines that are no call site, so a stored graph
// without them must be mined again.
//
// graph-algo-36: fragments mark abstract methods (graph-fragment-1.24). The
// stitch cannot tell an empty concrete method from an abstract one without it,
// so a stored graph without it must be mined again.
//
// graph-algo-37: a Java cast argument has the cast's type when an overload is
// chosen, `setItem(name, (COSObjectable) null)` binds the COSObjectable
// overload, and a pass-through call whose argument types leave two overloads
// tied binds neither. A stored graph may hold the overload the cast rules out,
// or one picked by tie order, which changed from run to run.
//
// graph-algo-38: a Java type name a file imports by a single-type import (or
// declares) stays certain when the other types of that simple name are all top
// level, so dependency type JARs no longer untype chain links and overloads:
// sshj's SecurityUtils.getKeyFactory(..).generatePrivate(..) is typed again.
// A stored graph may hold the name_only calls and wider overload sets.
//
// graph-algo-39: fragments carry service_providers (graph-fragment-1.25). The
// stitch reaches a registered ServiceLoader implementation only through them,
// so a stored graph of a component that registers providers must be mined
// again (one without registrations is unchanged).
const GraphAlgoVersion = "graph-algo-39"

// GraphFragmentExport is the on-the-wire JSON shape emitted by
// `crypto-finder scan --export-graph-fragment` for a single component. It is a
// public contract; the application's scanner (crypto-finder's internal/scan)
// builds it from a callgraph, and any consumer decodes it into a Fragment via
// DecodeFragment.
type GraphFragmentExport struct {
	SchemaVersion        string                          `json:"schema_version"`
	ScanMetadata         GraphFragmentScanMetadata       `json:"scan_metadata"`
	Functions            []GraphFragmentFunction         `json:"functions"`
	InternalEdges        []GraphFragmentEdge             `json:"internal_edges,omitempty"`
	InternalEdgeStrings  []string                        `json:"internal_edge_strings,omitempty"`
	CompactInternalEdges []GraphFragmentCompactEdge      `json:"internal_edges_compact,omitempty"`
	ExternalCalls        []GraphFragmentExternal         `json:"external_calls,omitempty"`
	CryptoAnnotations    []GraphFragmentCryptoOp         `json:"crypto_annotations,omitempty"`
	SupportingCalls      []GraphFragmentSupporting       `json:"supporting_calls,omitempty"`
	CryptoEntryPoints    []GraphFragmentCryptoEntryPoint `json:"crypto_entry_points,omitempty"`
	// Supertypes maps each type declared in the scanned source, fully
	// qualified, to the supertypes its extends/implements clauses name. A
	// clause the producer could not resolve keeps its candidates joined by
	// `|`. A server stitching several components needs it to follow a call on
	// an interface in one component to its implementation in another.
	Supertypes map[string][]string `json:"supertypes,omitempty"`
	// ServiceProviders maps a service type, by binary name, to the
	// implementation classes the scanned source registers for
	// java.util.ServiceLoader in META-INF/services/<service type>, in file
	// order (1.25, Java). A stitch dispatches a call on the service type to
	// the registered implementations its closure holds.
	ServiceProviders map[string][]string `json:"service_providers,omitempty"`
	// SourceLines holds, by function file path, the text of every line an
	// exported call site of the scanned source covers (line to end_line),
	// without its line terminator. A detector reports a finding's matched
	// text from it, so re-detecting over a stored fragment needs no source.
	SourceLines map[string]map[int]string `json:"source_lines,omitempty"`
	// ConstantRefs are the qualified constants the scanned functions
	// reference (1.17), ordered by function, line and column.
	ConstantRefs []GraphFragmentConstantRef `json:"constant_refs,omitempty"`
	// Declarations are the local variables and fields the scanned functions
	// declare, and Casts their cast expressions (1.18), each ordered by
	// function, line and column.
	Declarations []GraphFragmentDeclaration `json:"declarations,omitempty"`
	Casts        []GraphFragmentCast        `json:"casts,omitempty"`
	// CallAnchors are the syntax-tree positions of the scanned functions'
	// calls (1.20), by function, each function's in the parser's order.
	CallAnchors []GraphFragmentCallAnchor `json:"call_anchors,omitempty"`
	// ExternalSignatures are the signatures the producer read (from the
	// platform or type-only dependencies) for the methods outside the graph
	// that its calls target, keyed by package|type|name#arity, in the
	// producer's order (1.21).
	ExternalSignatures map[string][]GraphFragmentExternalSignature `json:"external_signatures,omitempty"`
	// RebindLines are, by function and variable, the lines that may rebind a
	// variable the function passes to a call (1.23), ordered by function and
	// name.
	RebindLines []GraphFragmentRebind `json:"rebind_lines,omitempty"`
	// Imports are, by file path, the bindings of each scanned file's import
	// statements in source order (Python, optional with no schema bump; Rust
	// `use` and `extern crate` from 1.26; Node from graph-algo-node-3,
	// optional with no schema bump; Go import specs from 1.32). A rule that names an import, or reads an
	// argument through an import alias, needs them without the source.
	Imports map[string][]GraphFragmentImport `json:"imports,omitempty"`
	// GoValues are, by file path, the composite literals, new(T)
	// expressions and field stores of each scanned Go file in source order
	// (1.34).
	GoValues map[string][]GraphFragmentGoValue `json:"go_values,omitempty"`
	// ObjectLiterals are, by file path, the outermost object expressions of
	// each scanned file in source order (1.28, Node). The text of every object
	// is written in full, so the field can be large on big files.
	ObjectLiterals map[string][]GraphFragmentObjectLiteral `json:"object_literals,omitempty"`
	// PropertyReads are, by file path, the member expressions each scanned
	// file reads without calling them, in source order (1.29, Node), each
	// keyed as a call of the expression would be.
	PropertyReads map[string][]GraphFragmentPropertyRead `json:"property_reads,omitempty"`
	// Items are, by file path, the items each scanned Rust file declares at
	// any depth, in source order (1.26, Rust; type aliases from 1.27): the
	// scopes a call, a use or a declaration stands in.
	Items map[string][]GraphFragmentItem `json:"items,omitempty"`
	// BinaryExprs are, by file path, the binary expressions of each scanned
	// Rust file's function bodies, in source order (1.30, Rust).
	BinaryExprs map[string][]GraphFragmentBinaryExpr `json:"binary_exprs,omitempty"`
	// Exports maps each public dotted name of the component (Python; optional,
	// no schema bump) that names a declaration made elsewhere in it to that
	// declaration: a function key, or a class as `pkg.(Type)`. Re-exports
	// (`from .api_jwt import encode`), star imports, `__all__` and module-level
	// aliases (`encode = _jwt_global_obj.encode`) give such names. The stitch
	// joins a client's call of a public name (`jwt.encode`) through it.
	Exports map[string]string `json:"exports,omitempty"`
	// PublicPaths maps each name a package's `__init__.py` imports, spelled
	// as the package's attribute, to the module path that declares it
	// (Python; optional, no schema bump): "jwt.encode" -> "jwt.api_jwt.encode",
	// the call graph's PythonPublicPaths. A rule whose api names a public
	// path (`cryptography.x509.CertificateBuilder.<init>`) surfaces the
	// declaration as an entry point through it, as a scan does.
	PublicPaths map[string]string `json:"public_paths,omitempty"`
	// AttributeStores are the assignments to an attribute of an object the
	// scanned functions make (Python; optional, no schema bump), ordered by
	// function, line and column. A rule that names one
	// (an assignment to a named attribute) needs them without the source.
	AttributeStores []GraphFragmentAttributeStore `json:"attribute_stores,omitempty"`
	// LocalBindings are, for each local a function binds more than once with
	// a call among the values, the statements that bind it (Python,
	// graph-algo-py-35; optional, no schema bump), ordered by function, line
	// and column. A rule that ties a receiver to the call assigned to it
	// (`$X = Factory(...) ... $X.m(...)`) reads which assignment reaches the
	// use without the source.
	LocalBindings []GraphFragmentLocalBinding `json:"local_bindings,omitempty"`
}

// GraphFragmentImport is one binding of an import statement: `import a.b`
// (module), `import a.b as z` (module, alias), `from m import n as a`
// (module, name, alias), `from m import *` (name "*"). A relative module is
// resolved against the file's package. local marks an import inside a
// function or class body.
//
// A Rust binding (1.26) is written as the source writes it, paths unresolved:
// `use a::b::C as D` (module a::b, name C, alias D), `use a::b::*` (name "*"),
// a leaf of a grouped use `use a::{b::{self, C}}` (module a, name b; module
// a::b, name C), `extern crate a as z` (module a, alias z, no name). Each
// binding carries its declaration's span, visibility to semicolon (start_col,
// end_col 1-based and exclusive, end_line only when it spans lines), and its
// use tree as written (text: `a::{b::{self, C}}`, or `a as z`); local marks a
// declaration inside a function body.
//
// A Go binding (callgraph.GoImport, 1.32) is one import spec as written:
// module the import path, alias the name written before it ("" for none,
// "." for a dot import, "_" for a blank one), with the spec's span (start_col,
// end_col 1-based and exclusive, end_line only when it spans lines). A rule
// that binds only an aliased import (`import $P "p"`) needs the alias.
//
// A Node binding (callgraph.NodeImport, graph-algo-node-3) carries the module
// specifier as written ('node:crypto', './util'); name the export imported
// ("default" for a default import, "*" for a namespace import or star
// re-export, a dotted path for `require('m').a.b`), empty when the module
// itself is bound or nothing is; alias the local name when it differs from
// name; local an import inside a function or class body. kind (Node only,
// optional, no schema bump) is "" for an import declaration, "type" for a
// TypeScript type-only one, "require" for require() and `import x =
// require('m')`, "dynamic" for import() and "export" for `export ... from
// 'm'`. `import d from 'm'` is {name: default, alias: d}; `const x =
// require('m')` is {alias: x, kind: require}.
type GraphFragmentImport struct {
	Line     int    `json:"line"`
	Module   string `json:"module"`
	Name     string `json:"name,omitempty"`
	Alias    string `json:"alias,omitempty"`
	Kind     string `json:"kind,omitempty"`
	Local    bool   `json:"local,omitempty"`
	StartCol int    `json:"start_col,omitempty"`
	EndCol   int    `json:"end_col,omitempty"`
	EndLine  int    `json:"end_line,omitempty"`
	Text     string `json:"text,omitempty"`
}

// GraphFragmentObjectLiteral is one outermost object expression of a Node
// file (callgraph.NodeObjectLiteral, graph-fragment-1.28). An object inside
// another one's text, method bodies included, is not listed on its own; an
// empty object, a destructuring pattern and a TypeScript object type are not
// listed. The span follows the imports' convention: columns 1-based, end
// exclusive, end_line written only for an object that spans lines (a reader
// takes a missing end_line as line). text is the
// object's exact source, which a consumer parses itself; it can be large.
// caller_key is the key of the innermost function that holds the object, as
// its call sites carry it, or the module's `<module>` key at module level.
// assigned_var (1.29) is the variable the object is bound to, as a call's
// assigned_var is: the name of the `const`, `let` or `var` declarator it
// initializes, or the plain name an assignment writes it to; omitted for any
// other object. assign_start_col (1.29) is then the 1-based column that name
// starts at, and assign_line (1.29) its line, written only when it is not
// line (a declarator whose name and object stand on different lines).
type GraphFragmentObjectLiteral struct {
	Line           int    `json:"line"`
	StartCol       int    `json:"start_col"`
	EndLine        int    `json:"end_line,omitempty"`
	EndCol         int    `json:"end_col"`
	Text           string `json:"text"`
	CallerKey      string `json:"caller_key"`
	AssignedVar    string `json:"assigned_var,omitempty"`
	AssignStartCol int    `json:"assign_start_col,omitempty"`
	AssignLine     int    `json:"assign_line,omitempty"`
}

// GraphFragmentGoValue is one Go expression that builds or configures a
// value without a call the graph records (callgraph.GoValue,
// graph-fragment-1.34): kind "composite" (`T{...}`), "new" (`new(T)`) or
// "store" (`x.f = v`). The span is the expression's own (columns 1-based, end
// exclusive, end_line only when it spans lines); a composite literal's
// leading `&` is at addr_col. type_text is the type as written (a store's
// receiver's declared type), package and type qualify it as method keys do;
// receiver is a store's receiver as written; fields are a literal's elements
// in order (name empty for a positional one) or a store's field and value.
// function is the key of the function that holds it, empty outside any.
type GraphFragmentGoValue struct {
	Kind     string                      `json:"kind"`
	Line     int                         `json:"line"`
	StartCol int                         `json:"start_col"`
	EndCol   int                         `json:"end_col"`
	EndLine  int                         `json:"end_line,omitempty"`
	AddrCol  int                         `json:"addr_col,omitempty"`
	TypeText string                      `json:"type_text,omitempty"`
	Package  string                      `json:"package,omitempty"`
	Type     string                      `json:"type,omitempty"`
	Receiver string                      `json:"receiver,omitempty"`
	Fields   []GraphFragmentGoValueField `json:"fields,omitempty"`
	Function string                      `json:"function,omitempty"`
}

// GraphFragmentGoValueField is one element of a Go composite literal, or
// the field a store writes, with its value as written and the value's span.
type GraphFragmentGoValueField struct {
	Name     string `json:"name,omitempty"`
	Value    string `json:"value"`
	Line     int    `json:"line"`
	StartCol int    `json:"start_col"`
	EndCol   int    `json:"end_col"`
	EndLine  int    `json:"end_line,omitempty"`
}

// GraphFragmentPropertyRead is one member expression of a Node file whose
// value is read, not called (callgraph.NodePropertyRead,
// graph-fragment-1.29): `a.b.c` or `a['b']`, the outermost of its chain only,
// never a callee, an assignment or update target, a `delete` operand, a
// destructuring target or a TypeScript type. target_key is the key a call of
// the expression would target in the same place (module-qualified for an
// import, the declared class for a typed receiver, caller-local otherwise),
// method_name its last property, raw the expression as written, and
// receiver_var and assigned_var are set as that call's would be. caller_key
// is the key of the function that holds the read, or the module's `<module>`
// key at module level. The span follows the calls' convention: columns
// 1-based, end exclusive, end_line written only for a read that spans lines.
type GraphFragmentPropertyRead struct {
	CallerKey   string `json:"caller_key"`
	TargetKey   string `json:"target_key"`
	MethodName  string `json:"method_name"`
	Raw         string `json:"raw"`
	Line        int    `json:"line"`
	StartCol    int    `json:"start_col"`
	EndLine     int    `json:"end_line,omitempty"`
	EndCol      int    `json:"end_col"`
	ReceiverVar string `json:"receiver_var,omitempty"`
	AssignedVar string `json:"assigned_var,omitempty"`
	// CandidateModules (1.29) are the module specifiers a read on a merged
	// module object may read the member from, as an external call's
	// candidate_modules; target_key stays caller-local.
	CandidateModules []string `json:"candidate_modules,omitempty"`
}

// GraphFragmentItem is one item a Rust file declares (graph-fragment-1.26).
// JSON is a positional array: [line, start_col, end_col, kind, name,
// end_line, type, keyword_col].
//
// kind is mod (an inline module with a body), fn (a function with a body),
// impl, trait, const, static, struct, extern_crate or type (a type alias,
// 1.27, an impl's associated type definition included); name is the item's
// name as written, an impl block's self type without whitespace (`Kdf<H>`),
// an `extern crate`'s crate. The span is the item without its attributes,
// visibility to closing brace or semicolon, columns 1-based, end exclusive.
// end_line is written only for an item that spans lines, or as 0 before a
// type alias's fields. type (1.27) is a type alias's aliased type, the text
// after `=` as written, whitespace kept, and keyword_col the 1-based column
// of its `type` keyword on line (0 when the keyword is on another line); both
// are written only for a type alias, or as "" and 0 before a fn's params.
// params (1.30) are a fn's parameters in order, self receiver included
// (GraphFragmentParam), written only for a fn with parameters.
type GraphFragmentItem struct {
	Line, StartCol, EndCol, EndLine int
	Kind, Name                      string
	Type                            string
	KeywordCol                      int
	Params                          []GraphFragmentParam
}

// MarshalJSON encodes the item as a positional JSON array.
func (it GraphFragmentItem) MarshalJSON() ([]byte, error) {
	return AppendItemJSON(nil, it), nil
}

// AppendItemJSON appends the positional encoding of it to dst.
func AppendItemJSON(dst []byte, it GraphFragmentItem) []byte {
	dst = appendPositionalInts(append(dst, '['), it.Line, it.StartCol, it.EndCol)
	dst = appendPositionalStrings(dst, it.Kind, it.Name)
	if it.Type == "" && it.KeywordCol == 0 && len(it.Params) == 0 {
		return appendPositionalEnd(dst, it.EndLine)
	}
	dst = appendPositionalInts(dst, it.EndLine)
	dst = appendPositionalStrings(dst, it.Type)
	if len(it.Params) == 0 {
		return appendPositionalEnd(dst, it.KeywordCol)
	}
	dst = appendPositionalInts(dst, it.KeywordCol)
	dst = append(dst, '[')
	for i, param := range it.Params {
		if i > 0 {
			dst = append(dst, ',')
		}
		dst = AppendParamJSON(dst, param)
	}
	return append(dst, ']', ']')
}

// UnmarshalJSON decodes the positional item array.
func (it *GraphFragmentItem) UnmarshalJSON(data []byte) error {
	return decodePositional("item", data, 5, &it.Line, &it.StartCol, &it.EndCol, &it.Kind, &it.Name, &it.EndLine, &it.Type, &it.KeywordCol, &it.Params)
}

// GraphFragmentParam is one parameter of a Rust fn item (graph-fragment-1.30).
// JSON is a positional array: [line, start_col, end_col, pattern, type,
// end_line, self].
//
// pattern is the text before the `:` as written (`key`, `mut key`, `(a,
// b)`, `_`), or the whole receiver for a shorthand self (`self`, `mut self`,
// `&self`, `&'a mut self`); type is the text after the `:` as written,
// whitespace kept, "" for a shorthand self. The span is the parameter without
// its attributes, columns 1-based, end exclusive. end_line is written only
// for a parameter that spans lines, or as 0 before self. self is written,
// as true, only for a receiver: a shorthand self or a typed `self:
// Box<Self>`.
type GraphFragmentParam struct {
	Line, StartCol, EndCol, EndLine int
	Pattern, Type                   string
	Self                            bool
}

// MarshalJSON encodes the parameter as a positional JSON array.
func (p GraphFragmentParam) MarshalJSON() ([]byte, error) {
	return AppendParamJSON(nil, p), nil
}

// AppendParamJSON appends the positional encoding of p to dst.
func AppendParamJSON(dst []byte, p GraphFragmentParam) []byte {
	dst = appendPositionalInts(append(dst, '['), p.Line, p.StartCol, p.EndCol)
	dst = appendPositionalStrings(dst, p.Pattern, p.Type)
	if !p.Self {
		return appendPositionalEnd(dst, p.EndLine)
	}
	dst = appendPositionalInts(dst, p.EndLine)
	return append(dst, "true]"...)
}

// UnmarshalJSON decodes the positional parameter array.
func (p *GraphFragmentParam) UnmarshalJSON(data []byte) error {
	return decodePositional("param", data, 5, &p.Line, &p.StartCol, &p.EndCol, &p.Pattern, &p.Type, &p.EndLine, &p.Self)
}

// GraphFragmentBinaryExpr is one binary expression of a Rust function body
// (callgraph.RustBinaryExpr, graph-fragment-1.30). JSON is a positional
// array: [line, start_col, end_col, op, left, right, left_end_col,
// right_start_col, function, end_line, left_end_line, right_line].
//
// op is the operator as written (`*`, `+`, `==`, `&&`, ...), left and right
// the operands' source text as written. Every binary expression of a body is
// listed, an operand of another included (`a * b + c` gives two), and one in
// the arguments of an expression macro too. The span is the expression,
// columns 1-based, end exclusive. The left operand starts where the
// expression starts and ends at left_end_col, on left_end_line; the right
// operand starts at right_start_col, on right_line, and ends where the
// expression ends. function is the key of the innermost function whose span
// holds the expression, "" when none does. The three trailing lines are each
// 0 when they equal line, and written only up to the last that is not 0.
type GraphFragmentBinaryExpr struct {
	Line, StartCol, EndCol, EndLine int
	Op, Left, Right                 string
	LeftEndCol, LeftEndLine         int
	RightStartCol, RightLine        int
	Function                        string
}

// MarshalJSON encodes the expression as a positional JSON array.
func (e GraphFragmentBinaryExpr) MarshalJSON() ([]byte, error) {
	return AppendBinaryExprJSON(nil, e), nil
}

// AppendBinaryExprJSON appends the positional encoding of e to dst.
func AppendBinaryExprJSON(dst []byte, e GraphFragmentBinaryExpr) []byte {
	dst = appendPositionalInts(append(dst, '['), e.Line, e.StartCol, e.EndCol)
	dst = appendPositionalStrings(dst, e.Op, e.Left, e.Right)
	dst = appendPositionalInts(dst, e.LeftEndCol, e.RightStartCol)
	dst = appendPositionalStrings(dst, e.Function)
	lines := []int{e.EndLine, e.LeftEndLine, e.RightLine}
	for len(lines) > 0 && lines[len(lines)-1] == 0 {
		lines = lines[:len(lines)-1]
	}
	dst = appendPositionalInts(dst, lines...)
	dst[len(dst)-1] = ']'
	return dst
}

// UnmarshalJSON decodes the positional expression array.
func (e *GraphFragmentBinaryExpr) UnmarshalJSON(data []byte) error {
	return decodePositional("binary expression", data, 9, &e.Line, &e.StartCol, &e.EndCol, &e.Op, &e.Left, &e.Right, &e.LeftEndCol, &e.RightStartCol, &e.Function, &e.EndLine, &e.LeftEndLine, &e.RightLine)
}

// GraphFragmentExternalSignature is one signature of a method outside the
// graph (graph-fragment-1.21).
type GraphFragmentExternalSignature struct {
	ParameterTypes []string `json:"parameter_types"`
	ReturnType     string   `json:"return_type,omitempty"`
}

// GraphFragmentRawSource is the provenance of a value as the parser traced it
// within one function, before the export resolves it across calls
// (graph-fragment-1.21): a call argument's or a return value's. call_target
// is a function key; a location's file path is relative to the component
// root. guard, return_value and call_argument are the flow the value took.
type GraphFragmentRawSource struct {
	Type                string                   `json:"type"`
	Name                string                   `json:"name,omitempty"`
	DeclaredType        string                   `json:"declared_type,omitempty"`
	Value               string                   `json:"value,omitempty"`
	ParameterIndex      int                      `json:"parameter_index,omitempty"`
	CallTarget          string                   `json:"call_target,omitempty"`
	Location            *GraphFragmentSourceLoc  `json:"location,omitempty"`
	SourceNodes         []GraphFragmentRawSource `json:"source_nodes,omitempty"`
	MayValues           []string                 `json:"may_values,omitempty"`
	MayValuesExhaustive bool                     `json:"may_values_exhaustive,omitempty"`
	Guard               *GraphFragmentRawGuard   `json:"guard,omitempty"`
	ReturnValue         bool                     `json:"return_value,omitempty"`
	CallArgument        bool                     `json:"call_argument,omitempty"`
}

// GraphFragmentRawGuard is the branch a value is returned under: the
// function's parameter compared, the value it equals, or the default branch.
type GraphFragmentRawGuard struct {
	ParameterIndex int    `json:"parameter_index"`
	Value          string `json:"value,omitempty"`
	Default        bool   `json:"default,omitempty"`
}

// GraphFragmentDeclaration is one local variable or field declaration
// (graph-fragment-1.18), one per declared name. JSON is a positional array:
// [function, line, start_col, end_col, type, name, init, end_line].
//
// function addresses GraphFragmentExport.Functions (a field initializer
// belongs to its class's <clinit>); the span is the whole declaration,
// modifiers to semicolon, columns 1-based, end exclusive; type is the declared
// type as written, without whitespace; init is the initializer's kind: call
// (a method call or `new T(...)`), cast, null, literal, other, or "" for a
// declaration without one. end_line is written only for a declaration that
// spans lines.
type GraphFragmentDeclaration struct {
	Function                        int
	Line, StartCol, EndCol, EndLine int
	Type, Name, Init                string
}

// MarshalJSON encodes the declaration as a positional JSON array.
func (d GraphFragmentDeclaration) MarshalJSON() ([]byte, error) {
	return AppendDeclarationJSON(nil, d), nil
}

// AppendDeclarationJSON appends the positional encoding of d to dst.
func AppendDeclarationJSON(dst []byte, d GraphFragmentDeclaration) []byte {
	dst = appendPositionalInts(append(dst, '['), d.Function, d.Line, d.StartCol, d.EndCol)
	dst = appendPositionalStrings(dst, d.Type, d.Name, d.Init)
	return appendPositionalEnd(dst, d.EndLine)
}

// UnmarshalJSON decodes the positional declaration array.
func (d *GraphFragmentDeclaration) UnmarshalJSON(data []byte) error {
	return decodePositional("declaration", data, 7, &d.Function, &d.Line, &d.StartCol, &d.EndCol, &d.Type, &d.Name, &d.Init, &d.EndLine)
}

// GraphFragmentCast is one cast of a call, `(T) $F.m(...)` or `(T) new C(...)`
// (graph-fragment-1.18).
// JSON is a positional array:
// [function, line, start_col, end_col, type, inner_line, inner_col, end_line].
//
// function addresses GraphFragmentExport.Functions; the span is the cast
// expression, columns 1-based, end exclusive; type is the target type as
// written, without whitespace; inner_line and inner_col are where the call
// starts, read through parentheses (the line and start_col of that call's
// site). end_line is written only for a cast that spans lines.
type GraphFragmentCast struct {
	Function                        int
	Line, StartCol, EndCol, EndLine int
	Type                            string
	InnerLine, InnerCol             int
}

// MarshalJSON encodes the cast as a positional JSON array.
func (c GraphFragmentCast) MarshalJSON() ([]byte, error) {
	return AppendCastJSON(nil, c), nil
}

// AppendCastJSON appends the positional encoding of c to dst.
func AppendCastJSON(dst []byte, c GraphFragmentCast) []byte {
	dst = appendPositionalInts(append(dst, '['), c.Function, c.Line, c.StartCol, c.EndCol)
	dst = appendPositionalStrings(dst, c.Type)
	dst = appendPositionalInts(dst, c.InnerLine, c.InnerCol)
	return appendPositionalEnd(dst, c.EndLine)
}

// UnmarshalJSON decodes the positional cast array.
func (c *GraphFragmentCast) UnmarshalJSON(data []byte) error {
	return decodePositional("cast", data, 7, &c.Function, &c.Line, &c.StartCol, &c.EndCol, &c.Type, &c.InnerLine, &c.InnerCol, &c.EndLine)
}

// GraphFragmentCallAnchor is the syntax-tree position of one call a function
// makes (graph-fragment-1.20). JSON is a positional array:
// [function, line, start_col, end_col, kind, path, chain_id].
// 1.21 appends [callee, raw, arguments, argument_sources], written up to the
// last that is set (chain_id is then written, "" when none): the call's
// target as the parser named it (a function key), its text, its argument
// expressions and, per argument, their provenance (GraphFragmentRawSource).
//
// function addresses GraphFragmentExport.Functions; line and the columns
// (1-based, end exclusive) are the call's site, as on its edges; kind is the
// call's syntax node type (method_invocation, object_creation_expression,
// ...) and path its named nodes from the function, each <kind>[<index among
// the parent's named children>], joined by "/". A scan keys the occurrence
// of an asset on a call by the two. chain_id is the fluent chain the call
// itself is a link of, written only when it is one: an edge carries the
// chain of its line, also for a call that only sits on that line. A
// function's anchors are in the order the parser recorded its calls.
type GraphFragmentCallAnchor struct {
	Function               int
	Line, StartCol, EndCol int
	Kind, Path, ChainID    string
	Callee, Raw            string
	Arguments              []string
	ArgumentSources        [][]GraphFragmentRawSource
}

// MarshalJSON encodes the anchor as a positional JSON array.
func (a GraphFragmentCallAnchor) MarshalJSON() ([]byte, error) {
	return AppendCallAnchorJSON(nil, a), nil
}

// AppendCallAnchorJSON appends the positional encoding of a to dst.
func AppendCallAnchorJSON(dst []byte, a GraphFragmentCallAnchor) []byte {
	dst = appendPositionalInts(append(dst, '['), a.Function, a.Line, a.StartCol, a.EndCol)
	dst = appendPositionalStrings(dst, a.Kind, a.Path)
	last := 0
	for i, set := range [...]bool{a.ChainID != "", a.Callee != "", a.Raw != "", a.Arguments != nil, a.ArgumentSources != nil} {
		if set {
			last = i + 1
		}
	}
	if last >= 1 {
		dst = appendPositionalStrings(dst, a.ChainID)
	}
	if last >= 2 {
		dst = appendPositionalStrings(dst, a.Callee)
	}
	if last >= 3 {
		dst = appendPositionalStrings(dst, a.Raw)
	}
	if last >= 4 {
		arguments, _ := json.Marshal(a.Arguments) // strings always encode
		dst = append(append(dst, arguments...), ',')
	}
	if last >= 5 {
		sources, _ := json.Marshal(a.ArgumentSources) // plain values always encode
		dst = append(append(dst, sources...), ',')
	}
	return appendPositionalEnd(dst, 0)
}

// UnmarshalJSON decodes the positional anchor array.
func (a *GraphFragmentCallAnchor) UnmarshalJSON(data []byte) error {
	return decodePositional("call anchor", data, 6, &a.Function, &a.Line, &a.StartCol, &a.EndCol, &a.Kind, &a.Path, &a.ChainID,
		&a.Callee, &a.Raw, &a.Arguments, &a.ArgumentSources)
}

// appendPositionalInts appends each value followed by a comma.
func appendPositionalInts(dst []byte, values ...int) []byte {
	for _, n := range values {
		dst = strconv.AppendInt(dst, int64(n), 10)
		dst = append(dst, ',')
	}
	return dst
}

// appendPositionalStrings appends each value JSON-quoted, followed by a comma.
func appendPositionalStrings(dst []byte, values ...string) []byte {
	for _, s := range values {
		quoted, _ := json.Marshal(s) // a string always encodes
		dst = append(append(dst, quoted...), ',')
	}
	return dst
}

// appendPositionalEnd closes an array whose last element so far ends with a
// comma, writing endLine as an optional trailing field.
func appendPositionalEnd(dst []byte, endLine int) []byte {
	if endLine != 0 {
		dst = strconv.AppendInt(dst, int64(endLine), 10)
		return append(dst, ']')
	}
	dst[len(dst)-1] = ']'
	return dst
}

// decodePositional decodes a positional array of required fields followed by
// one optional trailing field into targets.
func decodePositional(what string, data []byte, required int, targets ...any) error {
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	if len(values) < required || len(values) > len(targets) {
		return fmt.Errorf("graphfrag: %s has %d fields, want %d to %d", what, len(values), required, len(targets))
	}
	for i := range values {
		if err := json.Unmarshal(values[i], targets[i]); err != nil {
			return fmt.Errorf("graphfrag: %s field %d: %w", what, i, err)
		}
	}
	return nil
}

// GraphFragmentConstantRef is one reference to a qualified constant
// (graph-fragment-1.17). JSON is a positional array:
// [function, line, start_col, end_col, text, context, end_line].
//
// function addresses GraphFragmentExport.Functions (the function whose body
// holds the reference); columns are 1-based, end exclusive; text is the
// reference without whitespace, a.b.Owner.NAME for a name imported with
// `import static`; context is the position kind: compare (operand of == or
// !=), equals (receiver or argument of equals), case (switch label), return,
// assign, init (initializer of a local or a field), array (array initializer
// element), arg (call or constructor argument), other, struct (a Rust struct
// literal's path, 1.33) or type (a path written as a Rust type, 1.35). end_line is written
// only for a reference that spans lines.
//
// 1.19 appends operand, written only for a reference in a comparison whose
// operand was traced (end_line is then written, 0 on one line): what the
// constant is compared with, as a call argument's parameter object.
type GraphFragmentConstantRef struct {
	Function                        int
	Line, StartCol, EndCol, EndLine int
	Text, Context                   string
	Operand                         *GraphFragmentParameter
}

// MarshalJSON encodes the reference as a positional JSON array.
func (r GraphFragmentConstantRef) MarshalJSON() ([]byte, error) {
	return AppendConstantRefJSON(nil, r), nil
}

// AppendConstantRefJSON appends the positional encoding of r to dst.
func AppendConstantRefJSON(dst []byte, r GraphFragmentConstantRef) []byte {
	dst = append(dst, '[')
	for _, n := range [...]int{r.Function, r.Line, r.StartCol, r.EndCol} {
		dst = strconv.AppendInt(dst, int64(n), 10)
		dst = append(dst, ',')
	}
	text, _ := json.Marshal(r.Text) // a string always encodes
	context, _ := json.Marshal(r.Context)
	dst = append(append(append(dst, text...), ','), context...)
	if r.EndLine != 0 || r.Operand != nil {
		dst = append(dst, ',')
		dst = strconv.AppendInt(dst, int64(r.EndLine), 10)
	}
	if r.Operand != nil {
		operand, _ := json.Marshal(r.Operand) // a parameter always encodes
		dst = append(append(dst, ','), operand...)
	}
	return append(dst, ']')
}

// UnmarshalJSON decodes the positional reference array.
func (r *GraphFragmentConstantRef) UnmarshalJSON(data []byte) error {
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	if len(values) < 6 || len(values) > 8 {
		return fmt.Errorf("graphfrag: constant ref has %d fields, want 6 to 8", len(values))
	}
	targets := []any{&r.Function, &r.Line, &r.StartCol, &r.EndCol, &r.Text, &r.Context, &r.EndLine, &r.Operand}
	for i := range values {
		if err := json.Unmarshal(values[i], targets[i]); err != nil {
			return fmt.Errorf("graphfrag: constant ref field %d: %w", i, err)
		}
	}
	return nil
}

// GraphFragmentCompactEdge is the graph-fragment-1.7 compact form of
// GraphFragmentEdge. JSON is a positional array:
// [caller_fn, callee_fn, line, resolution_s, declared_type_s, method_s, arity,
//
//	receiver_var_s, assigned_var_s, chain_id_s, start_col, end_col,
//	resolved_receiver_type_s, end_line, entry_call].
//
// end_line (1.16) is written only for a call that spans lines; a call on one
// line omits it, and its entry_call then takes its position, as before 1.16.
// Function indexes address GraphFragmentExport.Functions; string indexes
// address GraphFragmentExport.InternalEdgeStrings.
type GraphFragmentCompactEdge struct {
	Caller, Callee                       int
	Line                                 int
	Resolution, DeclaredType, MethodName int
	Arity                                int
	ReceiverVar, AssignedVar, ChainID    int
	StartCol, EndCol                     int
	ResolvedReceiverType                 int
	EndLine                              int
	EntryCall                            *GraphFragmentCallSite
}

// MarshalJSON encodes the compact edge as a positional JSON array.
func (e GraphFragmentCompactEdge) MarshalJSON() ([]byte, error) {
	values := []int{
		e.Caller, e.Callee, e.Line, e.Resolution, e.DeclaredType, e.MethodName,
		e.Arity, e.ReceiverVar, e.AssignedVar, e.ChainID, e.StartCol, e.EndCol,
		e.ResolvedReceiverType,
	}
	if e.EndLine != 0 {
		values = append(values, e.EndLine)
	}
	last := len(values) - 1
	for last >= 0 && values[last] == 0 {
		last--
	}
	if e.EntryCall != nil {
		last = len(values)
	}
	var buf bytes.Buffer
	buf.WriteByte('[')
	for i := 0; i <= last; i++ {
		if i > 0 {
			buf.WriteByte(',')
		}
		if i == len(values) {
			data, err := json.Marshal(e.EntryCall)
			if err != nil {
				return nil, err
			}
			buf.Write(data)
			continue
		}
		buf.WriteString(strconv.Itoa(values[i]))
	}
	buf.WriteByte(']')
	return buf.Bytes(), nil
}

// UnmarshalJSON decodes the compact positional edge array.
func (e *GraphFragmentCompactEdge) UnmarshalJSON(data []byte) error {
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	ints := []*int{
		&e.Caller, &e.Callee, &e.Line, &e.Resolution, &e.DeclaredType, &e.MethodName,
		&e.Arity, &e.ReceiverVar, &e.AssignedVar, &e.ChainID, &e.StartCol, &e.EndCol,
		&e.ResolvedReceiverType,
	}
	// end_line follows the 13 fixed integers when it is an integer; entry_call,
	// an object, comes last.
	if len(values) > len(ints) && compactFieldIsInt(values[len(ints)]) {
		ints = append(ints, &e.EndLine)
	}
	if len(values) > len(ints)+1 {
		return fmt.Errorf("graphfrag: compact edge has %d fields, want at most %d", len(values), len(ints)+1)
	}
	for i := 0; i < len(values) && i < len(ints); i++ {
		if err := json.Unmarshal(values[i], ints[i]); err != nil {
			return fmt.Errorf("graphfrag: compact edge field %d: %w", i, err)
		}
	}
	if len(values) == len(ints)+1 && len(values[len(ints)]) > 0 && string(values[len(ints)]) != "null" {
		var call GraphFragmentCallSite
		if err := json.Unmarshal(values[len(ints)], &call); err != nil {
			return fmt.Errorf("graphfrag: compact edge entry_call: %w", err)
		}
		e.EntryCall = &call
	}
	return nil
}

// compactFieldIsInt reports whether a positional compact-edge value is an
// integer rather than the entry_call object (or null).
func compactFieldIsInt(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) > 0 && (trimmed[0] == '-' || (trimmed[0] >= '0' && trimmed[0] <= '9'))
}

// GraphFragmentScanMetadata summarizes the scan that produced a graph-fragment
// export and the payload counts emitted for that component.
type GraphFragmentScanMetadata struct {
	Ecosystem   string `json:"ecosystem,omitempty"`
	RootModule  string `json:"root_module,omitempty"`
	ToolName    string `json:"tool_name,omitempty"`
	ToolVersion string `json:"tool_version,omitempty"`
	// GraphAlgoVersion is the callgraph-construction algorithm version of the
	// fragment's ecosystem (GraphAlgoVersionFor). Consumers cache structural
	// graphs keyed on it.
	GraphAlgoVersion  string `json:"graph_algo_version,omitempty"`
	RulesVersion      string `json:"rules_version,omitempty"`
	ExportedAt        string `json:"exported_at"`
	FunctionCount     int    `json:"function_count"`
	InternalEdges     int    `json:"internal_edge_count"`
	ExternalCalls     int    `json:"external_call_count"`
	CryptoOps         int    `json:"crypto_operation_count"`
	SupportingCalls   int    `json:"supporting_call_count,omitempty"`
	CryptoEntryPoints int    `json:"crypto_entry_point_count,omitempty"`
	// EntryKinds (1.14+) is true when the producer recorded entry_kind on the
	// functions it recognized as entry points. False means the fragment has no
	// entry-kind data, which differs from data that names no entry point.
	EntryKinds bool `json:"entry_kinds,omitempty"`
	// SharedEntryCalls, ImplicitSourceFiles, DerivedFunctionNames and
	// DerivedTargetNames (1.22)
	// say what the document left out for readers to restore (elide.go).
	// RestoreElided restores it and clears them.
	SharedEntryCalls     bool `json:"shared_entry_calls,omitempty"`
	ImplicitSourceFiles  bool `json:"implicit_source_files,omitempty"`
	DerivedFunctionNames bool `json:"derived_function_names,omitempty"`
	DerivedTargetNames   bool `json:"derived_target_names,omitempty"`
	// RebindLines (1.23+) is true when the producer wrote rebind_lines: a
	// function it does not list there then rebinds nothing.
	RebindLines bool `json:"rebind_lines,omitempty"`
	// AbstractMethods (1.24+) is true when the producer marked abstract every
	// function declared without a body: a function it does not mark then has
	// one.
	AbstractMethods bool `json:"abstract_methods,omitempty"`
}

// GraphFragmentFunction is one function declaration included in a component's
// graph-fragment export.
type GraphFragmentFunction struct {
	Key                           string   `json:"key"`
	FunctionName                  string   `json:"function_name"`
	CanonicalSignature            string   `json:"canonical_signature,omitempty"`
	ErasedSignature               string   `json:"erased_signature,omitempty"`
	CompatibleCanonicalSignatures []string `json:"compatible_canonical_signatures,omitempty"`
	Package                       string   `json:"package,omitempty"`
	Type                          string   `json:"type,omitempty"`
	Name                          string   `json:"name,omitempty"`
	FilePath                      string   `json:"file_path,omitempty"`
	StartLine                     int      `json:"start_line,omitempty"`
	EndLine                       int      `json:"end_line,omitempty"`
	ReturnType                    string   `json:"return_type,omitempty"`
	ParameterTypes                []string `json:"parameter_types,omitempty"`
	Visibility                    string   `json:"visibility,omitempty"`
	OwnerVisibility               string   `json:"owner_visibility,omitempty"`
	DisplaySymbol                 string   `json:"display_symbol,omitempty"`
	Aliases                       []string `json:"aliases,omitempty"`
	// EntryKind (1.14+) is "main" or "framework_entry" for a function the
	// producing scan recognized as an entry point: a program entry, or a method
	// a framework or the runtime calls, which no call edge leads to.
	EntryKind string `json:"entry_kind,omitempty"`
	// Abstract (1.24+) marks a function declared without a body, read with
	// scan_metadata.abstract_methods.
	Abstract bool `json:"abstract,omitempty"`
	// ReturnsCalls (1.15+) lists, sorted, the callee keys of the calls whose
	// result the function returns (`return f()`, or `x = f(); return x`), each
	// a callee the function calls exactly once. Annotate reads it to follow a
	// returned crypto object into its callers. Absent when the function returns
	// no such call or the producer did not record it (1.14 and older).
	ReturnsCalls []string `json:"returns_calls,omitempty"`
	// ParameterNames (1.21+) are the names of the function's parameters, in
	// order.
	ParameterNames []string `json:"parameter_names,omitempty"`
	// ReturnSources (1.21+) is the provenance of the values the function
	// returns, as the parser traced it.
	ReturnSources  []GraphFragmentRawSource `json:"return_sources,omitempty"`
	InferredReturn json.RawMessage          `json:"-"`
}

// GraphFragmentCallSite carries the per-edge call-site invocation detail: the
// arguments the caller passed to the callee at this edge, mirroring the
// schema-6.0 entry_call shape. It lives on the edge (not the function) because
// entry_call describes the caller→callee invocation.
type GraphFragmentCallSite struct {
	// Line is the source line of the call expression in the caller.
	Line int `json:"line,omitempty"`
	// Parameters carries the resolved argument data-flow for each positional
	// argument in the call.
	Parameters []GraphFragmentParameter `json:"parameters,omitempty"`
}

// GraphFragmentParameter mirrors the schema-6.0 callGraphParameter shape so the
// stitcher can emit entry_call.parameters[] verbatim.
type GraphFragmentParameter struct {
	// ParameterIndex is the 0-based position of this argument in the call.
	ParameterIndex int `json:"parameter_index"`
	// Keyword is the name a Python keyword argument (`algorithm="HS256"`)
	// passes it under; ParameterIndex is then its place in the call's
	// argument list, not a position of the callee's parameters, and
	// ArgumentExpression is the value alone. Empty for a positional argument.
	Keyword string `json:"keyword,omitempty"`
	// Type is the declared parameter type in the callee's signature.
	Type string `json:"type,omitempty"`
	// VariableName is the local variable name if the argument was a simple identifier.
	VariableName string `json:"variable_name,omitempty"`
	// ArgumentExpression is the raw source text of the argument expression.
	ArgumentExpression string `json:"argument_expression,omitempty"`
	// ResolvedValue is a simplified literal value when it can be statically resolved.
	ResolvedValue string `json:"resolved_value,omitempty"`
	// SourceNodes carries the data-flow provenance for this argument.
	SourceNodes []GraphFragmentSourceNode `json:"source_nodes,omitempty"`
}

// GraphFragmentSourceNode is the recursive data-flow provenance node, mirroring
// the schema-6.0 exportSourceNode shape. The SourceNodes field makes this type
// recursive so PARAMETER→CALL_RESULT chains are fully preserved.
type GraphFragmentSourceNode struct {
	// Type classifies the origin: VALUE, VARIABLE, FIELD, PARAMETER, CALL_RESULT, EXPRESSION.
	Type string `json:"type"`
	// Name is the variable/field/parameter name.
	Name string `json:"name,omitempty"`
	// DeclaredType is the type if known.
	DeclaredType string `json:"declared_type,omitempty"`
	// Value is the actual value for VALUE nodes.
	Value string `json:"value,omitempty"`
	// ParameterIndex is set for PARAMETER nodes.
	ParameterIndex *int `json:"parameter_index,omitempty"`
	// CallTarget is set for CALL_RESULT nodes — the function that produced the value.
	CallTarget string `json:"call_target,omitempty"`
	// Location is where this source is defined.
	Location *GraphFragmentSourceLoc `json:"location,omitempty"`
	// SourceNodes traces where THIS node's value came from (recursive).
	SourceNodes []GraphFragmentSourceNode `json:"source_nodes,omitempty"`
	// MayValues lists the string literals a variable written more than once
	// is assigned (1.16+). It has no single source, so SourceNodes stays
	// empty; a taint detector reads each of these as a value it may hold.
	MayValues []string `json:"may_values,omitempty"`
	// MayValuesExhaustive says every assignment of the variable is one of
	// MayValues: it always holds a string constant.
	MayValuesExhaustive bool `json:"may_values_exhaustive,omitempty"`
}

// GraphFragmentSourceLoc identifies a position in source code.
type GraphFragmentSourceLoc struct {
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"`
	// NoFile (1.22, with implicit_source_files) marks a location with a line
	// and no file, which a reader would otherwise put in its function's file.
	// RestoreElided clears it.
	NoFile bool `json:"no_file,omitempty"`
}

// GraphFragmentCryptoCall carries the identity and argument data-flow of the
// matched crypto invocation, mirroring the schema-6.0 callGraphCalledFunction
// shape. It is a dedicated type (not reusing GraphFragmentCallSite) so it can
// carry function identity fields alongside the call-site parameters.
type GraphFragmentCryptoCall struct {
	// FunctionName is the fully qualified function name of the matched crypto call.
	FunctionName string `json:"function_name,omitempty"`
	// CanonicalSignature is the canonical function signature.
	CanonicalSignature string `json:"canonical_signature,omitempty"`
	// ReturnType is the declared return type.
	ReturnType string `json:"return_type,omitempty"`
	// ParameterTypes lists the declared parameter types.
	ParameterTypes []string `json:"parameter_types,omitempty"`
	// DisplaySymbol is the customer-facing symbol, with constructor aliases.
	DisplaySymbol string `json:"display_symbol,omitempty"`
	// Aliases are alternate customer-facing names.
	Aliases []string `json:"aliases,omitempty"`
	// Line is the source line of the matched crypto call.
	Line int `json:"line,omitempty"`
	// Parameters carries the resolved argument data-flow for each positional argument.
	Parameters []GraphFragmentParameter `json:"parameters,omitempty"`
	// ParameterRoles is the issue-103 (WU3) contracts-KB-derived per-parameter
	// role/contribution list, index-aligned with ParameterTypes.
	ParameterRoles []GraphFragmentParameterRole `json:"parameter_roles,omitempty"`
	// ResolvedKeyLength is contract-scoped raw key-length evidence preserved for
	// stitch rendering on supporting_call declarations. Terminal crypto
	// annotations omit it. Bits is omitted when the source value is unresolved.
	ResolvedKeyLength *ResolvedKeyLength `json:"resolved_key_length,omitempty"`
}

// GraphFragmentRoleProvenance explains where a method_role came from: a
// direct contract match, or inherited from same-class sibling assets
// (issue-103 WU2).
type GraphFragmentRoleProvenance struct {
	Kind               string                      `json:"kind,omitempty"`
	ContractMethod     string                      `json:"contract_method,omitempty"`
	InheritedFrom      string                      `json:"inherited_from,omitempty"`
	Inherited          *GraphFragmentInheritedRole `json:"inherited,omitempty"`
	InheritedAmbiguous bool                        `json:"inherited_ambiguous,omitempty"`
}

// GraphFragmentInheritedRole carries the algorithm_family/primitive a
// synthesized operation entry point inherited from a same-class sibling asset.
type GraphFragmentInheritedRole struct {
	AlgorithmFamily string `json:"algorithm_family,omitempty"`
	Primitive       string `json:"primitive,omitempty"`
}

// GraphFragmentParameterRole is one index-aligned parameter role/contribution
// entry (issue-103 WU3).
type GraphFragmentParameterRole struct {
	Index       int                        `json:"index"`
	Name        string                     `json:"name,omitempty"`
	Role        string                     `json:"role"`
	Contributes *GraphFragmentContribution `json:"contributes,omitempty"`
}

// GraphFragmentContribution names the property a parameter contributes to
// and the derivation strategy a downstream consumer applies.
type GraphFragmentContribution struct {
	Property         string `json:"property,omitempty"`
	Derivation       string `json:"derivation,omitempty"`
	ArgumentProperty string `json:"argument_property,omitempty"`
}

// GraphFragmentMatchedOp records the matched operation kind, symbol, and
// expression for a crypto finding — the same fields carried by the schema-6.0
// matched_operation shape.
type GraphFragmentMatchedOp struct {
	// Kind is the operation kind: "call", "type_usage", or "expression".
	Kind string `json:"kind,omitempty"`
	// Symbol is the fully qualified API symbol (e.g., "javax.crypto.Cipher.getInstance").
	Symbol string `json:"symbol,omitempty"`
	// Expression is the raw source expression that matched.
	Expression string `json:"expression,omitempty"`
	// Line is the source line of the matched expression.
	Line int `json:"line,omitempty"`
}

// GraphFragmentEdge is one internal (intra-component) call edge plus the
// resolution metadata that lets a consumer decide whether to traverse it.
type GraphFragmentEdge struct {
	CallerKey    string `json:"caller_key"`
	CalleeKey    string `json:"callee_key"`
	Line         int    `json:"line,omitempty"`
	Resolution   string `json:"resolution"`
	DeclaredType string `json:"declared_type,omitempty"`
	MethodName   string `json:"method_name,omitempty"`
	Arity        int    `json:"arity,omitempty"`
	// ReceiverVar/AssignedVar/ChainID carry the call-site object identity (1.4+)
	// for cache-side object-lifecycle re-derivation. Empty on schema < 1.4.
	ReceiverVar string `json:"receiver_var,omitempty"`
	AssignedVar string `json:"assigned_var,omitempty"`
	ChainID     string `json:"chain_id,omitempty"`
	// StartCol/EndCol carry the 1-based call-expression columns (start inclusive,
	// end exclusive) so the annotate path runs the same column-intersection
	// terminal selection as the live exporter (1.4+). 0 on schema < 1.4.
	StartCol int `json:"start_col,omitempty"`
	EndCol   int `json:"end_col,omitempty"`
	// EndLine is the line EndCol is on, for a call written over several
	// lines (1.16+). 0 for a call on one line, and on schema < 1.16.
	EndLine int `json:"end_line,omitempty"`
	// EntryCall carries the call-site argument data-flow for this edge (1.2+).
	// Nil on fragments exported with schema < 1.2.
	EntryCall *GraphFragmentCallSite `json:"entry_call,omitempty"`
	// ResolvedReceiverType is the concrete receiver type resolved by KB-contract
	// or return-type inference for this call site (1.6+). Empty when inference
	// did not resolve a concrete type, or on fragments exported with schema < 1.6.
	ResolvedReceiverType string `json:"resolved_receiver_type,omitempty"`
}

// GraphFragmentExternal is one external (cross-component) call edge plus its
// resolution metadata.
type GraphFragmentExternal struct {
	CallerKey                string `json:"caller_key"`
	TargetKey                string `json:"target_key"`
	TargetFunctionName       string `json:"target_function_name,omitempty"`
	TargetCanonicalSignature string `json:"target_canonical_signature,omitempty"`
	Raw                      string `json:"raw,omitempty"`
	Line                     int    `json:"line,omitempty"`
	Resolution               string `json:"resolution"`
	DeclaredType             string `json:"declared_type,omitempty"`
	MethodName               string `json:"method_name,omitempty"`
	Arity                    int    `json:"arity,omitempty"`
	// ReceiverVar/AssignedVar/ChainID carry the call-site object identity (1.4+)
	// for cache-side object-lifecycle re-derivation. Empty on schema < 1.4.
	ReceiverVar string `json:"receiver_var,omitempty"`
	AssignedVar string `json:"assigned_var,omitempty"`
	ChainID     string `json:"chain_id,omitempty"`
	// StartCol/EndCol carry the 1-based call-expression columns (start inclusive,
	// end exclusive) so the annotate path runs the same column-intersection
	// terminal selection as the live exporter (1.4+). 0 on schema < 1.4.
	StartCol int `json:"start_col,omitempty"`
	EndCol   int `json:"end_col,omitempty"`
	// EndLine is the line EndCol is on, for a call written over several
	// lines (1.16+). 0 for a call on one line, and on schema < 1.16.
	EndLine int `json:"end_line,omitempty"`
	// EntryCall carries the call-site argument data-flow for this edge (1.2+).
	// Nil on fragments exported with schema < 1.2.
	EntryCall *GraphFragmentCallSite `json:"entry_call,omitempty"`
	// ResolvedReceiverType is the concrete receiver type resolved by KB-contract
	// or return-type inference for this call site (1.6+). Empty when inference
	// did not resolve a concrete type, or on fragments exported with schema < 1.6.
	ResolvedReceiverType string `json:"resolved_receiver_type,omitempty"`
	// CandidateModules (1.29, Node) lists, sorted and unique, the module
	// specifiers the call's receiver may hold the member from when it is, or
	// is a chain headed by (`H.sha256.create()`), a variable bound to an
	// object merging several modules
	// (`Object.assign({}, require('a'), require('b'))`, `{ ...a, ...b }`), the
	// graph's FunctionCall.CandidateModules. target_key stays caller-local,
	// since it cannot name one module; the candidates are the modules the
	// receiver may hold the member from. Omitted otherwise.
	CandidateModules []string `json:"candidate_modules,omitempty"`
}

// GraphFragmentCryptoOp is one crypto finding annotation attached to a function
// in the exported graph fragment.
type GraphFragmentCryptoOp struct {
	FunctionKey   string `json:"function_key,omitempty"`
	FindingID     string `json:"finding_id,omitempty"`
	OccurrenceKey string `json:"occurrence_key,omitempty"`
	RuleID        string `json:"rule_id,omitempty"`
	Symbol        string `json:"symbol,omitempty"`
	Expression    string `json:"expression,omitempty"`
	FilePath      string `json:"file_path,omitempty"`
	StartLine     int    `json:"start_line,omitempty"`
	EndLine       int    `json:"end_line,omitempty"`
	// CryptoCall carries the identity and argument data-flow of the matched
	// crypto invocation (1.2+). Nil on fragments exported with schema < 1.2.
	CryptoCall *GraphFragmentCryptoCall `json:"crypto_call,omitempty"`
	// OID is the Object Identifier for the cryptographic algorithm (1.2+).
	OID string `json:"oid,omitempty"`
	// Metadata is the raw asset metadata block from the scanner (1.2+).
	// It is stored verbatim so the stitcher can pass it through to the render
	// layer without re-serialization.
	Metadata json.RawMessage `json:"metadata,omitempty"`
	// Source indicates how the finding was discovered: "direct" or "indirect" (1.2+).
	Source string `json:"source,omitempty"`
	// PURL is the optional package URL promoted from direct rule metadata.
	PURL string `json:"purl,omitempty"`
	// MatchedOperation records the kind/symbol/expression of the matched crypto
	// operation (1.2+). Mirrors the schema-6.0 matched_operation shape.
	MatchedOperation *GraphFragmentMatchedOp `json:"matched_operation,omitempty"`
	// SupportingCallIDs are the supporting_id values of THIS finding's
	// object-lifecycle supporting calls (1.5+) — the precise finding->supporting
	// foreign key. Sorted, de-duplicated. Each id resolves to a top-level
	// supporting_calls entry; the stitch-built callgraph surfaces these as
	// finding_graph.supporting_call_ids and the served API as a per-asset
	// breadcrumb.
	SupportingCallIDs []string `json:"supporting_call_ids,omitempty"`
}

// GraphFragmentSupporting is a non-finding crypto-adjacent call such as
// builder/config/lifecycle/context setup. It is useful for reachability context
// but must not inflate crypto finding counts.
type GraphFragmentSupporting struct {
	SupportingID       string                   `json:"supporting_id"`
	FunctionKey        string                   `json:"function_key,omitempty"`
	FunctionName       string                   `json:"function_name,omitempty"`
	CanonicalSignature string                   `json:"canonical_signature,omitempty"`
	DisplaySymbol      string                   `json:"display_symbol,omitempty"`
	Aliases            []string                 `json:"aliases,omitempty"`
	Category           string                   `json:"category,omitempty"`
	FilePath           string                   `json:"file_path,omitempty"`
	StartLine          int                      `json:"start_line,omitempty"`
	EndLine            int                      `json:"end_line,omitempty"`
	MatchedOperation   *GraphFragmentMatchedOp  `json:"matched_operation,omitempty"`
	SupportingCall     *GraphFragmentCryptoCall `json:"supporting_call,omitempty"`
	Metadata           json.RawMessage          `json:"metadata,omitempty"`
}

// GraphFragmentCryptoEntryPoint is the catalog/customer stitch index: if a
// caller reaches this function key (or one of its aliases), these findings and
// supporting calls become reachable.
type GraphFragmentCryptoEntryPoint struct {
	FunctionKey              string                                 `json:"function_key"`
	FunctionName             string                                 `json:"function_name,omitempty"`
	CanonicalSignature       string                                 `json:"canonical_signature,omitempty"`
	DisplaySymbol            string                                 `json:"display_symbol,omitempty"`
	Aliases                  []string                               `json:"aliases,omitempty"`
	ReturnType               string                                 `json:"return_type,omitempty"`
	ParameterTypes           []string                               `json:"parameter_types,omitempty"`
	Visibility               string                                 `json:"visibility,omitempty"`
	OwnerVisibility          string                                 `json:"owner_visibility,omitempty"`
	ReachableFindings        []GraphFragmentReachableFinding        `json:"reachable_findings,omitempty"`
	ReachableSupportingCalls []GraphFragmentReachableSupportingCall `json:"reachable_supporting_calls,omitempty"`
	// MethodRole, RoleProvenance, ParameterRoles are issue-103 (WU2/WU3)
	// additions carried through the fragment so the stitch/served path can
	// enrich the reachability-projected crypto_entry_points entry by
	// function_key (see stitch.go indexOperationEntryPoints).
	MethodRole     string                       `json:"method_role,omitempty"`
	RoleProvenance *GraphFragmentRoleProvenance `json:"role_provenance,omitempty"`
	ParameterRoles []GraphFragmentParameterRole `json:"parameter_roles,omitempty"`
}

// GraphFragmentReachableFinding is a finding reachable from an entrypoint.
type GraphFragmentReachableFinding struct {
	FindingID  string `json:"finding_id"`
	ChainDepth int    `json:"chain_depth"`
	// Route names one minimum-length route from the entry point to the function
	// holding the finding, as indexes into Functions, entry-point-first and
	// inclusive of both ends — so its length equals ChainDepth. Indexes rather
	// than keys for the same reason the compact edges use them: on a dense
	// component the keys cost an order of magnitude more than the graph they
	// describe. Absent on fragments exported before graph-fragment-1.13, and on
	// any entry point whose route the producer could not name; ChainDepth stays
	// the answer either way.
	Route           []int  `json:"route,omitempty"`
	FindingGraphRef string `json:"finding_graph_ref,omitempty"`
}

// GraphFragmentReachableSupportingCall is a supporting call reachable from an
// entrypoint.
type GraphFragmentReachableSupportingCall struct {
	SupportingID      string `json:"supporting_id"`
	ChainDepth        int    `json:"chain_depth"`
	SupportingCallRef string `json:"supporting_call_ref,omitempty"`
}
