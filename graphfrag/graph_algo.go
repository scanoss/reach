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
// graph-algo-rs-10: constant_refs also list each path written as a whole type
// where OpenGrep matches a path pattern, in a new position kind type (`rng:
// SysRng`, `-> acme::Key`, `let k: acme::Key`, `Vec<SysRng>`, `x as Key`,
// `impl acme::Key {}`), one-segment names under the rule of rs-8 (upper-case
// first letter, not the prelude's nor Self). A fn's signature references are
// its own; those outside any fn (a field, an alias, an impl's self type, a
// const's type, a trait or extern fn's signature) are the file's
// `<varinit:<file>>`, which a file with any now has (graph-fragment-1.35): a
// stored rs-9 graph has none.
// graph-algo-rs-11: a free function defined more than once in one file
// (variants under mutually exclusive `#[cfg]` attributes) keeps the calls,
// references and declarations of every body under its one key, the first
// body's position kept; a stored rs-10 graph has only the last body's.
// graph-algo-rs-12: items also list, as kind block, each block of a function
// body that declares a use or an `extern crate` of its own (a match arm's,
// a branch's, a nested, closure, async or unsafe block), so a reader scopes
// such a use to its block; a stored rs-11 graph lists none.
// graph-algo-rs-13: a Rust graph carries the public paths a crate's `pub use`
// items re-export its types under (public_type_paths), and its call anchors
// carry the parser's calls (callee, text, arguments and their provenance) as
// Java, Python, Go, Node and C ones do. A stored rs-12 graph lacks both:
// annotate surfaces a rule's api named by its public path only through the
// first, and rebuilds a call's text and argument provenance only from the
// second.
// graph-algo-rs-14: a fragment's exports map the public paths a crate gives
// its functions, types and modules (CallGraph.RustExports: `pub use` items,
// renames, globs and re-exported modules followed to the declaring module,
// `pub type` aliases, a dependency's re-exported item under that crate's own
// key, and each module at its own path) to their declarations, so the stitch
// joins a consumer's call written with them (`jsonwebtoken::decode`,
// `ring::signature::RsaKeyPair`, `use ring::hmac; hmac::sign`,
// `age::scrypt::Identity`, `MlKem768::generate`, `rand::rngs::OsRng`); and a
// crate whose package name carries a dash records its crate-wide facts under
// its library name (`acme_sign::..`, the name its function keys carry), not
// the package name. A stored rs-13 graph has no exports, and a dashed crate's
// re-exported types resolved nowhere.
// graph-algo-rs-15: a crate's calls reach what its trait machinery runs. The
// trait hierarchy is the fragment's supertypes (`impl Trait for Type` makes
// Trait a supertype of Type, `trait A: B` makes B one of A, and a blanket
// `impl<G: Bound> Trait for G` makes the parameter's owner one of Bound), a
// trait's required method is an abstract function, and the stitch reads a
// Rust type's method as an implementation of its traits' (age-core's
// `ChaCha20Poly1305::encrypt` runs aead's blanket `Aead::encrypt`, and the
// default `encrypt_in_place` dispatches to the cipher's
// `encrypt_in_place_detached`). `<Type as Trait>::Assoc::f(..)` is keyed f
// on the type the crate's own impl, else the knowledge base's
// trait_associated_types, names for Assoc; the variable of a `for` over an
// `impl Iterator<Item = T>` holds T (age's `for recipient in recipients`
// calls `Recipient::wrap_file_key`); `s.parse::<T>()` also calls
// `T::from_str`; a function passed as a value is reached by the function
// that passes it, unless a framework registration makes it an entry point;
// and a call the crate makes to its own item through a public path
// (`crate::ssh::Identity::from_buffer` under `pub use identity::Identity;`)
// also reaches the declaration. A stored rs-14 graph has none of these
// edges.
const GraphAlgoVersionRust = rustGraphAlgoPrefix + "15"

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
// graph-algo-node-7: two functions of one module that shared a key both stay
// in the graph (the first one's calls were dropped). A function assigned as
// a property of a plain identifier is keyed by that object as owner
// (`hotp.gen = function` and `totp.gen = function` are m.(hotp).gen and
// m.(totp).gen, were both m.gen), and a member call on the module binding
// targets it (`hotp.gen(k)` calls m.(hotp).gen, was unbound). Of the others
// sharing a key, the last module-level one (else the last one) keeps it and
// each other one takes its start as a suffix (`sign@3:10`). A module without
// such a pair keys as node-6 did. Fragments list in `exports` each key a
// caller spells through one of the package's specifiers (`acme.sign`,
// `acme/sub.go`, `@acme/sign.sign`, `acme.default`, `notp.hotp.gen`) that
// names a function the package declares under another key
// (`acme/index.sign`), from package.json `exports`, `main` or index, directory
// indexes and re-exporting files; a stitch joins an application's call into
// the package through it, where a node-6 fragment has no exports. A package
// call linked in one build also follows `var o = {}; o.f = function` behind
// `module.exports = { o }`.
// Also in node-7: a name the file binds to the WebCrypto object keys its
// calls on the interface, as the global spelling does: `const { crypto } =
// globalThis`, `const c = self.crypto`, `const c = nodeCrypto.webcrypto`,
// `const { webcrypto } = nodeCrypto`, a guarded read with a null, undefined
// or `{}` fallback (`'crypto' in g ? g.crypto : undefined`), `g.crypto ||
// g.msCrypto`, and the global object held through a local or returned by a
// file function that returns only global objects (`getGlobal()`).
// `c.randomUUID()` is (Crypto).randomUUID and `c.subtle.digest()`
// (SubtleCrypto).digest (were caller-local, or crypto.webcrypto.subtle.digest).
// A function nested in a class method, in a class field's value or in the
// value of a destructuring declaration (`class T { h(xs) { return xs.map((p)
// => m.f(p)); } }`, `const { a } = f(() => m.g())`) is a function of its own
// with its calls, as one nested in a top-level function is (its calls were
// in no function).
// A call made through a module of the build that re-exports another module's
// export is keyed as the export: `createHash()` imported from a file holding
// `export { createHash } from 'crypto'` calls crypto.createHash, and so do
// `export { crypto }` of `import * as crypto from 'node:crypto'`, `export *
// as ns from`, a whole re-export (`export * from 'm'`, `module.exports =
// require('m')`, `__exportStar`) of exactly one module for a name the file
// does not export itself, and chains of them (were keyed under the
// re-exporting module).
// A call in a default parameter value (`function f(a, aux = randomBytes(32))`)
// is a call of the function (was in no function).
// A call whose result a function assigns to a field of this (`this._dh =
// createECDH(c)`) carries AssignedVar `this._dh`, and a call on that field
// (`this._dh.generateKeys()`) ReceiverVar `this._dh`, so a contract types it
// as a call on a variable (was no AssignedVar, no ReceiverVar, caller-local).
// A call written as the fallback operand of `||` or `??` (`const iv = p.iv ||
// randomBytes(16)`) carries the AssignedVar the whole expression binds (was
// none).
// graph-algo-node-8: a member call on a name a function around the caller
// declares (a closure's captured `ecdh` in `ecdh.computeSecret(k)`) carries
// that name as ReceiverVar, as a call on the caller's own local does (was
// none). A member call no receiver binds whose caller-local key is a
// function the module declares (`signer.sign(..)` in a file holding a
// `function sign`, or inside it) is a call of the bare method name, `sign`,
// which no function declares (it was dropped: no edge, no external call).
// graph-algo-node-9: Node fragments carry each function's columns
// (graph-fragment-1.38 start_col, end_col), so annotating a stored fragment
// places a crypto call written on the line where a callback argument starts
// in the function that writes the call, as a scan does (was the callback).
// graph-algo-node-10: a graph follows values, where node-9 keyed a call by
// its text alone and left every other call without an edge. Beside the calls
// node-9 has, unchanged, a function now reaches:
//   - the function a call's callee is when the package's own source builds
//     it: a method of the object a factory returned (`make().run()`), of an
//     instance in a variable or a field of this (`this.sock.write()`), of a
//     class the method is only inherited from (`extends`, `util.inherits`,
//     prototype assignment), of the object a function is assigned to
//     (`this.gen()` in `hotp.verify = function`, in an object literal's
//     method), a function a variable holds, an immediately invoked function,
//     and f of `f.call(..)` and `f.apply(..)`;
//   - the constructor a `new` of a class or constructor function of the
//     package runs, the class's field initialisers (<clinit>), and the base
//     constructor `super(..)` runs;
//   - each function an object holds, from a call through a computed member
//     of it (`signers[alg](..)`);
//   - each function it hands over as a call argument or a returned value, by
//     name, as a member, bound (`f.bind(..)`), or held by an object or array
//     literal handed over (`promisify(client.getKey)`, `return { sign() {}
//     }`); node-9 drew this for the callback APIs it lists only;
//   - the top-level code of a module it loads with require or import() in
//     its body, and of a package any of its code loads, as `<spec>.<module>`;
//   - for a callee that comes from another package through a call or a
//     construction, the key of that access: `new fc.Totp().validate()`
//     reaches fc.(Totp).validate, `fc.client().getKey()` fc.(client()).getKey,
//     `fc.make()()` fc.(make()).<result>, `new fc.a.K().open().read()`
//     fc.a.(K>open()).read, with the value held in a variable, a field of
//     this or a destructured name on the way. A call the KB types keeps the
//     contract's key alone.
//
// A module that only loads a package at its top level gains a <module>
// function. Fragments list in `exports` the functions those keys name
// (`acme.(Totp).validate`, `acme.(Totp).<init>`, `acme.(client()).getKey`,
// `acme.<module>`), to two calls or constructions deep, and an export whose
// value is a member of an instance or of another module's export
// (`exports.finalize = i.finalize`, `exports.verify =
// require('./vs').verify`), which node-9 left out. A package.json "exports"
// condition object resolves to its first key, in the order written, among
// node, require and default (`import` when none of them resolves); node-9
// tried require, import, default and node in that order whatever the
// manifest's. A package whose manifest entry points lie in dist/ or build/
// has that directory in its graph even when it ships other source
// (skip.NodeEntryBuiltOutput).
// graph-algo-node-11: a parameter holds what the calls of its function pass,
// as a union over the call sites the graph resolved to that function, read
// again for up to four rounds so a value crosses one more function each
// round. A function now also reaches:
//   - the function a method called on a parameter, on a member of it or on
//     what is built from it names (`deps.Client` of `module.exports =
//     function (deps)`, `this.adapter.send()` with adapter a constructor
//     argument), the argument after the receiver for `f.call(self, a)`;
//   - the module a `require(x)` or `import(x)` loads when x is a string
//     constant, its own or one a caller passes (`loadModule('@acme/push')`),
//     and what is built from the loaded value, keyed by its access;
//   - what `table[key]` holds: the member declared under that very key
//     (`[kResume]() {..}`), else each member of the table and each value the
//     module writes into it through a computed key (`this.senders[type] =
//     new Web()`, `Encryption.algorithms[kind] = {..}`);
//   - what a class field declared without a value is assigned.
//
// A package's exports list what parameters hold too: `module.exports = new
// PG(Client)` with `this.Client = clientConstructor` publishes
// pg.(Client).connect.
// A member read on what a module exports also holds what the modules
// requiring it assign to that member (node-forge's `forge.pkcs5.pbkdf2`,
// written by pbkdf2.js into forge.js's exported object), and a module that
// holds only data is followed when another requires it.
// `exports = module.exports = fn` exports fn as the module, as
// `module.exports = fn` does (object-hash).
// A destructured parameter member holds its own default too
// (`{ processRequest = defaultProcessRequest } = {}`).
// An export written `inst.method.bind(inst)` publishes the method
// (web-push's sendNotification), and the arguments `f.bind(self, a)` binds
// fill f's parameters from the first, self being `this`.
// `this` in a method also holds the instances its calls are made on (a
// subclass's), a field the constructor empties holds what the methods
// assign it, and a field a method sets to what calling it returns holds
// each state such a machine steps through (mysql2's `this.next =
// this.next(packet)`).
//
// A function a caller passed is called by the caller that hands it over,
// not by the function that receives it. JavaScript with type annotations
// (Flow) that the JavaScript grammar cannot read is parsed with the TSX
// grammar (its functions and the class members after an annotation were in
// no function).
// A member call nothing typed is exported name_only, not exact: its receiver
// is a value of the program (a parameter, a field, what a call returned;
// not a global of the language, a literal, `call`/`apply` or a computed
// key), no import, class or contract bound it, and no value the graph
// follows names the method (`sink.write(d)` on a parameter no call fills,
// `this.cipher.update(b)`, `this.compute()` that no class of the receiver
// declares), or it is resolved on a receiver that is a property the package
// also writes on another object than this (`this._cipher.allocPacket(n)`
// with `this._protocol._cipher = createCipher(c)` elsewhere), which keeps
// the edges it has. Its target stays the key the parser gave it, which no
// function has; a stitch gives it the functions of that name in the
// component and in scope as name_only candidates (stitch_node_untyped.go),
// so a finding reached only across one reads unknown (unresolved_dispatch),
// where it read unreachable.
const GraphAlgoVersionNode = nodeGraphAlgoPrefix + "11"

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
// graph-algo-go-13: the graph lists each project file's composite literals,
// new(T) expressions and field stores (GoValues, graph-fragment-1.34).
// graph-algo-go-14: a Go call argument carries the source nodes of its value:
// a literal as written, a local traced to its initializer (or, when the
// function writes it again, the string literals it may hold), a parameter of
// the enclosing function with its index, a call result over the values passed
// to it, and an operation or composite literal over its operands, to depth 4,
// as Rust arguments do; a const keeps its VARIABLE-over-literal shape.
// graph-algo-go-15: the graph lists each project file's function body blocks
// and case clauses (GoBlocks) and its assignments to plain names (GoValues of
// kind assign, graph-fragment-1.36); a function returning a composite literal
// (`&T{...}`, `T{}`) gets an EXPRESSION return source holding it as written.
const GraphAlgoVersionGo = goGraphAlgoPrefix + "15"

// goGraphAlgoPrefix starts every Go graph algorithm id: a fragment stamped
// with one is a Go graph.
const goGraphAlgoPrefix = "graph-algo-go-"

// GraphAlgoVersionC identifies the callgraph-construction algorithm of C
// graphs. C has its own id so a change to C graph construction never marks a
// graph of another ecosystem stale.
//
// graph-algo-c-1: the C graphs of graph-algo-39, under their own id, whose
// fragments list each project file's #include directives (`imports`, the
// graph's CIncludes): the header as written, angle or quote form, the
// directive's text and span, and whether it sits in a preprocessor
// conditional; each function's local declarations and field stores; a
// declaration of a name another declaration of the package
// already holds (alternative backends, #if/#else bodies) is kept under a key
// scoped to its file (and line) instead of being dropped; and each project
// file's string literals (`strings`, the graph's CStrings: the literal as
// written and its span, at most 256 bytes each). The fragment facts are
// graph-fragment-1.37.
//
// graph-algo-c-2: a function handed out as a value has a caller. A function
// name read as a value (a callback argument, an assignment, an initializer,
// a return, through `&`, casts and `?:`) is an exact edge from the function
// that reads it, and one in a file-scope initializer (a table of handlers)
// an edge from the file's synthetic <varinit:file>, which is always a root,
// as Go's is. A table tree-sitter reads as K&R parameter declarations after
// a macro line counts as file scope.
//
// graph-algo-c-3: a C fragment carries the parser's calls, as Java, Python,
// Go and Node ones do: each call anchor's callee, text, arguments and their
// provenance, each function's return sources, the external signatures and
// the rebind lines, so annotate rebuilds a C graph's calls, and the linkage
// of each callee, from the fragment. Its source_lines also hold the
// preprocessor conditionals of each file's statically false #if blocks, so
// annotate drops the findings in them as a scan of the file does. A C
// fragment of an earlier id annotates its supporting calls without the
// callee's text or the KB category and roles of a call of an externally
// linked function, and keeps the findings of #if 0 blocks.
const GraphAlgoVersionC = cGraphAlgoPrefix + "3"

// cGraphAlgoPrefix starts every C graph algorithm id: a fragment stamped
// with one is a C graph.
const cGraphAlgoPrefix = "graph-algo-c-"

// GraphAlgoVersionCPP identifies the callgraph-construction algorithm of C++
// graphs, apart from C's and every other ecosystem's.
//
// graph-algo-cpp-1: the C++ graphs of graph-algo-39, under their own id, with
// each project file's #include directives and string literals as
// graph-algo-c-1 lists C's, and redefinitions kept as graph-algo-c-1 keeps
// them.
//
// graph-algo-cpp-2: a C++ graph records constructor calls written without a
// call_expression: a declaration that constructs a class-typed variable
// (`T v(args);`, `T v{args};`, `T v;`), `new T(...)` and `T{...}`. Each is a
// call of (T).T, the key a constructor definition has, so one of a project
// type is an edge to the constructor and one of a dependency type an external
// call; its span reads back as the construct (`T v(args)`, `new T(args)`,
// `T{args}`), so a C++ fragment carries it as a call site as written. A
// declaration tree-sitter reads as a function declaration because every
// argument is a name (`QSslKey key(data, QSsl::Rsa)`) is one of them.
//
// graph-algo-cpp-3: a C++ graph records the functions that return a
// reference (`const T& f()`, `T& C::f()`) and the operator functions
// (`T::operator()`), which it dropped; a call of a call's result
// (`SHA256()(x)`) as a call of (T).operator() when the inner callee is a
// name; `T v();` as a construction of T with no arguments; each function's
// local declarations (as C's, references included) and its parameters as
// written (WrittenParameters); and each file's using directives and
// declarations among its includes, so a C++ fragment carries them as
// imports.
//
// graph-algo-cpp-4: a C++ call is resolved against every file of the
// project once all are parsed (callgraph's resolveCPPCalls): a member
// call's receiver is typed from a data member's declared type, from a
// project function's declared return type (an `auto` local bound to such a
// call included, and a deduced return of a member), and through `->` of a
// std::unique_ptr / std::shared_ptr; a type, scope or function name is
// looked up in the enclosing class and namespaces innermost first, then
// globally, then in the using-directives' namespaces; an unqualified call in
// a member function is looked up as a member first; a method is looked up in
// the base classes; a definition is found in any directory of the project (a
// `static` one only from its own file), a qualified call of a static
// function of a named namespace included. A call that can dispatch also
// reaches, as interface_dispatch, the override in every project class
// derived from its receiver's type (class hierarchy analysis). A
// std::make_unique<T> / make_shared<T> call is also a construction of T, and
// a constructor's member initializer list is read: its calls are the
// constructor's, and an entry constructs the member's class type or the base
// it names. A class written with an export macro (`class LIB_API Name {`),
// which tree-sitter reads as a function, is read as the class. A call that
// resolves to no project definition is keyed as before, so the contract KB
// types it as before.
const GraphAlgoVersionCPP = cppGraphAlgoPrefix + "4"

// cppGraphAlgoPrefix starts every C++ graph algorithm id: a fragment stamped
// with one is a C++ graph.
const cppGraphAlgoPrefix = "graph-algo-cpp-"

// GraphAlgoVersionRuby is the Ruby call graph algorithm id. It moves when a
// Ruby graph changes, and re-mines Ruby graphs alone.
const GraphAlgoVersionRuby = rubyGraphAlgoPrefix + "10"

// rubyGraphAlgoPrefix starts every Ruby graph algorithm id: a fragment stamped
// with one is a Ruby graph.
const rubyGraphAlgoPrefix = "graph-algo-rb-"

// GraphAlgoVersionCSharp is the C# call graph algorithm id. It moves when a
// C# graph changes, and re-mines C# graphs alone.
const GraphAlgoVersionCSharp = csharpGraphAlgoPrefix + "1"

// csharpGraphAlgoPrefix starts every C# graph algorithm id: a fragment stamped
// with one is a C# graph.
const csharpGraphAlgoPrefix = "graph-algo-cs-"

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
	case "c":
		return GraphAlgoVersionC
	case "cpp":
		return GraphAlgoVersionCPP
	case "ruby":
		return GraphAlgoVersionRuby
	case "csharp":
		return GraphAlgoVersionCSharp
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
	case strings.HasPrefix(id, cppGraphAlgoPrefix):
		return "cpp"
	case strings.HasPrefix(id, cGraphAlgoPrefix):
		return "c"
	case strings.HasPrefix(id, rubyGraphAlgoPrefix):
		return "ruby"
	case strings.HasPrefix(id, csharpGraphAlgoPrefix):
		return "csharp"
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
	case strings.HasPrefix(purl, "pkg:gem/"):
		return "ruby"
	case strings.HasPrefix(purl, "pkg:nuget/"):
		return "csharp"
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
