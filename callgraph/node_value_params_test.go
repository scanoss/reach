// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

// A parameter holds what the calls of its function pass: a call on it, on a
// member of it or on what is built from it reaches the functions those
// values name, and no function that only shares the method's name.
func TestNodeValueFlow_ParametersHoldWhatCallersPass(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{
		{
			name: "dependencies handed to a module factory",
			files: map[string]string{
				"client.js": `module.exports = function (dependencies) {
  const sign = dependencies.sign;
  function Client(options) { this.token = sign(options); }
  Client.prototype.write = function write(n) { return n; };
  return Client;
};
`,
				"provider.js": `module.exports = function (dependencies) {
  const Client = dependencies.Client;
  function Provider(options) { this.client = new Client(options); }
  Provider.prototype.send = function send(n) { return this.client.write(n); };
  return Provider;
};
`,
				"index.js": `function sign(o) { return o; }
function unrelated() { return { write(n) { return n; } }; }
const Client = require('./client')({ sign });
const Provider = require('./provider')({ Client });
module.exports = { Provider, unrelated };
`,
			},
			want: []string{
				"app/client.Client -> app/index.sign",
				"app/provider.Provider -> app/client.Client",
				"app/provider.(Provider).send -> app/client.(Client).write",
			},
			not: []string{"app/provider.(Provider).send -> app/index.write"},
		},
		{
			// pg's stream.js: `const { getSecureStream } = getStreamFuncs()`
			// with each runtime's functions, exported as `{ getSecureStream }`.
			name: "an export destructured from what a call returns",
			files: map[string]string{
				"s.js": `function forNode() { function open(o) { return o } return { open } }
function forWorker() { function open(o) { return o } return { open } }
function pick() { if (globalThis.navigator) { return forWorker() } return forNode() }
const { open } = pick()
module.exports = { open }
`,
				"c.js": "const { open } = require('./s')\nfunction connect(o) { return open(o) }\nmodule.exports = connect\n",
			},
			want: []string{"app/c.connect -> app/s.open", "app/c.connect -> app/s.open@1:22"},
		},
		{
			// graphql-upload's `function graphqlUploadExpress({ processRequest
			// = defaultProcessRequest } = {})`, called without that member.
			name: "a destructured member's default when the caller passes none",
			files: map[string]string{
				"proc.js": "function processRequest(r) { return r; }\nmodule.exports = processRequest;\n",
				"mw.js": `const defaultProcessRequest = require("./proc.js");
function mw({ processRequest = defaultProcessRequest, ...rest } = {}) {
  function inner(req) { return processRequest(req, rest); }
  return inner;
}
module.exports = mw;
`,
				"app.js": "const mw = require('./mw.js');\nmw({ max: 1 })({});\n",
			},
			want: []string{"app/mw.inner -> app/proc.processRequest"},
		},
		{
			name: "an instance stored in a field by the constructor it is passed to",
			files: map[string]string{"m.js": `class Adapter { send(b) { return b; } }
class Other { send(b) { return b; } }
class Worker {
  constructor(adapter, { queue }, fallback = new Other()) { this.adapter = adapter; this.queue = queue; this.fallback = fallback; }
  run(b) { this.queue.push(b); this.fallback.send(b); return this.adapter.send(b); }
}
class Queue { push(b) { return b; } }
function start() { return new Worker(new Adapter(), { queue: new Queue() }).run(1); }
function untouched(x) { return x.send(1); }
`},
			want: []string{
				"app/m.(Worker).run -> app/m.(Adapter).send",
				"app/m.(Worker).run -> app/m.(Queue).push",
				"app/m.(Worker).run -> app/m.(Other).send",
			},
			not: []string{
				"app/m.untouched -> app/m.(Adapter).send",
				"app/m.untouched -> app/m.(Other).send",
			},
		},
		{
			// The function that hands a function over reaches it; the one that
			// receives it as a parameter and calls it draws no edge of its own,
			// which every other caller of it would share.
			name: "a function passed down two calls, and through call",
			files: map[string]string{"m.js": `function hash(d) { return d; }
function other(d) { return d; }
function inner(fn, d) { return fn(d); }
function outer(fn, d) { return inner(fn, d); }
function viaCall(self, fn) { return fn(1); }
function start() { outer(hash, 1); viaCall.call(null, {}, other); }
`},
			want: []string{"app/m.start -> app/m.hash", "app/m.start -> app/m.other"},
			not:  []string{"app/m.inner -> app/m.hash", "app/m.inner -> app/m.other", "app/m.viaCall -> app/m.other"},
		},
		{
			name: "arguments after the receiver of call",
			files: map[string]string{"m.js": `class A { run() { return 1; } }
class B { run() { return 2; } }
function viaCall(first, second) { return second.run(); }
function viaApply(first) { return first.run(); }
function start() { viaCall.call(null, new A(), new B()); viaApply.apply(null, [new A()]); }
`},
			want: []string{"app/m.viaCall -> app/m.(B).run"},
			not:  []string{"app/m.viaCall -> app/m.(A).run", "app/m.viaApply -> app/m.(A).run"},
		},
		{
			name: "a field declared without a value and assigned by the constructor",
			files: map[string]string{"m.ts": `class Adapter { send(b: number) { return b; } }
export class Worker {
  private adapter: Adapter;
  constructor(adapter: Adapter) { this.adapter = adapter; }
  run(b: number) { return this.adapter.send(b); }
}
export function start() { return new Worker(new Adapter()).run(1); }
`},
			want: []string{"app/m.(Worker).run -> app/m.(Adapter).send"},
		},
		{
			name: "a parameter no call passes a known value for",
			files: map[string]string{"m.js": `class Sink { write(d) { return d; } }
function emit(sink, d) { return sink.write(d); }
function start(unknown) { return emit(unknown, 1); }
`},
			not: []string{"app/m.emit -> app/m.(Sink).write"},
		},
	})
}

// A module name that reaches `import(x)` or `require(x)` as a string
// constant through a call names the module loaded: its top-level code runs,
// and what is built from the loaded value is keyed by its access.
func TestNodeValueFlow_ModuleNamesPassedToADynamicLoad(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{
		{
			name: "a package loaded by a helper, constructed and called elsewhere",
			files: map[string]string{
				"loader.js": `export async function loadModule(modulePath) {
  const module = await import(modulePath);
  return module?.default || module;
}
export function loadAdapter(adapter, defaultAdapter, options) {
  if (!adapter) { return loadAdapter(defaultAdapter, undefined, options); }
  if (typeof adapter === 'function') { var Adapter = adapter; return new Adapter(options); }
  return adapter;
}
`,
				"worker.js": `export class Worker {
  constructor(adapter) { this.adapter = adapter; }
  run(b) { return this.adapter.send(b); }
}
`,
				"index.js": `import { loadAdapter, loadModule } from './loader';
import { Worker } from './worker';
export async function start(options) {
  const PushAdapter = await loadModule('@acme/push-adapter');
  const adapter = loadAdapter(options.adapter, PushAdapter, options);
  return new Worker(adapter).run(1);
}
`,
			},
			want: []string{
				"app/loader.loadModule -> @acme/push-adapter.<module>",
				"app/loader.loadAdapter -> @acme/push-adapter.(default).<init>",
				"app/worker.(Worker).run -> @acme/push-adapter.(default).send",
			},
		},
		{
			name: "a module of the package required by name",
			files: map[string]string{
				"algs.js": `exports.sign = function sign(d) { return d; };
`,
				"m.js": `const NAME = './algs';
function load(name) { return require(name); }
function start() { return load(NAME).sign(1); }
function built(name) { return require('./' + name).sign(1); }
`,
			},
			want: []string{"app/m.start -> app/algs.sign"},
			not:  []string{"app/m.built -> app/algs.sign"},
		},
	})
}

// A table filled through a computed key holds what was written into it: a
// read through a key only known at run time yields any of those values.
func TestNodeValueFlow_TablesFilledByKey(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{
		{
			name: "a field of this filled in the constructor",
			files: map[string]string{"m.js": `class Web { send(d) { return d; } }
class Apns { send(d) { return d; } }
class Unused { send(d) { return d; } }
class Adapter {
  constructor(config) {
    this.senders = {};
    for (const type of Object.keys(config)) {
      if (type === 'web') { this.senders[type] = new Web(config[type]); } else { this.senders[type] = new Apns(config[type]); }
    }
  }
  send(type, d) { const sender = this.senders[type]; return sender.send(d); }
}
class Elsewhere { constructor() { this.senders = {}; this.senders['x' + 1] = new Unused(); } }
`},
			want: []string{"app/m.(Adapter).send -> app/m.(Web).send", "app/m.(Adapter).send -> app/m.(Apns).send"},
			not:  []string{"app/m.(Adapter).send -> app/m.(Unused).send"},
		},
		{
			name: "a variable filled in a loop and called through its key",
			files: map[string]string{"m.js": `function sha(d) { return d; }
function md(d) { return d; }
const table = {};
for (const [name, fn] of [['sha', sha]]) { table[name] = sha; }
table['m' + 'd'] = md;
function run(name, d) { return table[name](d); }
`},
			want: []string{"app/m.run -> app/m.sha", "app/m.run -> app/m.md"},
		},
		{
			// The member the table's entries are read for names the function,
			// whatever the function itself is called.
			name: "a table held in a member of an object, read through a variable",
			files: map[string]string{"m.js": `const Encryption = {};
Encryption.encryptDes = function (d) { return d; };
Encryption.encryptAes = function (d) { return d; };
Encryption.other = function (d) { return d; };
Encryption.algorithms = {};
Encryption.algorithms[1] = { encrypt: Encryption.encryptDes };
Encryption.algorithms[2] = { encrypt: Encryption.encryptAes };
Encryption.encrypt = function (kind, d) {
  var fn = Encryption.algorithms[kind].encrypt;
  return fn(d);
};
`},
			want: []string{"app/m.encrypt -> app/m.encryptDes", "app/m.encrypt -> app/m.encryptAes"},
			not:  []string{"app/m.encrypt -> app/m.other"},
		},
		{
			name: "a member declared under the key that reads it",
			files: map[string]string{"m.js": `const kResume = Symbol('resume');
const kClose = Symbol('close');
class Client {
  [kResume]() { return 1; }
  [kClose]() { return 2; }
}
function resume(any) { const client = new Client(); return client[kResume](); }
function either(name) { const client = new Client(); return client[name](); }
`},
			want: []string{"app/m.resume -> app/m.(Client).[kResume]", "app/m.either -> app/m.(Client).[kClose]"},
			not:  []string{"app/m.resume -> app/m.(Client).[kClose]"},
		},
	})
}

// JavaScript written with type annotations (Flow) is read with the TSX
// grammar, which spells them the same way: the JavaScript grammar drops a
// function with type parameters, and the class members after an annotated
// field, into an error node.
func TestNodeParser_TypedJavaScriptKeepsItsFunctions(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{
		{
			name: "type parameters, annotated parameters and fields",
			files: map[string]string{"m.js": `// @flow
export function load<T>(adapter, options: any): T { return make(options); }
function make(options: ?any): any { return options; }
export class Worker {
  subscriber: ?any;
  adapter: any;
  constructor(adapter: Adapter, config: any = {}) { this.adapter = adapter; }
  run({ body }: any): Promise<*> { return this.finish(body); }
  finish(body: any) { return load(body, {}); }
}
`},
			want: []string{
				"app/m.load -> app/m.make",
				"app/m.(Worker).run -> app/m.(Worker).finish",
				"app/m.(Worker).finish -> app/m.load",
			},
		},
		{
			// Plain JavaScript the grammar reads stays JavaScript: a comparison
			// chain is no type argument list.
			name: "plain javascript is not reread",
			files: map[string]string{"m.js": `function lt(a, b, c) { return a < b > (c); }
function start() { return lt(1, 2, 3); }
`},
			want: []string{"app/m.start -> app/m.lt"},
		},
	})
}

// A module holding only data that every other module of the package writes
// its functions into (node-forge's forge.js) is the receiver of the calls
// made through it: a member read on what it exports holds what the modules
// requiring it assign to that member.
func TestNodeValueFlow_NamespaceFilledByOtherModules(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{{
		name: "a namespace object filled by the modules requiring it",
		files: map[string]string{
			"forge.js": "module.exports = { options: {} };\n",
			"pbkdf2.js": `var forge = require('./forge');
var pkcs5 = forge.pkcs5 = forge.pkcs5 || {};
module.exports = forge.pbkdf2 = pkcs5.pbkdf2 = function (p, s) { return p + s; };
`,
			"md5.js": `var forge = require('./forge');
forge.md5 = { create: function create() { return 1; } };
`,
			"pbe.js": `var forge = require('./forge');
require('./pbkdf2');
require('./md5');
function derive(p) { return forge.pkcs5.pbkdf2(p, 's') + forge.md5.create(); }
module.exports = { derive };
`,
		},
		want: []string{"app/pbe.derive -> app/pbkdf2.exports", "app/pbe.derive -> app/md5.create"},
	}})
}

// `this` in a method holds the instances its calls are made on, a subclass's
// included, and a field a method sets to what calling it returns holds each
// state such a machine steps through (mysql2's Command.execute runs
// `this.next = this.next(packet)` over a ClientHandshake's states).
func TestNodeValueFlow_ReceiverAndStateMachineFields(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{
		{
			// google-auth-library's IdentityPoolClient constructor picks a
			// file, url or certificate supplier for one field.
			name: "each value a constructor may assign a field",
			files: map[string]string{"c.js": `class FileSupplier { token() { return 1; } }
class CertSupplier { token() { return 2; } }
class Other { token() { return 3; } }
class Client {
  constructor(opts) {
    if (opts.file) { this.supplier = new FileSupplier(); } else { this.supplier = new CertSupplier(); }
  }
  fetch() { return this.supplier.token(); }
}
module.exports = Client;
`},
			want: []string{"app/c.(Client).fetch -> app/c.(FileSupplier).token", "app/c.(Client).fetch -> app/c.(CertSupplier).token"},
			not:  []string{"app/c.(Client).fetch -> app/c.(Other).token"},
		},
		{
			// ssh2's Protocol: `this._parse = parseHeader` in the constructor,
			// and parseHeader, run as this._parse, sets `this._parse =
			// parsePacket`.
			name: "a field a plain function the class holds assigns",
			files: map[string]string{"p.js": `class Protocol {
  constructor() { this._parse = parseHeader; }
  parse(chunk) { return this._parse(chunk); }
}
function parseHeader(chunk) { this._parse = parsePacket; return 0; }
function parsePacket(chunk) { return chunk; }
function unrelated(chunk) { return chunk; }
module.exports = Protocol;
`},
			want: []string{"app/p.(Protocol).parse -> app/p.parseHeader", "app/p.(Protocol).parse -> app/p.parsePacket"},
			not:  []string{"app/p.(Protocol).parse -> app/p.unrelated"},
		}, {
			name: "a command whose states return the next one",
			files: map[string]string{
				"command.js": `class Command {
  constructor() { this.next = null; }
  execute(packet) {
    if (!this.next) { this.next = this.start; }
    this.next = this.next(packet);
    return !this.next;
  }
}
module.exports = Command;
`,
				"handshake.js": `const Command = require('./command');
class ClientHandshake extends Command {
  start(p) { return ClientHandshake.prototype.handshakeInit; }
  handshakeInit(p) { return ClientHandshake.prototype.handshakeResult; }
  handshakeResult(p) { return null; }
  unused(p) { return p; }
}
module.exports = ClientHandshake;
`,
				"conn.js": `const ClientHandshake = require('./handshake');
class Conn {
  constructor() { this._command = new ClientHandshake(); }
  handle(p) { return this._command.execute(p); }
}
module.exports = Conn;
`,
			},
			want: []string{
				"app/command.(Command).execute -> app/handshake.(ClientHandshake).start",
				"app/command.(Command).execute -> app/handshake.(ClientHandshake).handshakeInit",
				"app/command.(Command).execute -> app/handshake.(ClientHandshake).handshakeResult",
			},
			not: []string{"app/command.(Command).execute -> app/handshake.(ClientHandshake).unused"},
		}})
}
