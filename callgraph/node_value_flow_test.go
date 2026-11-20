// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"sort"
	"testing"
)

// nodeFlowCase is one source layout of the package `app` with the edges the
// build must and must not draw.
type nodeFlowCase struct {
	name  string
	files map[string]string
	want  []string
	not   []string
}

func runNodeFlowCases(t *testing.T, cases []nodeFlowCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			graph := buildNodeFiles(t, tc.files)
			for _, edge := range tc.want {
				if pair := splitEdge(t, edge); !hasEdge(graph, pair) {
					keys := functionKeys(graph)
					sort.Strings(keys)
					t.Errorf("missing edge %s; callers of the callee: %v; functions: %v", edge, graph.Callers[pair[1]], keys)
				}
			}
			for _, edge := range tc.not {
				if hasEdge(graph, splitEdge(t, edge)) {
					t.Errorf("unexpected edge %s", edge)
				}
			}
		})
	}
}

// A call on a value the package's own source builds reaches the function
// that value's member is: the method of what a factory returned, of an
// instance in a variable or in a field of this, of the object a function is
// assigned to, and the function a variable holds.
func TestNodeValueFlow_CallsOnBuiltValues(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{
		{
			name: "method of the object a factory returns",
			files: map[string]string{"m.js": `function client() { return { getKey(n) { return n; } }; }
function viaVariable() { const cl = client(); return cl.getKey(16); }
function viaChain() { return client().getKey(16); }
`},
			want: []string{"app/m.viaVariable -> app/m.getKey", "app/m.viaChain -> app/m.getKey"},
		},
		{
			name: "this in a function assigned to a property of an object",
			files: map[string]string{"m.js": `const hotp = {};
hotp.gen = function (k) { return k; };
hotp.verify = function (t, k) { return this.gen(k) === t; };
const totp = { gen(k) { return k; }, verify(t, k) { return this.gen(k) === t; } };
module.exports = { check(k) { return this.other(k); }, other(k) { return k; } };
`},
			want: []string{
				"app/m.verify -> app/m.gen",
				"app/m.check -> app/m.other",
			},
			not: []string{"app/m.verify -> app/m.(totp).gen"},
		},
		{
			name: "prototype methods, inherited ones and the constructor",
			files: map[string]string{
				"base.js": `function Base() { this.ready = true; }
Base.prototype.open = function () { return this.close(); };
Base.prototype.close = function () { return 1; };
module.exports = Base;
`,
				"m.js": `const util = require('util');
const Base = require('./base');
function Conn(opts) { Base.call(this); this.opts = opts; }
util.inherits(Conn, Base);
Conn.prototype.send = function () { return this.open(); };
function start() { const c = new Conn({}); return c.send(); }
`,
			},
			want: []string{
				"app/m.start -> app/m.Conn",
				"app/m.start -> app/m.(Conn).send",
				"app/m.(Conn).send -> app/base.(Base).open",
				"app/base.(Base).open -> app/base.(Base).close",
				"app/m.Conn -> app/base.Base",
			},
		},
		{
			name: "class constructor, super and a field holding an instance",
			files: map[string]string{"m.js": `class Socket { constructor() { this.id = 1; } write(b) { return b; } }
class Base { constructor() { this.sock = new Socket(); } flush() { return this.sock.write(1); } }
class Client extends Base {
  constructor() { super(); }
  send() { return this.flush(); }
}
function start() { return new Client().send(); }
`},
			want: []string{
				"app/m.start -> app/m.(Client).constructor",
				"app/m.start -> app/m.(Client).send",
				"app/m.(Client).constructor -> app/m.(Base).constructor",
				"app/m.(Base).constructor -> app/m.(Socket).constructor",
				"app/m.(Base).flush -> app/m.(Socket).write",
			},
		},
		{
			name: "function held in a variable, immediately invoked function, call and apply",
			files: map[string]string{"m.js": `function make() { return function signer(x) { return x; }; }
function sign(x) { return x; }
function viaVariable() { const f = make(); return f(1); }
function viaCall(self) { return sign.call(self, 1); }
function viaApply(self) { return sign.apply(self, [1]); }
const ready = (function probe() { return sign(1); })();
`},
			want: []string{
				"app/m.viaVariable -> app/m.signer",
				"app/m.viaCall -> app/m.sign",
				"app/m.viaApply -> app/m.sign",
				"app/m.<module> -> app/m.probe",
			},
		},
		{
			name: "variable assigned after its declaration, and a field a method assigns",
			files: map[string]string{"m.js": `class Mailer { sendMail() { return 1; } }
class Socket { write() { return 1; } }
function createTransport(t) { let mailer; if (t) { mailer = null; } mailer = new Mailer(); return mailer; }
function start() { return createTransport().sendMail(); }
function plain(m) { return m; }
function wrap(inner) { return function wrapped(m) { return inner(m); }; }
function build(run) { var method = plain; method = wrap(method); return run(method); }
class Conn {
  open() { this.sock = new Socket(); }
  send() { return this.sock.write(); }
}
`},
			want: []string{"app/m.start -> app/m.(Mailer).sendMail", "app/m.(Conn).send -> app/m.(Socket).write", "app/m.build -> app/m.plain", "app/m.build -> app/m.wrapped"},
		},
		{
			name: "member of another module's export",
			files: map[string]string{
				"vs.js": "function VerifyStream() {}\nVerifyStream.verify = function (d) { return d; };\nmodule.exports = VerifyStream;\n",
				"m.js":  "const VS = require('./vs');\nfunction run(d) { const check = VS.verify; return check(d); }\n",
			},
			want: []string{"app/m.run -> app/vs.verify"},
		},
	})
}

// A value the source does not settle names no function: a parameter, a name
// that is assigned again, an exported `let`, a destructured name. A method
// name alone links nothing.
func TestNodeValueFlow_UnknownReceiversStayUnbound(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{{
		name: "unknown receivers",
		files: map[string]string{"m.js": `class Hasher { digest() { return 1; } }
function make() { return new Hasher(); }
function viaParam(h) { return h.digest(); }
function viaRebound() { let h = make(); h = other(); return h.digest(); }
function viaDestructured(x) { const { h } = x; return h.digest(); }
function viaLoop(xs) { for (const h of xs) { h.digest(); } }
function viaProperty(x) { return x.h.digest(); }
function known() { const h = make(); return h.digest(); }
var i = make();
var digest = i.digest;
function otherScope(xs) { var i; for (i = 0; i < xs.length; i++) { xs[i](); } }
function viaExtracted() { return digest(); }
const table = { digest: () => digest };
`},
		want: []string{"app/m.known -> app/m.(Hasher).digest", "app/m.viaExtracted -> app/m.(Hasher).digest"},
		not: []string{
			"app/m.viaParam -> app/m.(Hasher).digest",
			"app/m.viaRebound -> app/m.(Hasher).digest",
			"app/m.viaDestructured -> app/m.(Hasher).digest",
			"app/m.viaLoop -> app/m.(Hasher).digest",
			"app/m.viaProperty -> app/m.(Hasher).digest",
		},
	}})
}

// A computed member call may run any function the object holds, and a
// function handed over as an argument or a returned value may be called by
// whoever receives it.
func TestNodeValueFlow_TablesAndHandedOverFunctions(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{
		{
			name: "function table",
			files: map[string]string{"m.js": `function hmac(bits) { return bits; }
function rsa(bits) { return bits; }
function unused(bits) { return bits; }
const signers = { hs: hmac, rs: rsa };
function jwa(alg, bits) { return signers[alg](bits); }
`},
			want: []string{"app/m.jwa -> app/m.hmac", "app/m.jwa -> app/m.rsa"},
			not:  []string{"app/m.jwa -> app/m.unused", "app/m.<module> -> app/m.hmac"},
		},
		{
			// node-apn: `this.config.createConnection = (a) => ..` then
			// `http2.connect(url, this.config)`, which calls it.
			name: "a function written into an object the same body hands over",
			files: map[string]string{"m.js": `const http2 = require('http2');
function dial(a) { return a; }
class Client {
  connect(socket) {
    if (socket) { this.config.createConnection = (a) => dial(a); }
    this.config.other = function kept() { return 1; };
    return http2.connect('x', this.config);
  }
  idle() { this.spare.onIdle = function idle() { return 1; }; return 0; }
}
function tlsConnect(o) { return o; }
function netConnect(o) { return o; }
function initAsClient(opts, secure) {
  opts.createConnection = opts.createConnection || (secure ? tlsConnect : netConnect);
  return http2.request(opts);
}
`},
			want: []string{
				"app/m.(Client).connect -> app/m.createConnection", "app/m.(Client).connect -> app/m.kept",
				"app/m.initAsClient -> app/m.tlsConnect", "app/m.initAsClient -> app/m.netConnect",
			},
			not: []string{"app/m.(Client).idle -> app/m.idle"},
		},
		{
			name: "returned closure and object, and a bound function",
			files: map[string]string{"m.js": `function sign(x) { return x; }
function factory(bits) { return function inner(x) { return x + bits; }; }
function api() { return { run() { return 1; }, sign }; }
function token() { return sign.bind(null, 1); }
const stored = { keep() { return 1; } };
`},
			want: []string{
				"app/m.factory -> app/m.inner",
				"app/m.api -> app/m.run",
				"app/m.token -> app/m.sign",
			},
			// Returning a function that has a name calls nothing, and
			// neither does storing one.
			not: []string{"app/m.api -> app/m.sign", "app/m.<module> -> app/m.(stored).keep"},
		},
		{
			name: "function an immediately invoked function returns",
			files: map[string]string{"m.js": `const cookie = (() => { const buf = []; return () => buf.length; })();
const web = (function () { return function inner() { return 1; }; })();
function used() { return cookie(); }
`},
			want: []string{"app/m.used -> app/m.<anonymous>@1:48"},
			not:  []string{"app/m.<module> -> app/m.<anonymous>@1:48", "* -> app/m.inner"},
		},
		{
			name: "functions in an argument, and helpers that call none",
			files: map[string]string{"m.js": `const util = require('util');
function onData() {}
function onEnd() {}
function Sub() {}
function Base() {}
function getter() {}
function start(stream, run) {
  stream.pipe({ write: onData, end() { return 1; } });
  run([onEnd]);
}
util.inherits(Sub, Base);
Object.defineProperty(exports, 'x', { enumerable: true, get: getter });
`},
			want: []string{"app/m.start -> app/m.onData", "app/m.start -> app/m.end", "app/m.start -> app/m.onEnd"},
			not:  []string{"* -> app/m.Sub", "* -> app/m.Base", "* -> app/m.getter"},
		},
		{
			name: "method passed as a value",
			files: map[string]string{"m.js": `const util = require('util');
class Client { getKey(cb) { cb(null, 1); } }
function start() { const c = new Client(); return util.promisify(c.getKey)(); }
`},
			want: []string{"app/m.start -> app/m.(Client).getKey"},
		},
	})
}

// Loading a module runs its top-level code: a require or import() inside a
// function loads it when the function runs, and a package is loaded by
// whoever names it, under the key the package's exports give its entry
// module's top-level code.
func TestNodeValueFlow_ModuleLoads(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{{
		name: "lazy and package loads",
		files: map[string]string{
			"dep.js": "register();\n",
			"m.ts": `import pkg from 'acme-pkg';
import type { T } from 'acme-types';
import fs from 'node:fs';
function lazy() { return require('./dep'); }
async function dynamic() { return (await import('./dep')).x; }
function lazyPackage() { return require('acme-lazy/sub'); }
pkg.run();
`,
		},
		want: []string{
			"app/m.lazy -> app/dep.<module>",
			"app/m.dynamic -> app/dep.<module>",
			"app/m.<module> -> acme-pkg.<module>",
			"app/m.lazyPackage -> acme-lazy/sub.<module>",
		},
		not: []string{
			"app/m.<module> -> app/dep.<module>",
			"* -> acme-types.<module>",
			"* -> node:fs.<module>",
			"* -> fs.<module>",
		},
	}})
}

// A call on a value of another package is keyed by the steps that lead to
// it from the import, the key that package's exports list the function
// under.
func TestNodeValueFlow_CallsOnValuesOfAnotherPackage(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{{
		name: "access keys",
		files: map[string]string{"m.js": `const util = require('util');
const fc = require('fakecrypto');
const { connect } = require('acme-db');
import Sftp from 'acme-sftp';
const crypto = require('crypto');
function instance(x) { const t = new fc.Totp(); return t.validate(x); }
function factory() { const cl = fc.client(); return cl.getKey(16); }
function chain() { return fc.client().getKey(16); }
function value() { const cl = fc.client2(); return util.promisify(cl.getKey2)(); }
function destructured() { const db = connect(); return db.query(); }
class Monitor {
  constructor() { this.sftp = new Sftp(); }
  check() { return this.sftp.connect(); }
}
function deep() { return new fc.a.K().open().read(); }
function runtime() { const h = crypto.createHash('sha1'); return h.update('x'); }
`},
		want: []string{
			"app/m.instance -> fakecrypto.(Totp).validate",
			"app/m.factory -> fakecrypto.(client()).getKey",
			"app/m.chain -> fakecrypto.(client()).getKey",
			"app/m.value -> fakecrypto.(client2()).getKey2",
			"app/m.destructured -> acme-db.(connect()).query",
			"app/m.(Monitor).check -> acme-sftp.(default).connect",
			"app/m.deep -> fakecrypto.a.(K>open()).read",
		},
		not: []string{"* -> crypto.(createHash()).update"},
	}})
}

// A prototype taken from another package, a base class of one and a member
// of an unresolved value name no function of this package, and none is read
// as one.
func TestNodeValueFlow_ValuesOfOtherPackagesInThePrototypeChain(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{{
		name: "external prototypes and bases",
		files: map[string]string{"m.js": `const ext = require('acme-ext');
const { EventEmitter } = require('events');
function Wrapped() {}
Wrapped.prototype = ext.proto;
function Derived() {}
Derived.prototype = Object.create(ext.Base.prototype);
class Sub extends ext.Base { own() { return this.inherited(); } }
class Emitter extends EventEmitter { fire() { return this.emit('x'); } }
function start() {
  new Wrapped().go();
  new Derived().run();
  return new Sub().inherited();
}
`},
		want: []string{
			"app/m.start -> acme-ext.(Base).run",
			"app/m.start -> acme-ext.(Base).inherited",
			"app/m.(Sub).own -> acme-ext.(Base).inherited",
		},
		not: []string{"* -> events.(EventEmitter).emit"},
	}})
}

// A route handler is called by the router, not by the code that registers
// it: it stays an entry point with no caller.
func TestNodeValueFlow_RouteHandlersStayEntryPoints(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{{
		name: "express routes",
		files: map[string]string{"m.js": `const express = require('express');
const app = express();
function handler(req, res) { res.end(); }
function wrapped(req, res) { res.end(); }
function wrap(fn) { return fn; }
function other() {}
app.get('/x', handler);
app.post('/y', wrap(wrapped));
setup(other);
`},
		want: []string{"app/m.<module> -> app/m.other"},
		not:  []string{"* -> app/m.handler", "* -> app/m.wrapped"},
	}})
}

// A package lists, in its exports, the functions those keys name.
func TestNodeValueExports(t *testing.T) {
	t.Parallel()
	graph := buildNodePackage(t, "fakecrypto", map[string]string{
		"package.json": `{"name":"fakecrypto","main":"index.js"}`,
		"index.js": `const crypto = require('crypto');
exports.direct = function direct(d) { return d; };
class Base { open() { return this; } read() { return 1; } }
class Totp extends Base { constructor() { super(); } validate(d) { return d; } }
exports.Totp = Totp;
class Pure { finalize(d) { return d; } }
const i = new Pure();
const finalize = i.finalize;
exports.finalize = finalize;
exports.client = function client() { return { getKey(n) { return n; } }; };
exports.make = function make() { return function made() {}; };
const hotp = {};
hotp.gen = function (k) { return k; };
exports.hotp = hotp;
const VS = require('./vs');
exports.vverify = VS.verify;
function Legacy() { this.x = 1; }
Legacy.prototype.run = function () { return 1; };
exports.Legacy = Legacy;
`,
		"vs.js": "function VerifyStream() {}\nVerifyStream.verify = function (d) { return d; };\nmodule.exports = VerifyStream;\n",
	})
	want := map[string]string{
		"fakecrypto.direct":                 "fakecrypto/index.direct",
		"fakecrypto.finalize":               "fakecrypto/index.(Pure).finalize",
		"fakecrypto.vverify":                "fakecrypto/vs.verify",
		"fakecrypto.(Totp).<init>":          "fakecrypto/index.(Totp).constructor",
		"fakecrypto.(Totp).validate":        "fakecrypto/index.(Totp).validate",
		"fakecrypto.(Totp).open":            "fakecrypto/index.(Base).open",
		"fakecrypto.(Totp>open()).read":     "fakecrypto/index.(Base).read",
		"fakecrypto.(client()).getKey":      "fakecrypto/index.getKey",
		"fakecrypto.(make()).<result>":      "fakecrypto/index.made",
		"fakecrypto.(Legacy).<init>":        "fakecrypto/index.Legacy",
		"fakecrypto.(Legacy).run":           "fakecrypto/index.(Legacy).run",
		"fakecrypto.<module>":               "fakecrypto/index.<module>",
		"fakecrypto.hotp.gen":               "fakecrypto/index.gen",
		"fakecrypto.client":                 "fakecrypto/index.client",
		"fakecrypto.make":                   "fakecrypto/index.make",
		"fakecrypto.Legacy":                 "fakecrypto/index.Legacy",
		"fakecrypto.Legacy.run":             "fakecrypto/index.(Legacy).run",
		"fakecrypto.(Totp>open()).open":     "fakecrypto/index.(Base).open",
		"fakecrypto.(Totp).read":            "fakecrypto/index.(Base).read",
		"fakecrypto.(Totp>open()).<init>":   "",
		"fakecrypto.(direct).<init>":        "",
		"fakecrypto.(client()).<result>":    "",
		"fakecrypto.(Totp>open()).validate": "",
	}
	for public, decl := range want {
		if got := graph.NodePackageExports[public]; got != decl {
			t.Errorf("exports[%s] = %q, want %q", public, got, decl)
		}
	}
	for public, decl := range graph.NodePackageExports {
		if graph.Functions[decl] == nil {
			t.Errorf("exports[%s] = %s, which the graph does not declare", public, decl)
		}
		if _, listed := want[public]; !listed {
			t.Errorf("unexpected export %s -> %s", public, decl)
		}
	}
}
