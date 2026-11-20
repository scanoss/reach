// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"sort"
	"testing"
)

// nodeUntypedCalls lists, sorted, the member calls of a graph nothing typed,
// as `<caller key> <method>`, and checks each is recorded name_only.
func nodeUntypedCalls(t *testing.T, graph *CallGraph) []string {
	t.Helper()
	var out []string
	for key, decl := range graph.Functions {
		for i := range decl.Calls {
			call := &decl.Calls[i]
			if !NodeCallUntyped(call) {
				continue
			}
			out = append(out, key+" "+call.Callee.Name)
			res, ok := graph.EdgeResolutions[EdgeResolutionKey(key, call.Callee.String(), EdgeResolution{
				MethodName: call.Callee.Name, CallSite: call.Line, StartCol: call.StartCol, EndCol: call.EndCol,
			})]
			if !ok || res.Kind != EdgeKindNameOnly {
				t.Errorf("%s -> %s: resolution %q (recorded %v), want %q", key, call.Callee.String(), res.Kind, ok, EdgeKindNameOnly)
			}
			if graph.Functions[call.Callee.String()] != nil {
				t.Errorf("%s -> %s: an untyped call names a function of the graph", key, call.Callee.String())
			}
		}
	}
	sort.Strings(out)
	return out
}

// A member call whose receiver no value of the source names is a name_only
// call: on a parameter no call the package makes fills, on a field assigned
// from one, on what such a value returns, and of a method no class of the
// receiver declares. A call the value flow resolves, a call on a global of
// the language, on a literal, through call or apply, or under a computed key
// is not one.
func TestNodeUntypedMemberCalls(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		src  string
		want []string
	}{
		{
			name: "a parameter no caller fills",
			src: `class Sink { write(d) { return d; } }
function emit(sink, d) { return sink.write(d); }
module.exports = { emit };
`,
			want: []string{"app/m.emit write"},
		},
		{
			name: "a parameter every caller fills",
			src: `class Sink { write(d) { return d; } }
function emit(sink, d) { return sink.write(d); }
function start() { return emit(new Sink(), 1); }
`,
		},
		{
			name: "a field assigned from a parameter, and what its method returns",
			src: `class Session {
  constructor(cipher) { this.cipher = cipher; }
  run(b) { return this.cipher.update(b).final(); }
}
module.exports = Session;
`,
			want: []string{"app/m.(Session).run final", "app/m.(Session).run update"},
		},
		{
			name: "a method no class of the receiver declares",
			src: `class Base { finish() { return this.compute(); } }
class Sha extends Base { compute() { return 1; } }
module.exports = { Base, Sha };
`,
			want: []string{"app/m.(Base).finish compute"},
		},
		{
			name: "a module function of the same name is not what the call runs",
			src: `function sign(d) { return d; }
function start(signer, d) { return signer.sign(d); }
module.exports = { sign, start };
`,
			want: []string{"app/m.start sign"},
		},
		{
			name: "a resolved field the package also writes through another object",
			src: `class NullCipher { alloc(n) { return n; } }
class Protocol {
  constructor() { this._cipher = new NullCipher(); this._queue = new NullCipher(); }
  send(n) { this._queue.alloc(n); return this._cipher.alloc(n); }
}
function rekey(protocol, cipher) { protocol._cipher = cipher; }
module.exports = { Protocol, rekey };
`,
			want: []string{"app/m.(Protocol).send alloc"},
		},
		{
			name: "globals, literals, call and apply, computed keys",
			src: `function start(o, key, fn) {
  JSON.stringify(o);
  Object.keys(o).forEach(function () {});
  'a,b'.split(',');
  [1, 2].map(function (x) { return x; });
  fn.call(null, o);
  fn.apply(null, [o]);
  return o[key](1);
}
module.exports = start;
`,
		},
		{
			name: "a global the module declares itself is a value of the program",
			src: `function start(process) { return process.run(1); }
module.exports = start;
`,
			want: []string{"app/m.start run"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := nodeUntypedCalls(t, buildNodeFiles(t, map[string]string{"m.js": tc.src}))
			if len(got) != len(tc.want) {
				t.Fatalf("untyped calls %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("untyped calls %v, want %v", got, tc.want)
				}
			}
		})
	}
}

// A call marked for a property written through another object keeps the
// edges its own class's values give it.
func TestNodeUntypedFieldCallKeepsItsEdges(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{"m.js": `class NullCipher { alloc(n) { return n; } }
class Protocol {
  constructor() { this._cipher = new NullCipher(); }
  send(n) { return this._cipher.alloc(n); }
}
function rekey(protocol, cipher) { protocol._cipher = cipher; }
module.exports = { Protocol, rekey };
`})
	if !hasEdge(graph, splitEdge(t, "app/m.(Protocol).send -> app/m.(NullCipher).alloc")) {
		t.Fatalf("missing the edge to the value the constructor assigns; callers: %v", graph.Callers)
	}
	if got := nodeUntypedCalls(t, graph); len(got) != 1 || got[0] != "app/m.(Protocol).send alloc" {
		t.Fatalf("untyped calls %v, want the call on this._cipher", got)
	}
}

// A call on a module of the runtime the program holds under a mutable name
// (undici's `let tls; .. tls = require('tls'); tls.connect(..)`) runs the
// runtime's function: it is resolved, not name_only.
func TestNodeUntypedRuntimeModuleHeldLater(t *testing.T) {
	t.Parallel()
	graph := buildNodeFiles(t, map[string]string{"connect.js": `let tls;
function connect(opts) {
  if (!tls) { tls = require('tls'); }
  return tls.connect(opts);
}
module.exports = connect;
`})
	if got := nodeUntypedCalls(t, graph); len(got) != 0 {
		t.Fatalf("untyped calls %v, want none", got)
	}
}
