// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

// The runtime drives an HTTP agent: the constructor of a class that extends
// http.Agent, https.Agent or agent-base's Agent reaches the protocol methods
// its chain declares. A class that only shares the method names does not.
func TestNodeAgentProtocol(t *testing.T) {
	t.Parallel()
	runNodeFlowCases(t, []nodeFlowCase{
		{
			name: "agent-base and its subclasses",
			files: map[string]string{"a.js": `const http = require("http");
const agent_base_1 = require("agent-base");
class Agent extends http.Agent {
  constructor(o) { super(o); }
  createSocket(req, o, cb) { return this.connect(req, o); }
  createConnection() { return null; }
}
class HttpsProxyAgent extends agent_base_1.Agent {
  constructor(p) { super(p); }
  async connect(req, opts) { return opts; }
}
class LocalProxy extends Agent {
  constructor() { super(); }
  connect(req, opts) { return opts; }
}
class Plain { constructor() {} connect() { return 1; } createSocket() { return 2; } }
exports.Agent = Agent; exports.HttpsProxyAgent = HttpsProxyAgent; exports.Plain = Plain; exports.LocalProxy = LocalProxy;
`},
			want: []string{
				"app/a.(Agent).constructor -> app/a.(Agent).createSocket",
				"app/a.(Agent).constructor -> app/a.(Agent).createConnection",
				"app/a.(HttpsProxyAgent).constructor -> app/a.(HttpsProxyAgent).connect",
				"app/a.(LocalProxy).constructor -> app/a.(LocalProxy).connect",
				"app/a.(LocalProxy).constructor -> app/a.(Agent).createSocket",
			},
			not: []string{
				"app/a.(Plain).constructor -> app/a.(Plain).connect",
				"app/a.(Plain).constructor -> app/a.(Plain).createSocket",
			},
		},
	})
}
