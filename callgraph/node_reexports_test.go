// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"
)

// A call made through a project module that re-exports another module's
// export is keyed as the export: named re-exports, a re-exported namespace
// import, `export * from`, `module.exports = require()`, and a chain of
// them. A name the re-exporting module declares itself, and a module that
// re-exports two modules whole, keep the call's key.
func TestBuilder_NodeCallsThroughReExportsKeyAsTheExport(t *testing.T) {
	t.Parallel()

	graph := buildNodeFiles(t, map[string]string{
		"lib/named.js": "export { createHash, createHmac as hmac } from 'crypto';\n",
		"lib/node.ts":  "import * as crypto from 'node:crypto';\nimport * as fs from 'node:fs';\nexport { crypto, fs };\n",
		"lib/cjs.js":   "module.exports = require('crypto');\n",
		"lib/star.js":  "export * from 'node:crypto';\nexport function randomBytes(n) { return new Uint8Array(n); }\n",
		"lib/two.js":   "export * from 'a';\nexport * from 'b';\n",
		"lib/chain.js": "export * from './named.js';\n",
		"lib/use.ts": `import { createHash, hmac } from './named.js';
import { crypto } from './node';
import * as star from './star.js';
import * as two from './two.js';
import { createHash as chained } from './chain.js';
const cjs = require('./cjs');
export function run(d) {
  createHash('sha256');
  hmac('sha1', d);
  crypto.randomUUID();
  new crypto.X509Certificate(d);
  cjs.randomBytes(16);
  star.createSign('RSA-SHA256');
  star.randomBytes(4);
  two.f();
  chained('md5');
}
`,
	})
	_, run := graphFunction(t, graph, "app/lib/use", "", "run")
	var got []string
	for _, call := range run.Calls {
		got = append(got, call.Callee.String())
	}
	for _, want := range []string{
		"crypto.createHash",
		"crypto.createHmac",
		"node:crypto.randomUUID",
		"node:crypto.(X509Certificate).<init>",
		"crypto.randomBytes",
		"node:crypto.createSign",
		"app/lib/star.randomBytes",
		"app/lib/two.f",
		"crypto.createHash",
	} {
		i := slices.Index(got, want)
		if i < 0 {
			t.Errorf("no call keyed %s in %q", want, got)
			continue
		}
		got = slices.Delete(got, i, i+1)
	}
}
