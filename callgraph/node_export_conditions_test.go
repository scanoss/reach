// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"encoding/json"
	"testing"
)

// A condition object resolves as Node resolves it for required code: the
// first key that holds, in the order the manifest writes them. `node` before
// `default` picks the Node build, whatever a map's order would give, and
// `import` is used only when nothing else resolves.
func TestNodeConditionTargetFollowsManifestOrder(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, exports, want string
	}{
		{"node before default", `{"types":"./a.d.ts","bun":"./esm.js","node":{"import":"./node.mjs","require":"./node.cjs"},"default":"./esm.js"}`, "./node.cjs"},
		{"default before node", `{"default":"./esm.js","node":"./node.cjs"}`, "./esm.js"},
		{"require beside import", `{"import":"./index.mjs","require":"./index.cjs"}`, "./index.cjs"},
		{"default after import", `{"import":"./index.mjs","default":"./index.js"}`, "./index.js"},
		{"import alone", `{"types":"./index.d.ts","import":"./index.mjs"}`, "./index.mjs"},
		{"alternatives", `[{"browser":"./b.js"},"./fallback.js"]`, "./fallback.js"},
		{"nothing that holds", `{"browser":"./b.js","types":"./a.d.ts"}`, ""},
	}
	for _, tc := range cases {
		got, ok := nodeConditionTarget(json.RawMessage(tc.exports))
		if got != tc.want || ok != (tc.want != "") {
			t.Errorf("%s: target = %q (ok %v), want %q", tc.name, got, ok, tc.want)
		}
	}
}
