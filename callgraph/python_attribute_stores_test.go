// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"reflect"
	"testing"
)

// pythonStoresOf lists a parsed file's attribute stores by function name as
// "line:col-endcol receiver.attribute op value [sources]" strings.
func pythonStoresOf(analysis *FileAnalysis) map[string][]string {
	out := map[string][]string{}
	for _, fn := range analysis.Functions {
		for _, store := range fn.AttributeStores {
			s := fmt.Sprintf("%d:%d-%d %s.%s %s %s", store.Line, store.StartCol, store.EndCol, store.Receiver, store.Attribute, store.Operator, store.Value.Text)
			for _, node := range store.Value.Sources {
				s += fmt.Sprintf(" [%s %s%s %v]", node.Type, node.Name, node.Value, node.MayValues)
			}
			if store.EndLine != 0 {
				s += fmt.Sprintf(" end %d", store.EndLine)
			}
			key := fn.ID.Name
			if fn.ID.Type != "" {
				key = fn.ID.Type + "." + key
			}
			out[key] = append(out[key], s)
		}
	}
	return out
}

func TestPythonAttributeStores(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, `import ssl

ssl._create_default_https_context = ssl._create_unverified_context


class Client:
    retries = 3
    Client.default = None

    def __init__(self, ctx, mode):
        ctx.verify_mode = ssl.CERT_NONE
        ctx.check_hostname = False
        ctx.options |= ssl.OP_NO_TLSv1
        self._ctx.minimum_version = mode
        name = "TLSv1"
        if mode:
            name = "TLSv1_1"
        ctx.protocol = name
        ctx.a = ctx.b = "x"
        ctx.allowed_algs = [
            "HS256",
        ]
        ctx[0] = 1
        a, ctx.c = 1, 2
        ctx.d: int = 4
        self.made = ssl.create_default_context()
        self.ctx = ctx.e = ssl.create_default_context()
        ctx.made = ssl.create_default_context()
        self.mode = ssl.CERT_NONE
        self.flags |= ssl.flags()
        cls.shared = ssl.create_default_context()
`)
	got := pythonStoresOf(analysis)
	want := map[string][]string{
		"<module>":        {"3:1-67 ssl._create_default_https_context = ssl._create_unverified_context [EXPRESSION ssl._create_unverified_context []]"},
		"Client.<clinit>": {"8:5-26 Client.default = None [VALUE None []]"},
		"Client.<init>": {
			"11:9-40 ctx.verify_mode = ssl.CERT_NONE [EXPRESSION ssl.CERT_NONE []]",
			"12:9-35 ctx.check_hostname = False [VALUE False []]",
			"13:9-39 ctx.options |= ssl.OP_NO_TLSv1 [EXPRESSION ssl.OP_NO_TLSv1 []]",
			// A method's parameter is no caller position (self is the
			// receiver): no source, as for a call argument.
			"14:9-41 self._ctx.minimum_version = mode [PARAMETER mode []]",
			`18:9-28 ctx.protocol = name [VARIABLE name ["TLSv1" "TLSv1_1"]]`,
			// A chained assignment stores the last value in each target.
			`19:9-28 ctx.a = "x" [VALUE "x" []]`,
			`19:17-28 ctx.b = "x" [VALUE "x" []]`,
			"20:9-10 ctx.allowed_algs = [\n            \"HS256\",\n        ] end 22",
			"25:9-23 ctx.d = 4 [VALUE 4 []]",
			// A field assigned a call is the call's assigned variable
			// (`self.made`); a chained target is not.
			"27:9-56 self.ctx = ssl.create_default_context() [CALL_RESULT ssl.create_default_context() []]",
			"27:20-56 ctx.e = ssl.create_default_context() [CALL_RESULT ssl.create_default_context() []]",
			"28:9-48 ctx.made = ssl.create_default_context() [CALL_RESULT ssl.create_default_context() []]",
			"29:9-34 self.mode = ssl.CERT_NONE [EXPRESSION ssl.CERT_NONE []]",
			"30:9-34 self.flags |= ssl.flags() [CALL_RESULT ssl.flags() []]",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("stores:\n got %q\nwant %q", got, want)
	}
}

// A module whose only statement is a store still gets its <module>.
func TestPythonAttributeStores_StoreOnlyModule(t *testing.T) {
	t.Parallel()
	analysis := parsePythonSource(t, "config.verify = False\n")
	want := map[string][]string{"<module>": {"1:1-22 config.verify = False [VALUE False []]"}}
	if got := pythonStoresOf(analysis); !reflect.DeepEqual(got, want) {
		t.Errorf("stores = %q, want %q", got, want)
	}
}
