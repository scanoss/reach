// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

// The key of an access is the one a caller's graph and the owning package's
// exports both derive from the steps, and it reads back as the function ID it
// was built from.
func TestNodeAccessKey(t *testing.T) {
	t.Parallel()
	name := func(n string) nodeAccessStep { return nodeAccessStep{name: n} }
	call := func(n string) nodeAccessStep { return nodeAccessStep{name: n, call: true} }
	ctor := func(n string) nodeAccessStep { return nodeAccessStep{name: n, ctor: true} }
	cases := []struct {
		steps []nodeAccessStep
		want  string
	}{
		{[]nodeAccessStep{call("client"), name("getKey")}, "fc.(client()).getKey"},
		{[]nodeAccessStep{ctor("Totp"), name("validate")}, "fc.(Totp).validate"},
		{[]nodeAccessStep{ctor("Totp")}, "fc.(Totp).<init>"},
		{[]nodeAccessStep{name("a"), ctor("K"), call("open"), name("read")}, "fc.a.(K>open()).read"},
		{[]nodeAccessStep{call("make")}, "fc.(make()).<result>"},
		{[]nodeAccessStep{call("make"), call("")}, "fc.(make()>()).<result>"},
		{[]nodeAccessStep{call(""), name("sign")}, "fc.(default()).sign"},
		{[]nodeAccessStep{ctor(""), name("connect")}, "fc.(default).connect"},
		{[]nodeAccessStep{call("create"), name("pool"), name("query")}, "fc.(create()>pool).query"},
		{[]nodeAccessStep{name("a"), name("b")}, ""},
		{[]nodeAccessStep{call("make"), ctor("K"), name("m")}, ""},
		{nil, ""},
	}
	for _, tc := range cases {
		id, ok := nodeAccessKey("fc", tc.steps)
		if got := id.String(); ok != (tc.want != "") || (ok && got != tc.want) {
			t.Errorf("nodeAccessKey(%v) = %q (ok %v), want %q", tc.steps, got, ok, tc.want)
			continue
		}
		if !ok {
			continue
		}
		if parsed, err := ParseFunctionID(tc.want); err != nil || parsed != id {
			t.Errorf("ParseFunctionID(%q) = %+v, %v; want %+v", tc.want, parsed, err, id)
		}
	}
	if id, ok := (&nodeValueAccess{module: "fc", steps: []nodeAccessStep{name("a"), name("b")}}).key(); !ok || id.String() != "fc.a.b" {
		t.Errorf("member path key = %q (ok %v), want fc.a.b", id.String(), ok)
	}
	if _, ok := (&nodeValueAccess{module: "crypto", runtime: true, steps: []nodeAccessStep{call("createHash"), name("update")}}).key(); ok {
		t.Error("a runtime module's value has a key")
	}
	long := &nodeValueAccess{module: "fc"}
	for range nodeAccessMaxSteps {
		long = long.then(name("a"))
	}
	if long == nil || long.then(name("b")) != nil {
		t.Errorf("an access of %d steps takes another step", nodeAccessMaxSteps)
	}
}
