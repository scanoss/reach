// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestGraphFragmentAttributeStoreJSON(t *testing.T) {
	t.Parallel()
	store := GraphFragmentAttributeStore{
		Function: 3, Line: 9, StartCol: 5, EndCol: 31, EndLine: 10,
		Receiver: "self._ctx", Attribute: "options", Operator: "|=",
		Value: GraphFragmentParameter{ArgumentExpression: "ssl.OP_NO_TLSv1", ResolvedValue: "ssl.OP_NO_TLSv1"},
	}
	data, err := json.Marshal(store)
	if err != nil {
		t.Fatal(err)
	}
	const want = `[3,9,5,31,"self._ctx","options","|=",10,{"parameter_index":0,"argument_expression":"ssl.OP_NO_TLSv1","resolved_value":"ssl.OP_NO_TLSv1"}]`
	if string(data) != want {
		t.Fatalf("encoding = %s, want %s", data, want)
	}
	var back GraphFragmentAttributeStore
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, store) {
		t.Errorf("decoded %+v, want %+v", back, store)
	}
	for _, bad := range []string{`[3,9,5,31,"a","b","=",0]`, `[3,9,5,31,"a","b","=",0,{},1]`, `[3,9,5,31,"a","b","=","x",{}]`} {
		if err := json.Unmarshal([]byte(bad), &back); err == nil {
			t.Errorf("%s decoded without error", bad)
		}
	}
}
