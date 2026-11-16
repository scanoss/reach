// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestGraphFragmentRebindRoundTrips(t *testing.T) {
	in := []GraphFragmentRebind{{Function: 3, Name: "iv", Lines: []int{12, 15}}, {Function: 7}}
	data, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(data), `[[3,"iv",12,15],[7]]`; got != want {
		t.Fatalf("encoded = %s, want %s", got, want)
	}
	var out []GraphFragmentRebind
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(out, in) {
		t.Errorf("decoded = %+v, want %+v", out, in)
	}
	if out[0].Unread() || !out[1].Unread() {
		t.Errorf("unread = %v, %v; want only the bare function unread", out[0].Unread(), out[1].Unread())
	}
	for _, bad := range []string{`[]`, `[1,"iv"]`, `[1,"",4]`, `["x"]`, `[1,"iv","x"]`} {
		var r GraphFragmentRebind
		if err := json.Unmarshal([]byte(bad), &r); err == nil {
			t.Errorf("%s decoded as %+v, want an error", bad, r)
		}
	}
}
