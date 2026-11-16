// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestGraphFragmentLocalBindingJSON(t *testing.T) {
	t.Parallel()
	binding := GraphFragmentLocalBinding{Function: 2, Name: "cipher", Line: 7, Col: 5, EffectLine: 7, EffectCol: 44,
		BlockEndLine: 12, BlockEndCol: 20, LoopLine: 6, LoopCol: 5}
	data, err := json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	const want = `[2,"cipher",7,5,7,44,12,20,6,5]`
	if string(data) != want {
		t.Fatalf("encoding = %s, want %s", data, want)
	}
	var back GraphFragmentLocalBinding
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, binding) {
		t.Errorf("decoded %+v, want %+v", back, binding)
	}
	unpacked := GraphFragmentLocalBinding{Function: 1, Name: "priv", Line: 3, Col: 5, EffectLine: 3, EffectCol: 37,
		BlockEndLine: 4, BlockEndCol: 28, Unpacked: true, Element: 1, ValueLine: 3, ValueCol: 17}
	data, err = json.Marshal(unpacked)
	if err != nil {
		t.Fatal(err)
	}
	if want := `[1,"priv",3,5,3,37,4,28,0,0,1,3,17]`; string(data) != want {
		t.Fatalf("encoding = %s, want %s", data, want)
	}
	back = GraphFragmentLocalBinding{}
	if err := json.Unmarshal(data, &back); err != nil || !reflect.DeepEqual(back, unpacked) {
		t.Errorf("decoded %+v (%v), want %+v", back, err, unpacked)
	}
	for _, bad := range []string{`[2,"cipher",7,5,7,44,12,20,6]`, `[2,7,5,7,44,12,20,6,5,1]`, `[2,"cipher",7,5,7,44,12,20,6,5,0,1]`,
		`[2,"cipher",7,5,7,44,12,20,6,5,0,1,2,3]`} {
		if err := json.Unmarshal([]byte(bad), &back); err == nil {
			t.Errorf("%s decoded without error", bad)
		}
	}
}
