// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag_test

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// Property reads are written by file path with their keys, text and span,
// end_line, receiver_var and assigned_var only when set, and read back as
// written.
func TestGraphFragmentPropertyReadsRoundTrip(t *testing.T) {
	export := graphfrag.GraphFragmentExport{PropertyReads: map[string][]graphfrag.GraphFragmentPropertyRead{
		"src/a.js": {
			{
				CallerKey: "app/a.<module>", TargetKey: "acme-crypto.enums.hash.md5", MethodName: "md5",
				Raw: "acme.enums.hash.md5", Line: 2, StartCol: 11, EndCol: 30, AssignedVar: "h",
			},
			{
				CallerKey: "app/a.print", TargetKey: "acme-crypto.(Cert).fingerprint", MethodName: "fingerprint",
				Raw: "c\n  .fingerprint", Line: 5, StartCol: 10, EndLine: 6, EndCol: 15, ReceiverVar: "c",
			},
		},
	}}
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	want := `"property_reads":{"src/a.js":[` +
		`{"caller_key":"app/a.\u003cmodule\u003e","target_key":"acme-crypto.enums.hash.md5","method_name":"md5",` +
		`"raw":"acme.enums.hash.md5","line":2,"start_col":11,"end_col":30,"assigned_var":"h"},` +
		`{"caller_key":"app/a.print","target_key":"acme-crypto.(Cert).fingerprint","method_name":"fingerprint",` +
		`"raw":"c\n  .fingerprint","line":5,"start_col":10,"end_line":6,"end_col":15,"receiver_var":"c"}]}`
	if !strings.Contains(text, want) {
		t.Errorf("property read JSON:\n got  %s\n want it to hold %s", text, want)
	}
	if strings.Index(text, `"object_literals"`) > strings.Index(text, `"property_reads"`) {
		t.Errorf("property_reads is not written after object_literals: %s", text)
	}
	var back graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.PropertyReads, export.PropertyReads) {
		t.Errorf("property reads read back as %+v, want %+v", back.PropertyReads, export.PropertyReads)
	}
	empty, err := json.Marshal(graphfrag.GraphFragmentExport{})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(empty), "property_reads") {
		t.Errorf("a fragment without property reads writes the field: %s", empty)
	}
}

// candidate_modules is written on an external call and a property read only
// when set, sorted as given, and read back as written.
func TestGraphFragmentCandidateModulesRoundTrip(t *testing.T) {
	modules := []string{"acme-h/sha256", "acme-h/sha3"}
	export := graphfrag.GraphFragmentExport{
		ExternalCalls: []graphfrag.GraphFragmentExternal{
			{CallerKey: "app.<module>", TargetKey: "app.sha256", Resolution: "exact", Line: 2, CandidateModules: modules},
			{CallerKey: "app.<module>", TargetKey: "app.other", Resolution: "exact", Line: 3},
		},
		PropertyReads: map[string][]graphfrag.GraphFragmentPropertyRead{
			"a.js": {{CallerKey: "app.<module>", TargetKey: "app.sha256", MethodName: "sha256", Raw: "H.sha256", Line: 4, StartCol: 14, EndCol: 22, CandidateModules: modules}},
		},
	}
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if got := strings.Count(text, `"candidate_modules":["acme-h/sha256","acme-h/sha3"]`); got != 2 {
		t.Errorf("candidate_modules written %d times, want 2 (one call, one read): %s", got, text)
	}
	var back graphfrag.GraphFragmentExport
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back.ExternalCalls, export.ExternalCalls) || !reflect.DeepEqual(back.PropertyReads, export.PropertyReads) {
		t.Errorf("read back as %+v / %+v", back.ExternalCalls, back.PropertyReads)
	}
	frag, err := graphfrag.DecodeFragment(graphfrag.ComponentKey{Purl: "pkg:npm/app", Version: "1.0.0"}, data)
	if err != nil {
		t.Fatal(err)
	}
	if len(frag.ExternalCalls) != 2 || !reflect.DeepEqual(frag.ExternalCalls[0].CandidateModules, modules) {
		t.Errorf("decoded external calls = %+v, want the candidates on the first", frag.ExternalCalls)
	}
}
