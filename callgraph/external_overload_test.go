// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

func TestSelectExternalOverload(t *testing.T) {
	sha3 := []ExternalMethodSignature{
		{ParameterTypes: []string{"org.bouncycastle.crypto.CryptoServicePurpose"}},
		{ParameterTypes: []string{"org.bouncycastle.crypto.digests.SHA3Digest"}},
		{ParameterTypes: []string{"int"}},
		{ParameterTypes: []string{"int", "org.bouncycastle.crypto.CryptoServicePurpose"}},
		{ParameterTypes: nil},
	}
	tests := []struct {
		name   string
		call   FunctionCall
		want   string
		wantOK bool
	}{
		{"int literal picks int", FunctionCall{Arguments: []string{"256"}}, "int", true},
		{"literal through data flow", FunctionCall{Arguments: []string{"bits"}, ArgumentSources: [][]SourceNode{{{Type: "VALUE", Value: "256"}}}}, "int", true},
		{"declared type picks its overload", FunctionCall{Arguments: []string{"other"}, ArgumentSources: [][]SourceNode{{{Type: "VARIABLE", DeclaredType: "SHA3Digest"}}}}, "org.bouncycastle.crypto.digests.SHA3Digest", true},
		{"unknown argument stays ambiguous", FunctionCall{Arguments: []string{"x"}}, "", false},
		{"single arity candidate", FunctionCall{Arguments: []string{"a", "b"}}, "int", true},
		{"no candidate of that arity", FunctionCall{Arguments: []string{"a", "b", "c"}}, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := SelectExternalOverload(sha3, &tt.call)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if ok && got.ParameterTypes[0] != tt.want {
				t.Fatalf("picked %v, want first parameter %s", got.ParameterTypes, tt.want)
			}
		})
	}
}
