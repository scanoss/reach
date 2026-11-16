// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

// A component mined alone guesses the owner of a type it imports on demand
// (oauth2-oidc-sdk: ConfigurableJWTProcessor from com.nimbusds.jwt.proc.*) as
// its own package. Once a dependency JAR's bytecode declares one alternative,
// the call moves there, and the caller index follows it.
func TestReanchorGuessedJavaOwnersFromBytecode(t *testing.T) {
	callerID := FunctionID{Package: "com.nimbusds.openid.connect.sdk.validators", Type: "IDTokenValidator", Name: "validate#2"}
	guessed := FunctionID{Package: "com.nimbusds.openid.connect.sdk.validators", Type: "ConfigurableJWTProcessor", Name: "process#2"}
	ambiguous := FunctionID{Package: "com.nimbusds.openid.connect.sdk.validators", Type: "Twice", Name: "run#0"}
	caller := &FunctionDecl{ID: callerID, Calls: []FunctionCall{
		{Callee: guessed, OwnerAlternatives: []string{
			"com.nimbusds.openid.connect.sdk.validators.ConfigurableJWTProcessor",
			"com.nimbusds.jose.ConfigurableJWTProcessor",
			"com.nimbusds.jwt.proc.ConfigurableJWTProcessor",
		}},
		{Callee: ambiguous, OwnerAlternatives: []string{
			"com.nimbusds.openid.connect.sdk.validators.Twice", "a.Twice", "b.Twice",
		}},
	}}
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{callerID.String(): caller},
		Callers:   map[string][]string{guessed.String(): {callerID.String()}},
		TypeHierarchy: map[string][]string{
			"com.nimbusds.jwt.proc.ConfigurableJWTProcessor": {"com.nimbusds.jwt.proc.JWTProcessor"},
			"a.Twice": {"java.lang.Object"}, "b.Twice": {"java.lang.Object"},
		},
	}
	if moved := reanchorGuessedJavaOwnersFromBytecode(graph); moved != 1 {
		t.Fatalf("moved = %d, want 1", moved)
	}
	if got := caller.Calls[0].Callee.Package; got != "com.nimbusds.jwt.proc" {
		t.Fatalf("callee package = %q, want com.nimbusds.jwt.proc", got)
	}
	if got := caller.Calls[1].Callee.Package; got != ambiguous.Package {
		t.Fatalf("two declaring alternatives must leave the guess: package = %q", got)
	}
	if len(graph.Callers[guessed.String()]) != 0 || len(graph.Callers[caller.Calls[0].Callee.String()]) != 1 {
		t.Fatalf("caller index not moved: %v", graph.Callers)
	}
}
