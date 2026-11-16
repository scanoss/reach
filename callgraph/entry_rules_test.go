// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

// TestTraceBackCondensed_TestCodeIsNotAnEntryPoint: a JUnit 3 setUp overrides
// a method of TestCase, a type outside the application, which would make it
// a framework entry. A test runner calls it, not the application, so crypto
// written in it stays unreachable when the test sources are in the graph.
func TestTraceBackCondensed_TestCodeIsNotAnEntryPoint(t *testing.T) {
	t.Parallel()
	setUp := FunctionID{Package: "com.app", Type: "LedgerTest", Name: "setUp"}
	crypto := FunctionID{Package: "java.security", Type: "MessageDigest", Name: "getInstance"}
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{
			setUp.String(): {
				ID: setUp, FilePath: "/repo/src/test/java/com/app/LedgerTest.java", StartLine: 8, EndLine: 12,
				Annotations: []string{"Override"},
				Calls:       []FunctionCall{{Callee: crypto, Line: 10}},
			},
		},
		Callers:          map[string][]string{crypto.String(): {setUp.String()}},
		SourceSupertypes: map[string][]string{"com.app.LedgerTest": {"junit.framework.TestCase"}},
	}

	trace := NewTracer(graph, ".").TraceBackCondensed(setUp, map[string]bool{"com.app": true}, 0, 0)

	if len(trace.Chains) != 0 {
		t.Fatalf("chains = %+v, want none: a test is not an entry point", trace.Chains)
	}
}
