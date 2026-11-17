// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag_test

import (
	"testing"

	"github.com/scanoss/reach/graphfrag"
)

// TestGraphAlgoVersionFor pins which id each ecosystem's graphs carry:
// Python, Rust, Node and Go their own, Java and the rest the shared one, and a
// fragment that names no ecosystem (written before scan_metadata.ecosystem) the shared one, so a
// stored Java graph reads as current exactly when it did before.
func TestGraphAlgoVersionFor(t *testing.T) {
	if graphfrag.GraphAlgoVersionPython == graphfrag.GraphAlgoVersion {
		t.Fatalf("Python shares the Java graph algorithm id %q", graphfrag.GraphAlgoVersion)
	}
	if graphfrag.GraphAlgoVersionRust == graphfrag.GraphAlgoVersion {
		t.Fatalf("Rust shares the Java graph algorithm id %q", graphfrag.GraphAlgoVersion)
	}
	if graphfrag.GraphAlgoVersionNode == graphfrag.GraphAlgoVersion || graphfrag.GraphAlgoVersionNode == graphfrag.GraphAlgoVersionPython || graphfrag.GraphAlgoVersionNode == graphfrag.GraphAlgoVersionRust {
		t.Fatalf("Node shares a graph algorithm id: %q", graphfrag.GraphAlgoVersionNode)
	}
	if graphfrag.GraphAlgoVersionGo == graphfrag.GraphAlgoVersion {
		t.Fatalf("Go shares the Java graph algorithm id %q", graphfrag.GraphAlgoVersion)
	}
	for _, c := range []struct{ ecosystem, want string }{
		{"java", graphfrag.GraphAlgoVersion},
		{"", graphfrag.GraphAlgoVersion},
		{"go", graphfrag.GraphAlgoVersionGo},
		{"python", graphfrag.GraphAlgoVersionPython},
		{"rust", graphfrag.GraphAlgoVersionRust},
		{"node", graphfrag.GraphAlgoVersionNode},
	} {
		if got := graphfrag.GraphAlgoVersionFor(c.ecosystem); got != c.want {
			t.Errorf("GraphAlgoVersionFor(%q) = %q, want %q", c.ecosystem, got, c.want)
		}
	}
	for _, c := range []struct{ purl, want string }{
		{"pkg:maven/org.bouncycastle/bcprov-jdk18on", graphfrag.GraphAlgoVersion},
		{"pkg:pypi/pyjwt", graphfrag.GraphAlgoVersionPython},
		{"pkg:npm/jose", graphfrag.GraphAlgoVersionNode},
		{"pkg:cargo/acme_kdf", graphfrag.GraphAlgoVersionRust},
		{"pkg:golang/filippo.io/age", graphfrag.GraphAlgoVersionGo},
	} {
		if got := graphfrag.GraphAlgoVersionForPurl(c.purl); got != c.want {
			t.Errorf("GraphAlgoVersionForPurl(%q) = %q, want %q", c.purl, got, c.want)
		}
	}
}

// TestGraphEcosystem: a stored graph names its ecosystem in its scan
// metadata; a Python, Rust, Node or Go graph whose metadata names none still
// reads as its ecosystem by its graph algorithm id, and a graph that names
// neither reads as "" (a Java graph written before scan_metadata.ecosystem).
func TestGraphEcosystem(t *testing.T) {
	for _, c := range []struct {
		meta graphfrag.GraphFragmentScanMetadata
		want string
	}{
		{graphfrag.GraphFragmentScanMetadata{Ecosystem: "python", GraphAlgoVersion: graphfrag.GraphAlgoVersionPython}, "python"},
		{graphfrag.GraphFragmentScanMetadata{GraphAlgoVersion: "graph-algo-py-12"}, "python"},
		{graphfrag.GraphFragmentScanMetadata{GraphAlgoVersion: graphfrag.GraphAlgoVersionRust}, "rust"},
		{graphfrag.GraphFragmentScanMetadata{Ecosystem: "node", GraphAlgoVersion: graphfrag.GraphAlgoVersionNode}, "node"},
		{graphfrag.GraphFragmentScanMetadata{GraphAlgoVersion: graphfrag.GraphAlgoVersionNode}, "node"},
		{graphfrag.GraphFragmentScanMetadata{GraphAlgoVersion: graphfrag.GraphAlgoVersionGo}, "go"},
		{graphfrag.GraphFragmentScanMetadata{Ecosystem: "java", GraphAlgoVersion: graphfrag.GraphAlgoVersion}, "java"},
		{graphfrag.GraphFragmentScanMetadata{GraphAlgoVersion: graphfrag.GraphAlgoVersion}, ""},
		{graphfrag.GraphFragmentScanMetadata{}, ""},
	} {
		export := graphfrag.GraphFragmentExport{ScanMetadata: c.meta}
		if got := export.GraphEcosystem(); got != c.want {
			t.Errorf("GraphEcosystem(%+v) = %q, want %q", c.meta, got, c.want)
		}
	}
}
