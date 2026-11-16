// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

// componentKeyLess must order exactly as the String forms do: the stitch's
// traversal orders, and so its served chains, depend on it.
func TestComponentKeyLessOrdersAsString(t *testing.T) {
	t.Parallel()
	keys := []ComponentKey{
		{}, {Purl: "a"}, {Purl: "a", Version: "1"}, {Purl: "a", Version: "10"}, {Purl: "a", Version: "2"},
		{Purl: "a-b"}, {Purl: "a-b", Version: "1"}, {Purl: "a@"}, {Purl: "a@1"}, {Purl: "a@1", Version: "0"},
		{Purl: "a@0"}, {Purl: "a@0", Version: "9"}, {Purl: "aA", Version: "1"}, {Purl: "a", Version: "1@"},
		{Purl: "pkg:maven/org.bouncycastle/bcprov-jdk18on", Version: "1.78"},
		{Purl: "pkg:maven/org.bouncycastle/bcprov-jdk18", Version: "1.78"},
		{Purl: "pkg:maven/org.bouncycastle/bcpkix-jdk18on", Version: "1.78"},
		{Purl: "", Version: "1"},
	}
	for _, a := range keys {
		for _, b := range keys {
			if got, want := componentKeyLess(a, b), a.String() < b.String(); got != want {
				t.Errorf("componentKeyLess(%q, %q) = %v, want %v", a, b, got, want)
			}
		}
	}
}
