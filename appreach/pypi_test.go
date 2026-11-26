// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package appreach

import (
	"testing"
)

// A PyPI version is read in its PEP 440 normal form; a legacy version that
// PEP 440 cannot parse stays as written.
func TestPyPIVersion(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"2.10.0":            "2.10.0",
		" 1.0 ":             "1.0",
		"v1.0":              "1.0",
		"1.0.0-RC1":         "1.0.0rc1",
		"1.0.0.c1":          "1.0.0rc1",
		"1.0.0preview2":     "1.0.0rc2",
		"1.0a":              "1.0a0",
		"1.0-alpha.1":       "1.0a1",
		"1.0.Beta-2":        "1.0b2",
		"1.0-1":             "1.0.post1",
		"1.0.post":          "1.0.post0",
		"1.0-rev3":          "1.0.post3",
		"1.0_DEV4":          "1.0.dev4",
		"1.0rc1.post2.dev3": "1.0rc1.post2.dev3",
		"01.002.0003":       "1.2.3",
		"0!1.0":             "1.0",
		"2!1.0":             "2!1.0",
		"1.0+Ubuntu-1_A":    "1.0+ubuntu.1.a",
		"2004d":             "2004d",
		"french toast":      "french toast",
	} {
		if got := PyPIVersion(in); got != want {
			t.Errorf("PyPIVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

// PEP 440 equality pads the release with zeros.
func TestPyPIVersionsEqual(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"1.0", "1.0.0", true},
		{"1", "1.0.0.0", true},
		{"1.0rc1", "1.0.0-RC1", true},
		{"1.0", "1.0.1", false},
		{"1.0", "1.0.post0", false},
		{"1.0+local", "1.0", false},
		{"2004d", "2004d", true},
		{"2004d", "2004D", false},
	} {
		if got := PyPIVersionsEqual(c.a, c.b); got != c.want {
			t.Errorf("PyPIVersionsEqual(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}

// A PyPI dependency is pinned under its PEP 503 name and PEP 440 version; two
// spellings of one release are one dependency, two releases conflict. Maven
// purls and versions are read as before.
