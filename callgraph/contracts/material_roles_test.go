// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package contracts_test

import (
	"strings"
	"testing"

	"github.com/scanoss/reach/callgraph/contracts"
)

// materialKB is a one-contract KB whose material_roles block is roles.
func materialKB(library, roles string) string {
	return `
schema_version: "2"
ecosystem: python
library:
  name: ` + library + `
contracts:
  - method: lib.Kdf.<init>
    arity: 3
    return:
      type: lib.Kdf
      confidence: high
    material_roles:
` + roles + `
hierarchy: {}
`
}

func TestLoad_MaterialRoles_IndexesByPositionAndKeyword(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, materialKB("material-lib", `      - index: 1
        name: salt
        material: salt
      - name: nonce
        material: nonce`))
	ctrs := kb.ContractsFor("lib.Kdf.<init>", 3)
	if len(ctrs) != 1 {
		t.Fatalf("contracts = %d, want 1", len(ctrs))
	}
	c := ctrs[0]
	for _, tc := range []struct {
		index int
		name  string
		want  string
	}{
		{index: 1, want: "salt"},
		{index: -1, name: "salt", want: "salt"},
		{index: -1, name: "nonce", want: "nonce"},
		{index: 0, want: ""},
		{index: 2, want: ""},
		// A keyword names its parameter exactly: a keyword the contract does
		// not declare never falls back to a position.
		{index: 1, name: "length", want: ""},
	} {
		if got := c.MaterialAt(tc.index, tc.name); got != tc.want {
			t.Errorf("MaterialAt(%d, %q) = %q, want %q", tc.index, tc.name, got, tc.want)
		}
	}
}

func TestLoad_MaterialRoles_RejectsInvalidEntries(t *testing.T) {
	t.Parallel()

	for name, tc := range map[string]struct {
		roles string
		want  string
	}{
		"unknown material":    {"      - index: 0\n        material: pepper", `material "pepper" is not a CycloneDX relatedCryptoMaterial type`},
		"other is not a role": {"      - index: 0\n        material: other", `material "other"`},
		"no parameter":        {"      - material: salt", "needs an index or a name"},
		"index at arity":      {"      - index: 3\n        material: salt", "index 3 is outside arity 3"},
		"negative index":      {"      - index: -1\n        material: salt", "index -1 is outside arity 3"},
		"repeated index": {
			"      - index: 1\n        material: salt\n      - index: 1\n        material: nonce",
			"repeats index 1",
		},
		"repeated name": {
			"      - name: salt\n        material: salt\n      - name: salt\n        material: nonce",
			`repeats name "salt"`,
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := contracts.Load([]byte(materialKB("bad-lib", tc.roles)))
			if err == nil {
				t.Fatal("Load succeeded, want an error")
			}
			if !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), "lib.Kdf.<init>") {
				t.Errorf("error %q should contain %q and name the method", err, tc.want)
			}
		})
	}
}

func TestMerge_MaterialRoles_IdenticalIsIdempotent(t *testing.T) {
	t.Parallel()

	a := mustLoad(t, materialKB("material-a", "      - index: 1\n        material: salt\n      - index: 2\n        material: nonce"))
	// The same roles in another order are the same declaration.
	b := mustLoad(t, materialKB("material-b", "      - index: 2\n        material: nonce\n      - index: 1\n        material: salt"))
	merged, err := contracts.Merge(a, b)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	ctrs := merged.ContractsFor("lib.Kdf.<init>", 3)
	if len(ctrs) != 1 || ctrs[0].MaterialAt(1, "") != "salt" {
		t.Fatalf("merged contracts = %+v, want one carrying the salt role", ctrs)
	}
}

func TestMerge_MaterialRoles_DivergentHardErrors(t *testing.T) {
	t.Parallel()

	for name, other := range map[string]string{
		"different material": "      - index: 1\n        material: nonce",
		"different index":    "      - index: 2\n        material: salt",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			a := mustLoad(t, materialKB("material-conflict-a", "      - index: 1\n        material: salt"))
			b := mustLoad(t, materialKB("material-conflict-b", other))
			_, err := contracts.Merge(a, b)
			if err == nil {
				t.Fatal("Merge succeeded, want a conflict")
			}
			for _, want := range []string{"material-conflict-a", "material-conflict-b", "lib.Kdf.<init>#3"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error %q should name %q", err, want)
				}
			}
		})
	}
}
