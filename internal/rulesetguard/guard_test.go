// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package rulesetguard

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRepositoryHoldsNoRulesetContent reads every file of the repository.
func TestRepositoryHoldsNoRulesetContent(t *testing.T) {
	allowed, err := ReadAllowed("allowed_ids.txt")
	if err != nil {
		t.Fatal(err)
	}
	findings, files, err := Check(filepath.Join("..", ".."), allowed)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Error(f)
	}
	if files < 100 {
		t.Fatalf("read %d files; the walk missed the repository", files)
	}
}

// Scan finds a rule-id-shaped token allowed does not list, and passes
// invented ids and Java package paths.
func TestScan(t *testing.T) {
	allowed := map[string]bool{"java.acme.invented-rule": true}
	text := strings.Join([]string{
		`RuleID: "python.foo.bar-baz"`,
		`RuleID: "java.acme.invented-rule"`,
		`call: java.security.MessageDigest.getInstance`,
		`id: acme.hash`,
	}, "\n")
	got := Scan(text, allowed)
	if len(got) != 1 || got[0].Line != 1 {
		t.Fatalf("findings = %+v, want the id-shaped token on line 1", got)
	}
}

// CryptoRules finds OpenGrep, card-map and card-list rules with a CycloneDX
// crypto block, and passes rules without one and files that are no rule file.
func TestCryptoRules(t *testing.T) {
	cases := []struct {
		name, yaml string
		want       []string
	}{
		{"opengrep", "rules:\n- id: acme.a\n  metadata:\n    crypto:\n      assetType: algorithm\n- id: acme.b\n  metadata: {}\n", []string{"acme.a"}},
		{"cards", "rules:\n  acme.c:\n    crypto:\n      assetType: related-crypto-material\n  acme.d:\n    crypto:\n      assetType: other\n", []string{"acme.c"}},
		{"card list", "cards:\n- rule: acme-e\n  crypto:\n    assetType: protocol\n- rule: acme-f\n", []string{"acme-e"}},
		{"entry points", "framework: acme\nentry_points:\n- name: run\n", nil},
		{"no yaml", ":\t[", nil},
	}
	for _, c := range cases {
		if got := CryptoRules([]byte(c.yaml)); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// RuleFile tells a rule or card file from other YAML.
func TestRuleFile(t *testing.T) {
	cases := []struct {
		yaml string
		want bool
	}{
		{"rules:\n- id: a\n", true},
		{"rules:\n  a: {}\n", true},
		{"cards:\n- rule: a\n", true},
		{"framework: acme\nentry_points: []\n", false},
		{"rules: 3\n", false},
		{":\t[", false},
	}
	for _, c := range cases {
		if got := RuleFile([]byte(c.yaml)); got != c.want {
			t.Errorf("RuleFile(%q) = %v, want %v", c.yaml, got, c.want)
		}
	}
}

// plant writes files under a temporary root and returns what Check finds
// there with no invented ids allowed.
func plant(t *testing.T, files map[string]string) []string {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	findings, _, err := Check(root, map[string]bool{})
	if err != nil {
		t.Fatal(err)
	}
	return findings
}

// pastedRule is an invented rule file shaped like a real detection ruleset's:
// a namespaced id with a dash, a sentence for a message and a CycloneDX block.
// The id is split so this file holds no id-shaped token itself.
var pastedRule = `rules:
- id: ` + "java" + `.acme-jca.cipher.aes-gcm-encrypt
  languages: [java]
  severity: INFO
  message: AES in GCM mode is used to encrypt data with an AcmeCipher
  metadata:
    crypto:
      assetType: algorithm
      algorithmFamily: AES
      primitive: ae
      mode: gcm
  pattern: AcmeCipher.getInstance("AES/GCM/NoPadding")
`

var pastedCard = `rules:
  ` + "python" + `.acme-crypto.hash.sha256-digest:
    crypto:
      assetType: algorithm
      algorithmFamily: SHA-2
`

// A rule file or card file pasted outside testdata is caught by its structure
// and by the shape of its ids.
func TestCheckCatchesPastedRuleFile(t *testing.T) {
	got := plant(t, map[string]string{
		"rules/java/cipher.yaml":   pastedRule,
		"rules/python/hash.cards":  pastedCard,
		"rules/python/README.yaml": "framework: acme\n",
	})
	want := []string{
		"rules/java/cipher.yaml:2: a rule-id-shaped token (java.acme-jca.cipher.aes-gcm-encrypt) is not in allowed_ids.txt",
		"rules/java/cipher.yaml: rule java.acme-jca.cipher.aes-gcm-encrypt carries a CycloneDX crypto block outside testdata",
		"rules/python/hash.cards:2: a rule-id-shaped token (python.acme-crypto.hash.sha256-digest) is not in allowed_ids.txt",
		"rules/python/hash.cards: rule python.acme-crypto.hash.sha256-digest carries a CycloneDX crypto block outside testdata",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A rule or card file under testdata must say it is invented.
func TestCheckWantsInventedMarkerInTestdata(t *testing.T) {
	fixture := "rules:\n- id: seal\n  message: m\n  metadata: {crypto: {assetType: algorithm}}\n  pattern: acme.Seal(...)\n"
	got := plant(t, map[string]string{
		"pkg/testdata/marked/rules.yaml":   InventedMarker + "\n" + fixture,
		"pkg/testdata/unmarked/rules.yaml": fixture,
		"pkg/testdata/unmarked/x.cards":    "cards:\n- rule: seal\n",
		"pkg/testdata/other.yaml":          "framework: acme\n",
	})
	want := []string{
		"pkg/testdata/unmarked/rules.yaml: a rule file in testdata lacks the line `" + InventedMarker + "`",
		"pkg/testdata/unmarked/x.cards: a rule file in testdata lacks the line `" + InventedMarker + "`",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
