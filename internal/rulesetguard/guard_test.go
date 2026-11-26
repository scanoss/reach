// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package rulesetguard

import (
	"bufio"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func readSet(t *testing.T, name string) map[string]bool {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	set := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			set[line] = true
		}
	}
	return set
}

// TestRepositoryHoldsNoRulesetContent reads every file of the repository.
func TestRepositoryHoldsNoRulesetContent(t *testing.T) {
	denied, allowed := readSet(t, "denylist.txt"), readSet(t, "allowed_ids.txt")
	if len(denied) == 0 {
		t.Fatal("denylist.txt is empty")
	}
	root := filepath.Join("..", "..")
	own, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	files := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if abs, _ := filepath.Abs(filepath.Dir(path)); abs == own && (d.Name() == "denylist.txt" || d.Name() == "allowed_ids.txt") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.IndexByte(data, 0) >= 0 {
			return nil // binary
		}
		files++
		for _, f := range Scan(string(data), denied, allowed) {
			t.Errorf("%s:%d: %s", path, f.Line, f.Reason)
		}
		if yamlFile(path) && !inTestdata(path) {
			for _, id := range CryptoRules(data) {
				t.Errorf("%s: rule %s carries a CycloneDX crypto block outside testdata", path, id)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files < 100 {
		t.Fatalf("read %d files; the walk missed the repository", files)
	}
}

func yamlFile(path string) bool {
	switch filepath.Ext(path) {
	case ".yaml", ".yml", ".cards":
		return true
	}
	return false
}

func inTestdata(path string) bool {
	return slices.Contains(strings.Split(filepath.ToSlash(path), "/"), "testdata")
}

// The guard finds a denied id, a denied message and an id-shaped token, and
// passes invented ones.
func TestScan(t *testing.T) {
	denied := map[string]bool{Hash("go.acme.secret-rule-id"): true, Hash("A private message of a real rule here"): true}
	allowed := map[string]bool{"java.acme.invented-rule": true}
	text := strings.Join([]string{
		`id: go.acme.secret-rule-id`,
		`  message: "A private  message of a real rule here"`,
		`RuleID: "python.foo.bar-baz"`,
		`RuleID: "java.acme.invented-rule"`,
		`call: java.security.MessageDigest.getInstance`,
		`id: acme.hash`,
	}, "\n")
	got := Scan(text, denied, allowed)
	lines := make([]int, len(got))
	for i, f := range got {
		lines[i] = f.Line
	}
	if len(got) != 4 || lines[0] != 1 || lines[1] != 1 || lines[2] != 2 || lines[3] != 3 {
		t.Fatalf("findings = %+v, want the id (twice: hash and shape), the message and the id-shaped token", got)
	}
}

// CryptoRules finds OpenGrep and card rules with a CycloneDX crypto block,
// and passes rules without one and files that are no rule file.
func TestCryptoRules(t *testing.T) {
	cases := []struct {
		name, yaml string
		want       []string
	}{
		{"opengrep", "rules:\n- id: acme.a\n  metadata:\n    crypto:\n      assetType: algorithm\n- id: acme.b\n  metadata: {}\n", []string{"acme.a"}},
		{"cards", "rules:\n  acme.c:\n    crypto:\n      assetType: related-crypto-material\n  acme.d:\n    crypto:\n      assetType: other\n", []string{"acme.c"}},
		{"entry points", "framework: acme\nentry_points:\n- name: run\n", nil},
		{"no yaml", ":\t[", nil},
	}
	for _, c := range cases {
		if got := CryptoRules([]byte(c.yaml)); !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
