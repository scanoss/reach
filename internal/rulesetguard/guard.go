// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package rulesetguard

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// idShapeRE is the shape of a ruleset rule id: a language, then at least
// two dotted, lower-case segments, one of them with a dash.
var idShapeRE = regexp.MustCompile(`\b(?:c|cpp|csharp|go|java|javascript|python|ruby|rust|typescript)(?:\.[a-z0-9_]+(?:-[a-z0-9_]+)*){2,}\b`)

// allowedFile is the list of invented rule-id-shaped tokens, relative to the
// repository root. Check does not scan it.
const allowedFile = "internal/rulesetguard/allowed_ids.txt"

// Finding is one match of the guard in a file.
type Finding struct {
	Line   int
	Reason string
}

// Scan returns the rule-id-shaped tokens of text that allowed does not list.
func Scan(text string, allowed map[string]bool) []Finding {
	var out []Finding
	for i, line := range strings.Split(text, "\n") {
		for _, id := range idShapeRE.FindAllString(line, -1) {
			if strings.Contains(id, "-") && !allowed[id] {
				out = append(out, Finding{i + 1, "a rule-id-shaped token (" + id + ") is not in allowed_ids.txt"})
			}
		}
	}
	return out
}

// ReadAllowed reads an allow-list: one id per line, `#` comments.
func ReadAllowed(name string) (map[string]bool, error) {
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if line := strings.TrimSpace(sc.Text()); line != "" && !strings.HasPrefix(line, "#") {
			set[line] = true
		}
	}
	return set, sc.Err()
}

// Check walks the tree at root, skipping .git, and returns what the guard
// finds, each as `<path>[:<line>]: <reason>` with root-relative paths, and
// the number of text files it read:
//
//   - a rule-id-shaped token that allowed does not list;
//   - a YAML or card file outside testdata whose rules carry a CycloneDX
//     crypto block;
//   - a rule or card file inside testdata without the InventedMarker line.
func Check(root string, allowed map[string]bool) ([]string, int, error) {
	var out []string
	files := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == allowedFile {
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
		for _, f := range Scan(string(data), allowed) {
			out = append(out, fmt.Sprintf("%s:%d: %s", rel, f.Line, f.Reason))
		}
		if !yamlFile(rel) {
			return nil
		}
		if inTestdata(rel) {
			if RuleFile(data) && !Invented(data) {
				out = append(out, fmt.Sprintf("%s: a rule file in testdata lacks the line `%s`", rel, InventedMarker))
			}
			return nil
		}
		for _, id := range CryptoRules(data) {
			out = append(out, fmt.Sprintf("%s: rule %s carries a CycloneDX crypto block outside testdata", rel, id))
		}
		return nil
	})
	return out, files, err
}

func yamlFile(path string) bool {
	switch filepath.Ext(path) {
	case ".yaml", ".yml", ".cards":
		return true
	}
	return false
}

func inTestdata(path string) bool {
	return slices.Contains(strings.Split(path, "/"), "testdata")
}
