// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

// Command gen writes the ruleset guard's denylist.txt from a private ruleset
// checkout: the hashes of every rule id and rule message (rulesetguard.Hash)
// of its v3 card files (`rules:` maps) and its OpenGrep rule files (`rules:`
// lists). It writes hashes only; nothing of the ruleset itself.
//
//	go run ./internal/rulesetguard/gen -ruleset <ruleset-dir> -out internal/rulesetguard/denylist.txt
package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/scanoss/reach/internal/rulesetguard"
)

func main() {
	ruleset := flag.String("ruleset", "", "ruleset checkout to read")
	out := flag.String("out", "internal/rulesetguard/denylist.txt", "denylist to write")
	flag.Parse()
	if *ruleset == "" {
		fmt.Fprintln(os.Stderr, "gen: -ruleset is required")
		os.Exit(2)
	}
	hashes, ids, messages, err := collect(*ruleset)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	header := "# Salted, truncated SHA-256 hashes of private ruleset rule ids and messages\n" +
		"# (rulesetguard.Hash). Regenerate with internal/rulesetguard/gen; never edit by hand.\n"
	if err := os.WriteFile(*out, []byte(header+strings.Join(hashes, "\n")+"\n"), 0o644); err != nil { //nolint:gosec // a public list of hashes
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
	fmt.Printf("gen: %d hashes (%d rule ids, %d messages) in %s\n", len(hashes), ids, messages, *out)
}

func collect(root string) (hashes []string, ids, messages int, err error) {
	set := map[string]bool{}
	addMessage := func(v any) {
		if m, ok := v.(string); ok {
			if m = rulesetguard.NormalizeMessage(m); rulesetguard.HashedMessage(m) {
				set[rulesetguard.Hash(m)] = true
				messages++
			}
		}
	}
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
		switch filepath.Ext(path) {
		case ".cards", ".yaml", ".yml":
		default:
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc struct {
			Rules yaml.Node `yaml:"rules"`
		}
		if yaml.Unmarshal(data, &doc) != nil {
			return nil // not a rule file
		}
		switch doc.Rules.Kind {
		case yaml.MappingNode: // v3 card file: id -> entry
			for i := 0; i+1 < len(doc.Rules.Content); i += 2 {
				set[rulesetguard.Hash(doc.Rules.Content[i].Value)] = true
				ids++
				var entry map[string]any
				if doc.Rules.Content[i+1].Decode(&entry) == nil {
					addMessage(entry["message"])
				}
			}
		case yaml.SequenceNode: // OpenGrep rule file: [{id, message, ...}]
			var rules []map[string]any
			if doc.Rules.Decode(&rules) != nil {
				return nil
			}
			for _, r := range rules {
				if id, ok := r["id"].(string); ok {
					set[rulesetguard.Hash(id)] = true
					ids++
				}
				addMessage(r["message"])
			}
		}
		return nil
	})
	for h := range set {
		hashes = append(hashes, h)
	}
	slices.Sort(hashes)
	return hashes, ids, messages, err
}
