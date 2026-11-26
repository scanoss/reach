// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package rulesetguard

import (
	"bytes"
	"fmt"

	"go.yaml.in/yaml/v3"
)

// InventedMarker is the line a rule or card file under testdata carries to
// say its rules were made up for a test, not taken from a ruleset.
const InventedMarker = "# rulesetguard: invented"

// Invented reports whether data holds the InventedMarker line.
func Invented(data []byte) bool {
	for _, line := range bytes.Split(data, []byte("\n")) {
		if string(bytes.TrimSpace(line)) == InventedMarker {
			return true
		}
	}
	return false
}

// RuleFile reports whether data is a rule or card file: YAML whose top level
// holds a `rules:` list or map, or a `cards:` list.
func RuleFile(data []byte) bool {
	var doc struct {
		Rules yaml.Node `yaml:"rules"`
		Cards yaml.Node `yaml:"cards"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return false
	}
	return doc.Rules.Kind == yaml.SequenceNode || doc.Rules.Kind == yaml.MappingNode || doc.Cards.Kind == yaml.SequenceNode
}

// assetTypes are the CycloneDX 1.7 cryptoProperties.assetType values a
// detection rule carries.
var assetTypes = map[string]bool{
	"algorithm":               true,
	"certificate":             true,
	"protocol":                true,
	"related-crypto-material": true,
}

// CryptoRules returns the rules of a YAML file that look like a detection
// ruleset's: a `rules:` list (OpenGrep) or map (cards), or a `cards:` list,
// whose entries carry a crypto block, under `metadata.crypto` or `crypto`, with a CycloneDX
// assetType. reach keeps such rules only in testdata, where tests use small
// invented ones; anywhere else they are a ruleset that should not be here.
// A file that is no YAML, or holds no `rules:`, has none.
func CryptoRules(data []byte) []string {
	var doc struct {
		Rules yaml.Node `yaml:"rules"`
		Cards yaml.Node `yaml:"cards"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return nil
	}
	var out []string
	check := func(name string, entry *yaml.Node) {
		var r struct {
			Crypto   map[string]any `yaml:"crypto"`
			Metadata struct {
				Crypto map[string]any `yaml:"crypto"`
			} `yaml:"metadata"`
		}
		if entry.Decode(&r) != nil {
			return
		}
		for _, c := range []map[string]any{r.Metadata.Crypto, r.Crypto} {
			if t, ok := c["assetType"].(string); ok && assetTypes[t] {
				out = append(out, name)
				return
			}
		}
	}
	list := func(entries []*yaml.Node) {
		for i, entry := range entries {
			name := fmt.Sprintf("rule %d", i+1)
			var id struct {
				ID   string `yaml:"id"`
				Rule string `yaml:"rule"`
			}
			if entry.Decode(&id) == nil {
				if id.ID != "" {
					name = id.ID
				} else if id.Rule != "" {
					name = id.Rule
				}
			}
			check(name, entry)
		}
	}
	if doc.Cards.Kind == yaml.SequenceNode {
		list(doc.Cards.Content)
	}
	switch doc.Rules.Kind {
	case yaml.SequenceNode:
		list(doc.Rules.Content)
	case yaml.MappingNode:
		for i := 0; i+1 < len(doc.Rules.Content); i += 2 {
			check(doc.Rules.Content[i].Value, doc.Rules.Content[i+1])
		}
	}
	return out
}
