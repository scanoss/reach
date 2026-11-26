// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package rulesetguard

import (
	"fmt"

	"go.yaml.in/yaml/v3"
)

// assetTypes are the CycloneDX 1.7 cryptoProperties.assetType values a
// detection rule carries.
var assetTypes = map[string]bool{
	"algorithm":               true,
	"certificate":             true,
	"protocol":                true,
	"related-crypto-material": true,
}

// CryptoRules returns the rules of a YAML file that look like a detection
// ruleset's: a `rules:` list (OpenGrep) or map (cards) whose entries carry a
// crypto block, under `metadata.crypto` or `crypto`, with a CycloneDX
// assetType. reach keeps such rules only in testdata, where tests use small
// invented ones; anywhere else they are a ruleset that should not be here.
// A file that is no YAML, or holds no `rules:`, has none.
func CryptoRules(data []byte) []string {
	var doc struct {
		Rules yaml.Node `yaml:"rules"`
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
	switch doc.Rules.Kind {
	case yaml.SequenceNode:
		for i, entry := range doc.Rules.Content {
			name := fmt.Sprintf("rule %d", i+1)
			var id struct {
				ID string `yaml:"id"`
			}
			if entry.Decode(&id) == nil && id.ID != "" {
				name = id.ID
			}
			check(name, entry)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(doc.Rules.Content); i += 2 {
			check(doc.Rules.Content[i].Value, doc.Rules.Content[i+1])
		}
	}
	return out
}
