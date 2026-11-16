// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// structuralPrefix starts every structural graph StructuralExport writes:
// schema_version first, so a reader tells it apart from other stored forms.
var structuralPrefix = []byte(`{"schema_version":`)

// StructuralExport (the crypto miner's own, which stores its output as a
// component's code graph) returns the rules-independent part of a crypto-finder
// graph-fragment export: the document as the producer wrote it, without its
// crypto_annotations, supporting_calls and crypto_entry_points and without
// the scan's rules version and crypto counts.
//
// Every other section is kept byte for byte, including sections this build
// does not know, so a newer producer's detection data survives: call end
// lines, source_lines, constant_refs, declarations and casts
// (graph-fragment-1.16 to 1.19), call_anchors (1.20), supertypes and entry
// kinds. A detector needs them to re-match rules over a stored graph without
// the source. schema_version is written first; the other sections follow in
// key order, compacted.
func StructuralExport(data []byte) ([]byte, error) {
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(data, &sections); err != nil {
		return nil, fmt.Errorf("graphfrag: decode export: %w", err)
	}
	schemaVersion, ok := sections["schema_version"]
	if !ok {
		return nil, fmt.Errorf("graphfrag: export has no schema_version")
	}
	for _, crypto := range []string{"crypto_annotations", "supporting_calls", "crypto_entry_points"} {
		delete(sections, crypto)
	}
	if raw, ok := sections["scan_metadata"]; ok {
		var meta map[string]json.RawMessage
		if err := json.Unmarshal(raw, &meta); err != nil {
			return nil, fmt.Errorf("graphfrag: decode scan_metadata: %w", err)
		}
		for _, field := range []string{"rules_version", "crypto_operation_count", "supporting_call_count", "crypto_entry_point_count"} {
			delete(meta, field)
		}
		encoded, err := json.Marshal(meta)
		if err != nil {
			return nil, fmt.Errorf("graphfrag: encode scan_metadata: %w", err)
		}
		sections["scan_metadata"] = encoded
	}
	delete(sections, "schema_version")

	keys := make([]string, 0, len(sections))
	for key := range sections {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var buf bytes.Buffer
	buf.Grow(len(data))
	buf.Write(structuralPrefix)
	if err := json.Compact(&buf, schemaVersion); err != nil {
		return nil, err
	}
	for _, key := range keys {
		name, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		buf.WriteByte(',')
		buf.Write(name)
		buf.WriteByte(':')
		// The producer indents its document; the stored copy is compact.
		if err := json.Compact(&buf, sections[key]); err != nil {
			return nil, fmt.Errorf("graphfrag: compact %s: %w", key, err)
		}
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}
