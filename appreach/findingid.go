// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package appreach

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
)

// DepPrefixedPath is a dependency file's path as the stitch names it:
// module@version/path.
func DepPrefixedPath(filePath, module, version string) string {
	if filePath == "" || module == "" || version == "" {
		return filePath
	}
	return module + "@" + version + "/" + filePath
}

// ComputeFindingID is the finding id the stitch gives an annotated operation
// (graphfrag's own, which is unexported).
func ComputeFindingID(path string, startLine int, ruleID string) string {
	if path == "" && startLine == 0 && ruleID == "" {
		return ""
	}
	h := sha256.Sum256([]byte(path + ":" + strconv.Itoa(startLine) + ":" + ruleID))
	return hex.EncodeToString(h[:])[:8]
}

// FindingOwners maps each finding id of the closure's dependencies to the
// component it sits in, computed as the stitch computes the ids of dependency
// findings. The root's own operations are left out.
func FindingOwners(root ComponentKey, fragments map[ComponentKey]Fragment) map[string]ComponentKey {
	out := make(map[string]ComponentKey)
	for key, frag := range fragments {
		if key == root {
			continue
		}
		for i := range frag.CryptoOperations {
			op := &frag.CryptoOperations[i]
			path := DepPrefixedPath(op.FilePath, frag.Module, key.Version)
			out[ComputeFindingID(path, op.StartLine, op.RuleID)] = key
		}
	}
	return out
}

// StitchIDs maps the finding ids a dependency's annotated operations carry
// (the ids of the producer's own report) to the ids the stitch gives them,
// which it derives from the operation's dependency-prefixed path, line and
// first rule. Several operations on one line under one first rule share a
// stitch id, and so a verdict. Operations without a finding id are left out.
func StitchIDs(key ComponentKey, frag Fragment) map[string]string {
	out := make(map[string]string, len(frag.CryptoOperations))
	for i := range frag.CryptoOperations {
		op := &frag.CryptoOperations[i]
		if op.FindingID == "" {
			continue
		}
		out[op.FindingID] = ComputeFindingID(DepPrefixedPath(op.FilePath, frag.Module, key.Version), op.StartLine, op.RuleID)
	}
	return out
}
