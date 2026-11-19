// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package skip

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// maxNodeManifestBytes bounds the package.json read for its entry points.
const maxNodeManifestBytes = 4 << 20

// NodeEntryBuiltOutput reports the built-output directories of targetDir that
// its package.json names as where the package's code is loaded from: the
// top-level `dist` or `build` that `main`, `module`, `browser` or `exports`
// resolves into, when that file is there.
//
// BuiltOutputOnlySource keeps such a directory only when nothing else in the
// tree is source. One stray file defeats it: liquidjs ships `bin/liquid.js`
// beside `dist/`, socket.io and engine.io a `wrapper.mjs`, @firebase/util a
// `postinstall.js`. Their `main` points into the directory the scan then
// skipped, so the scan read the stray file and reported nothing for the
// package. The manifest says which file a consumer runs, and that is not
// generated noise beside the source: it is the package.
//
// A package whose entry points are elsewhere keeps its exclusions, and so does
// a checkout that has not been built: an entry point that is not on disk
// rescues nothing.
func NodeEntryBuiltOutput(targetDir string) []string {
	root := filepath.Clean(targetDir)
	info, err := os.Stat(filepath.Join(root, "package.json"))
	if err != nil || info.IsDir() || info.Size() > maxNodeManifestBytes {
		return nil
	}
	data, err := os.ReadFile(filepath.Join(root, "package.json"))
	if err != nil {
		return nil
	}
	var manifest struct {
		Main    json.RawMessage `json:"main"`
		Module  json.RawMessage `json:"module"`
		Browser json.RawMessage `json:"browser"`
		Exports json.RawMessage `json:"exports"`
	}
	if json.Unmarshal(data, &manifest) != nil {
		return nil
	}
	var out []string
	for _, field := range []json.RawMessage{manifest.Main, manifest.Module, manifest.Browser, manifest.Exports} {
		for _, target := range nodeManifestTargets(field, 0) {
			dir, ok := nodeEntryBuiltOutputDir(root, target)
			if ok && !slices.Contains(out, dir) {
				out = append(out, dir)
			}
		}
	}
	slices.Sort(out)
	return out
}

// nodeManifestTargets lists the file targets a manifest field names: a
// string, or the strings nested in the condition and subpath objects and the
// arrays of alternatives that `exports` and `browser` hold. The targets under
// a `types` condition are declarations, which hold no code. An object's keys
// are subpaths or conditions, never targets, except in `browser`, whose keys
// name the files it replaces: those are on the same side of the build as the
// values, so reading the values is enough.
func nodeManifestTargets(raw json.RawMessage, depth int) []string {
	if len(raw) == 0 || depth > 8 {
		return nil
	}
	var single string
	if json.Unmarshal(raw, &single) == nil {
		return []string{single}
	}
	var alternatives []json.RawMessage
	if json.Unmarshal(raw, &alternatives) == nil {
		var out []string
		for _, alternative := range alternatives {
			out = append(out, nodeManifestTargets(alternative, depth+1)...)
		}
		return out
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil {
		return nil
	}
	var out []string
	for key, value := range object {
		if key == "types" || key == "typings" {
			continue
		}
		out = append(out, nodeManifestTargets(value, depth+1)...)
	}
	return out
}

// nodeEntryBuiltOutputDir returns the top-level built-output directory target
// lies in, when the target names code that is on disk: the file itself, or,
// for a pattern such as `./dist/*.js`, the directory.
func nodeEntryBuiltOutputDir(root, target string) (string, bool) {
	rel := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(filepath.FromSlash(target))), "./")
	top, nested := topSegment(rel)
	if !nested || !slices.Contains(builtOutputDirs, top) {
		return "", false
	}
	for _, suffix := range declarationSuffixes {
		if strings.HasSuffix(strings.ToLower(rel), suffix) {
			return "", false
		}
	}
	if strings.Contains(rel, "*") {
		info, err := os.Stat(filepath.Join(root, top))
		return top, err == nil && info.IsDir()
	}
	candidates := []string{rel, rel + ".js", rel + ".cjs", rel + ".mjs", rel + "/index.js"}
	for _, candidate := range candidates {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(candidate)))
		if err == nil && !info.IsDir() && isSourceFile(candidate) {
			return top, true
		}
	}
	return "", false
}
