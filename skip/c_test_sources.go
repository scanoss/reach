// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package skip

import (
	"errors"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
)

var (
	cTestMatcher    = NewGitIgnoreMatcher(DefaultSkippedCTestPatterns)
	cSourceSuffixes = []string{".c", ".cc", ".cpp", ".cxx"}
	// errFoundCProduct stops the walk at the first product source.
	errFoundCProduct = errors.New("product C source found")
)

// CTestPatternsFor returns DefaultSkippedCTestPatterns when targetDir holds a
// C/C++ source they do not match, and nil otherwise: like the built-output
// rescue, a pattern must never exclude the only source a package has. A walk
// that hits the entry cap abstains and keeps every file.
func CTestPatternsFor(targetDir string) []string {
	return cTestPatternsFor(targetDir, maxBuiltOutputWalk)
}

func cTestPatternsFor(targetDir string, maxEntries int) []string {
	root := filepath.Clean(targetDir)
	seen := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable entry is no product source
		}
		seen++
		if seen > maxEntries {
			return fs.SkipAll
		}
		name := d.Name()
		if d.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") ||
				slices.Contains(DefaultSkippedDirs, name) || slices.Contains(extraRescueIgnoredDirs, name)) {
				return fs.SkipDir
			}
			return nil
		}
		if !slices.Contains(cSourceSuffixes, strings.ToLower(filepath.Ext(name))) {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return nil //nolint:nilerr // a path outside the root is no product source
		}
		if cTestMatcher.ShouldSkip(filepath.ToSlash(rel), false) {
			return nil
		}
		return errFoundCProduct
	})
	if errors.Is(err, errFoundCProduct) {
		return DefaultSkippedCTestPatterns
	}
	return nil
}
