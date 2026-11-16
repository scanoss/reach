// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package importguard

import (
	"go/build"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// repoRoot is the module root, relative to this package's directory.
const repoRoot = "../.."

// platforms are the GOOS values a build-constrained file could target.
var platforms = []string{"linux", "darwin", "windows"}

// packageDirs returns the module-relative directories holding Go packages,
// skipping testdata and hidden directories.
func packageDirs(t *testing.T) []string {
	t.Helper()
	var dirs []string
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		name := d.Name()
		if path != repoRoot && (name == "testdata" || strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_")) {
			return filepath.SkipDir
		}
		rel, err := filepath.Rel(repoRoot, path)
		if err != nil {
			return err
		}
		if matches, _ := filepath.Glob(filepath.Join(path, "*.go")); len(matches) > 0 {
			dirs = append(dirs, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return dirs
}

// allowed reports whether a reach package may import imp.
func allowed(imp string) bool {
	first, _, _ := strings.Cut(imp, "/")
	if !strings.Contains(first, ".") {
		return true // standard library
	}
	if imp == Module || strings.HasPrefix(imp, Module+"/") {
		return true
	}
	return slices.ContainsFunc(AllowedModules, func(m string) bool {
		return imp == m || strings.HasPrefix(imp, m+"/")
	})
}

// TestImportsStayInsideReach fails when a reach package or its tests import
// anything other than the standard library, reach and AllowedModules.
func TestImportsStayInsideReach(t *testing.T) {
	t.Parallel()
	dirs := packageDirs(t)
	if !slices.Contains(dirs, "callgraph") || !slices.Contains(dirs, "graphfrag") {
		t.Fatalf("package walk found %v, which misses callgraph or graphfrag", dirs)
	}
	for _, rel := range dirs {
		for _, goos := range platforms {
			ctx := build.Default
			ctx.GOOS = goos
			pkg, err := ctx.ImportDir(filepath.Join(repoRoot, filepath.FromSlash(rel)), 0)
			if err != nil {
				if _, noGo := err.(*build.NoGoError); noGo {
					continue
				}
				t.Fatalf("%s (GOOS=%s): %v", rel, goos, err)
			}
			for _, imports := range [][]string{pkg.Imports, pkg.TestImports, pkg.XTestImports} {
				for _, imp := range imports {
					if !allowed(imp) {
						t.Errorf("%s (GOOS=%s) imports %s, outside reach, the standard library and importguard.AllowedModules", rel, goos, imp)
					}
				}
			}
		}
	}
}
