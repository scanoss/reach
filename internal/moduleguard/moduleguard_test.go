// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package moduleguard

import (
	"io/fs"
	"path/filepath"
	"testing"
)

// repoRoot is the module root, relative to this package's directory.
const repoRoot = "../.."

// TestNoNestedModules fails on a go.mod below the module root: the module
// zip drops its directory.
func TestNoNestedModules(t *testing.T) {
	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && d.Name() == ".git" {
			return filepath.SkipDir
		}
		if !d.IsDir() && d.Name() == "go.mod" && filepath.Dir(path) != repoRoot {
			rel, _ := filepath.Rel(repoRoot, path)
			t.Errorf("%s: the module zip leaves out its directory; name it go.mod.fixture", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
