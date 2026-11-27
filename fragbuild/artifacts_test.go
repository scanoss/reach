// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"fmt"
	"path/filepath"
	"testing"
)

// linearDependencyForPath tries every root, longest first, and returns the
// first one the path is relative to: the answer DependencyForPath must agree with.
func linearDependencyForPath(dependencies []Dependency, path string) *Dependency {
	for i := range dependencies {
		if _, ok := RelativeToRoot(dependencies[i].Dir, path); ok {
			return &dependencies[i]
		}
	}
	return nil
}

// DependencyForPath agrees with trying every root, longest first, for nested
// roots, two dependencies sharing a directory, a root that is the path
// itself, and relative paths.
func TestDependencyForPath_AgreesWithTryingEveryRoot(t *testing.T) {
	artifacts := NewArtifacts("/work", []Dependency{
		{Module: "outer", Version: "1", Dir: "/mod/outer@1"},
		{Module: "inner", Version: "1", Dir: "/mod/outer@1/vendor/inner"},
		{Module: "twin-a", Version: "1", Dir: "/mod/twin@1"},
		{Module: "twin-b", Version: "1", Dir: "/mod/twin@1/"},
		{Module: "vendored", Version: "1", Dir: "/work/vendor/lib"},
		{Module: "relative", Version: "1", Dir: "deps/rel"},
		{Module: "no-dir", Version: "1"},
	})
	for _, path := range []string{
		"/mod/outer@1/a.go",
		"/mod/outer@1",
		"/mod/outer@1/vendor/inner/b.go",
		"/mod/outer@1/vendor/innerx/b.go",
		"/mod/twin@1/c.go",
		"/work/vendor/lib/d.go",
		"/work/e.go",
		"/elsewhere/f.go",
		"/",
		"deps/rel/g.go",
		"deps/relx/g.go",
		"../deps/rel/h.go",
		"i.go",
		".",
	} {
		want := linearDependencyForPath(artifacts.Dependencies, path)
		if got := artifacts.DependencyForPath(path); got != want {
			t.Errorf("DependencyForPath(%q) = %+v, want %+v", path, got, want)
		}
	}
}

// Python distributions installed into one namespace directory share it as
// their Dir; a file there belongs to the one whose Files list it, so each
// exported function and call site names the distribution that installed it.
func TestDependencyForPath_NamespaceSiblingsOwnTheirFiles(t *testing.T) {
	ns := filepath.FromSlash("/sp/acme")
	core, extra := filepath.Join(ns, "core", "util.py"), filepath.Join(ns, "extra", "msg.py")
	artifacts := NewArtifacts("/work", []Dependency{
		{Module: "acme-extra", Version: "7", Dir: ns, Files: []string{extra}},
		{Module: "acme-core", Version: "2", Dir: ns, Files: []string{core}},
	})
	for path, want := range map[string]string{core: "acme-core", extra: "acme-extra", filepath.Join(ns, "other.py"): ""} {
		got := ""
		if dep := artifacts.DependencyForPath(path); dep != nil {
			got = dep.Module
		}
		if got != want {
			t.Errorf("DependencyForPath(%q) = %q, want %q", path, got, want)
		}
	}
}

// BenchmarkDependencyForPath compares trying every root with walking the
// path's ancestors, with 200 dependency roots.
func BenchmarkDependencyForPath(b *testing.B) {
	deps := make([]Dependency, 200)
	for i := range deps {
		deps[i] = Dependency{Module: fmt.Sprintf("m%d", i), Version: "1", Dir: fmt.Sprintf("/home/u/go/pkg/mod/example.com/m%d@v1.0.0", i)}
	}
	artifacts := NewArtifacts("/work", deps)
	path := "/home/u/go/pkg/mod/example.com/m7@v1.0.0/internal/pkg/file.go"
	b.Run("every-root", func(b *testing.B) {
		for range b.N {
			_ = linearDependencyForPath(artifacts.Dependencies, path)
		}
	})
	b.Run("ancestors", func(b *testing.B) {
		for range b.N {
			_ = artifacts.DependencyForPath(path)
		}
	})
}
