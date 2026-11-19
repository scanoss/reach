// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package skip

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func writeNodePackage(t *testing.T, manifest string, files ...string) string {
	t.Helper()
	root := writeFiles(t, files...)
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(manifest), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// A published package whose entry points are in dist/ or build/ is read
// there even when it ships a stray source file elsewhere: the layouts of
// liquidjs (bin/), socket.io and engine.io (wrapper.mjs), gamedig
// (protocols/, lib/) and @firebase/util (postinstall.js), each of which lost
// every finding to the exclusion.
func TestNodeEntryBuiltOutput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		manifest string
		files    []string
		want     []string
	}{
		{
			name:     "main in dist beside a bin script",
			manifest: `{"main": "dist/liquid.node.js", "bin": {"liquid": "./bin/liquid.js"}}`,
			files:    []string{"dist/liquid.node.js", "bin/liquid.js"},
			want:     []string{"dist"},
		},
		{
			name:     "exports conditions into dist beside a wrapper",
			manifest: `{"exports": {".": {"types": "./dist/index.d.ts", "import": "./wrapper.mjs", "require": "./dist/index.js"}}}`,
			files:    []string{"dist/index.js", "wrapper.mjs"},
			want:     []string{"dist"},
		},
		{
			name:     "exports without subpaths into build",
			manifest: `{"main": "./build/engine.io.js", "exports": {"import": "./wrapper.mjs", "require": "./build/engine.io.js"}}`,
			files:    []string{"build/engine.io.js", "wrapper.mjs"},
			want:     []string{"build"},
		},
		{
			name:     "one condition in dist, the other in lib",
			manifest: `{"exports": {"import": "./lib/index.js", "require": "./dist/index.cjs"}}`,
			files:    []string{"dist/index.cjs", "lib/index.js", "protocols/a.js"},
			want:     []string{"dist"},
		},
		{
			name:     "module and nested browser targets",
			manifest: `{"module": "dist/index.esm.js", "browser": {"./x.js": "./build/x.browser.js"}}`,
			files:    []string{"dist/index.esm.js", "build/x.browser.js", "postinstall.js"},
			want:     []string{"build", "dist"},
		},
		{
			name:     "a main without its extension, and a subpath pattern",
			manifest: `{"main": "dist/main", "exports": {"./*": "./build/*.js"}}`,
			files:    []string{"dist/main.js", "build/a.js", "index.js"},
			want:     []string{"build", "dist"},
		},
		{
			name:     "entry points elsewhere keep the exclusion",
			manifest: `{"main": "lib/index.js"}`,
			files:    []string{"lib/index.js", "dist/bundle.js", "build/out.js"},
			want:     nil,
		},
		{
			name:     "a checkout that is not built keeps the exclusion",
			manifest: `{"main": "dist/index.js"}`,
			files:    []string{"src/index.ts"},
			want:     nil,
		},
		{
			name:     "only declarations come from dist",
			manifest: `{"main": "index.js", "types": "dist/index.d.ts", "exports": {"types": "./dist/index.d.ts", "default": "./index.js"}}`,
			files:    []string{"index.js", "dist/index.d.ts", "dist/index.js"},
			want:     nil,
		},
		{
			name:     "a nested dist is not the package's built output",
			manifest: `{"main": "packages/x/dist/index.js"}`,
			files:    []string{"packages/x/dist/index.js", "src/a.js"},
			want:     nil,
		},
		{
			name:     "a manifest that does not parse rescues nothing",
			manifest: `{"main": "dist/index.js"`,
			files:    []string{"dist/index.js", "a.js"},
			want:     nil,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			root := writeNodePackage(t, tc.manifest, tc.files...)
			if got := NodeEntryBuiltOutput(root); !slices.Equal(got, tc.want) {
				t.Fatalf("NodeEntryBuiltOutput = %v, want %v", got, tc.want)
			}
		})
	}
}

// The directory an entry point loads from leaves the default patterns, with
// or without other source in the tree, and nothing else does.
func TestDefaultPatternsForTargetKeepNodeEntryOutput(t *testing.T) {
	t.Parallel()

	root := writeNodePackage(t, `{"main": "dist/index.js"}`, "dist/index.js", "bin/cli.js", "build/other.js")
	got := DefaultPatternsForTarget(root)
	if slices.Contains(got, "dist") {
		t.Error("dist is still excluded although main loads from it")
	}
	for _, keep := range []string{"node_modules", "vendor", "build", "docs", "target"} {
		if !slices.Contains(got, keep) {
			t.Errorf("%q was dropped from the defaults", keep)
		}
	}
	if rescued := NewDefaultsSourceForTarget(root).Rescued(); !slices.Equal(rescued, []string{"dist"}) {
		t.Errorf("Rescued = %v, want [dist]", rescued)
	}

	without := writeFiles(t, "dist/index.js", "bin/cli.js")
	if got := DefaultPatternsForTarget(without); !slices.Equal(got, DefaultPatterns()) {
		t.Errorf("a tree with no manifest changed its default patterns: %v", got)
	}
}
