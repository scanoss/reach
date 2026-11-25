// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// writeNodeSourceOfSize writes a module declaring fn, padded with a line
// comment to exactly size bytes.
func writeNodeSourceOfSize(t *testing.T, dir, name, fn string, size int) string {
	t.Helper()
	head := "export function " + fn + "() { return 1; }\n// "
	if size < len(head) {
		t.Fatalf("size %d below the %d-byte module", size, len(head))
	}
	src := head + strings.Repeat("x", size-len(head))
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A file past MaxNodeSourceBytes is a bundle: ParseDirectory leaves it out
// of the graph and names it in a warning, while a file at the cap parses.
// Not parallel: it swaps the global logger to read the warning.
func TestNodeParser_ParseDirectorySkipsSourceOverCap(t *testing.T) {
	dir := t.TempDir()
	writeNodeSourceOfSize(t, dir, "at_cap.js", "atCap", MaxNodeSourceBytes)
	big := writeNodeSourceOfSize(t, dir, "bundle.js", "inBundle", MaxNodeSourceBytes+1)

	var logs bytes.Buffer
	saved := log.Logger
	log.Logger = zerolog.New(&logs).Level(zerolog.WarnLevel)
	t.Cleanup(func() { log.Logger = saved })

	analyses, err := NewNodeParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, analysis := range analyses {
		for _, fn := range analysis.Functions {
			names = append(names, fn.ID.Name)
		}
	}
	if len(analyses) != 1 || !slices.Contains(names, "atCap") || slices.Contains(names, "inBundle") {
		t.Fatalf("parsed %d files with functions %v, want only at_cap.js (atCap)", len(analyses), names)
	}
	if got := logs.String(); !strings.Contains(got, `"level":"warn"`) || !strings.Contains(got, big) || !strings.Contains(got, "source size cap") {
		t.Fatalf("no warning naming the skipped file %s, logs: %s", big, got)
	}
}

// Every reader of node source refuses the oversize file with
// ErrNodeSourceTooLarge, so a caller can tell it from an unreadable one.
func TestNodeSourceReadersRefuseSourceOverCap(t *testing.T) {
	t.Parallel()

	big := writeNodeSourceOfSize(t, t.TempDir(), "bundle.js", "inBundle", MaxNodeSourceBytes+1)
	if _, err := NewNodeParser().ParseFile(big, "app"); !errors.Is(err, ErrNodeSourceTooLarge) {
		t.Errorf("ParseFile: %v, want ErrNodeSourceTooLarge", err)
	}
	if _, err := NodeModuleExports(big); !errors.Is(err, ErrNodeSourceTooLarge) {
		t.Errorf("NodeModuleExports: %v, want ErrNodeSourceTooLarge", err)
	}
	if _, err := NodeCodeNames(big); !errors.Is(err, ErrNodeSourceTooLarge) {
		t.Errorf("NodeCodeNames: %v, want ErrNodeSourceTooLarge", err)
	}
}
