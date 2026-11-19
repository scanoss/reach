// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Modules that `export *` from each other are resolved once each: without a
// memory every route through the cycle was walked to the depth cap, which for
// four such modules did not end.
func TestNodeShapesResolveStarExportCycles(t *testing.T) {
	t.Parallel()
	const modules = 8
	files := map[string]string{"impl.js": "export function found() {}\n"}
	for i := range modules {
		var body strings.Builder
		for j := range modules {
			if j != i {
				fmt.Fprintf(&body, "export * from './m%d.js';\n", j)
			}
		}
		if i == modules-1 {
			body.WriteString("export * from './impl.js';\n")
		}
		files[fmt.Sprintf("m%d.js", i)] = body.String()
	}
	root := writeShapeFiles(t, files)
	s := NewNodeShapes()
	defer s.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range modules {
			file := filepath.Join(root, fmt.Sprintf("m%d.js", i))
			if _, _, ok := s.Definition(file, "missing", nil); ok {
				t.Errorf("m%d: a name no module exports has a definition", i)
			}
			defFile, line, ok := s.Definition(file, "found", nil)
			if !ok || filepath.Base(defFile) != "impl.js" || line != 1 {
				t.Errorf("m%d: found = %s:%d (ok %v), want impl.js:1", i, defFile, line, ok)
			}
		}
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("star-export cycle did not resolve in 30s")
	}
}

// A remembered export answers as a fresh resolution does, whatever was asked
// before it: across a diamond of re-exports, and at the depth cap, where a
// chain too long to follow from its head stays unresolved after its tail was
// resolved on its own.
func TestNodeShapesRememberedExportsMatchFreshOnes(t *testing.T) {
	t.Parallel()
	files := map[string]string{
		"top.js":   "export * from './left.js';\nexport * from './right.js';\nexport { deep as renamed } from './left.js';\n",
		"left.js":  "export * from './base.js';\nexport function left() {}\n",
		"right.js": "export * from './base.js';\nexport { shared } from './base.js';\nexport function right() {}\n",
		"base.js":  "export function shared() {}\nexport const deep = () => 1;\nconst hidden = 1;\n",
	}
	const chain = nodeShapeDepth + 4
	for i := range chain {
		files[fmt.Sprintf("c%d.js", i)] = fmt.Sprintf("export * from './c%d.js';\n", i+1)
	}
	files[fmt.Sprintf("c%d.js", chain)] = "export function end() {}\n"
	root := writeShapeFiles(t, files)

	type query struct{ file, name string }
	var queries []query
	for _, file := range []string{"top.js", "left.js", "right.js", "base.js"} {
		for _, name := range []string{"shared", "deep", "renamed", "left", "right", "hidden", "default"} {
			queries = append(queries, query{file, name})
		}
	}
	for _, i := range []int{chain - 2, 0, 3, chain - nodeShapeDepth, chain - nodeShapeDepth - 1, chain} {
		queries = append(queries, query{fmt.Sprintf("c%d.js", i), "end"})
	}
	answer := func(s *NodeShapes, q query) string {
		file, line, ok := s.Definition(filepath.Join(root, q.file), q.name, nil)
		return fmt.Sprintf("%s:%d:%v", filepath.Base(file), line, ok)
	}
	shared := NewNodeShapes()
	defer shared.Close()
	for round := range 2 {
		for i := range queries {
			q := queries[i]
			if round == 1 {
				q = queries[len(queries)-1-i]
			}
			fresh := NewNodeShapes()
			want := answer(fresh, q)
			fresh.Close()
			if got := answer(shared, q); got != want {
				t.Errorf("round %d, %s %s: remembered %s, fresh %s", round, q.file, q.name, got, want)
			}
		}
	}
	if got := answer(shared, query{"c0.js", "end"}); !strings.HasSuffix(got, "false") {
		t.Errorf("a chain longer than the depth cap resolved from its head: %s", got)
	}
	if got := answer(shared, query{fmt.Sprintf("c%d.js", chain-2), "end"}); !strings.HasSuffix(got, "true") {
		t.Errorf("the chain's tail did not resolve: %s", got)
	}
}
