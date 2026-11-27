// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
)

// The tests below pin the package-level FragmentEdgeWorkers, so they must not
// run in parallel with anything that builds edges.

var (
	splitGraphOnce sync.Once
	splitGraph     *callgraph.CallGraph
	splitGraphDir  string
	splitGraphErr  error
)

// graphWithSplitCallee builds reach's own callgraph package once: it has a
// callee with more callers than one work item takes, so a parallel build
// splits it. A change to that package that loses the split fails loudly here.
func graphWithSplitCallee(t *testing.T) (*callgraph.CallGraph, string) {
	t.Helper()
	splitGraphOnce.Do(func() {
		// go test runs in the package directory, also from the module cache
		// and under -trimpath.
		if splitGraphDir, splitGraphErr = filepath.Abs(filepath.Join("..", "callgraph")); splitGraphErr != nil {
			return
		}
		splitGraph, splitGraphErr = callgraph.NewBuilderForEcosystem(EcosystemGo, callgraph.NewGoParser()).
			BuildFromDirectories([]callgraph.PackageDir{{Dir: splitGraphDir, ImportPath: "github.com/scanoss/reach/callgraph"}}, nil)
	})
	if splitGraphErr != nil {
		t.Fatal(splitGraphErr)
	}
	items := PlanFragmentEdgeItems(splitGraph, SortedKeys(splitGraph.Callers))
	split := false
	for _, item := range items {
		split = split || (len(item) == 1 && item[0].Callers != nil)
	}
	if len(items) < 8 || !split {
		t.Fatalf("graph plans %d work items, split callee %v; want at least 8 and a split one", len(items), split)
	}
	return splitGraph, splitGraphDir
}

func withWorkers(n int, fn func()) {
	saved := FragmentEdgeWorkers
	FragmentEdgeWorkers = func() int { return n }
	defer func() { FragmentEdgeWorkers = saved }()
	fn()
}

// A parallel build emits exactly the fragment the serial build does.
func TestBuildParallelMatchesSerial(t *testing.T) {
	graph, dir := graphWithSplitCallee(t)
	build := func(workers int) graphfrag.GraphFragmentExport {
		var out graphfrag.GraphFragmentExport
		withWorkers(workers, func() {
			out = Build(Input{Graph: graph, Ecosystem: EcosystemGo, ProjectRoot: dir, RootModule: "github.com/scanoss/reach"})
		})
		out.ScanMetadata.ExportedAt = ""
		return out
	}
	serial := build(1)
	for _, workers := range []int{2, 8} {
		if !reflect.DeepEqual(serial, build(workers)) {
			t.Fatalf("workers=%d fragment differs from the serial one", workers)
		}
	}
}

// ForEachFragmentEdges hands the edges over in serial order: the concatenated
// runs of a parallel build equal the serial ones, before any sorting.
func TestForEachFragmentEdgesKeepsSerialOrder(t *testing.T) {
	graph, dir := graphWithSplitCallee(t)
	collect := func(workers int) FragmentEdges {
		var all FragmentEdges
		withWorkers(workers, func() {
			ctx := NewContext(Input{Graph: graph, Ecosystem: EcosystemGo, ProjectRoot: dir})
			ForEachFragmentEdges(&ctx, SortedKeys(graph.Callers), nil, func(edges FragmentEdges) bool {
				all.Internal = append(all.Internal, edges.Internal...)
				all.External = append(all.External, edges.External...)
				return true
			})
		})
		return all
	}
	serial := collect(1)
	if len(serial.Internal) == 0 {
		t.Fatal("serial build emitted no internal edges")
	}
	for _, workers := range []int{2, 8} {
		if got := collect(workers); !reflect.DeepEqual(serial, got) {
			t.Fatalf("workers=%d edges differ from the serial order (%d/%d internal, %d/%d external)",
				workers, len(got.Internal), len(serial.Internal), len(got.External), len(serial.External))
		}
	}
}
