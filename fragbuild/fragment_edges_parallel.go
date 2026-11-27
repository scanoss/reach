// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"runtime"
	"sync"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
)

// FragmentEdgeWorkers is how many goroutines build graph-fragment edges.
// Pinning it to 1 gives the serial build, which a parallel build must equal.
var FragmentEdgeWorkers = func() int { return runtime.GOMAXPROCS(0) }

const (
	// FragmentEdgeItemCallers is about how many caller-callee pairs one work
	// item covers: enough to amortize the hand-off, few enough to keep the
	// workers balanced. A callee with more callers is cut into several items,
	// so one widely called function does not leave the other workers idle.
	FragmentEdgeItemCallers = 256
	// fragmentEdgeWindow bounds, per worker, how many work items may be built
	// ahead of the one being consumed, so the edges held in memory stay a
	// small window of the graph instead of all of it.
	fragmentEdgeWindow = 4
)

// FragmentEdges is a run of graph-fragment edges in emission order: the
// Internal edges in order and the external calls, of one callee or of a run
// of its callers.
type FragmentEdges struct {
	Internal []graphfrag.GraphFragmentEdge
	External []graphfrag.GraphFragmentExternal
	// EntryCalls optionally holds each Internal edge's call site encoded by
	// ForEachFragmentEdges' prepare hook; nil where it encoded none.
	EntryCalls [][]byte
}

// FragmentEdgePiece names the edges into calleeKey from callers, a run of its
// sorted callers; nil callers means all of them.
type FragmentEdgePiece struct {
	CalleeKey string
	Callers   []string
}

// ForEachFragmentEdges builds the edges into every callee in calleeKeys, on
// all cores, and hands them to consume in runs whose concatenation is exactly
// what a serial build emits, in that order. Each worker builds on its own fork
// of ctx (forkForFragmentEdges); at most fragmentEdgeWindow work items per
// worker are held ahead of consume. prepare, when set, runs over each run in
// the worker that built it. The build stops once consume returns false.
func ForEachFragmentEdges(ctx *Context, calleeKeys []string, prepare func(*FragmentEdges), consume func(FragmentEdges) bool) {
	workers := FragmentEdgeWorkers()
	var items [][]FragmentEdgePiece
	if workers >= 2 {
		items = PlanFragmentEdgeItems(ctx.Graph, calleeKeys)
		workers = min(workers, len(items))
	}
	if workers < 2 {
		for _, calleeKey := range calleeKeys {
			if !consume(buildFragmentEdgePiece(ctx, FragmentEdgePiece{CalleeKey: calleeKey}, prepare)) {
				return
			}
		}
		return
	}

	prepareFragmentEdgeForks(ctx)
	build := &fragmentEdgeBuild{
		items:   items,
		prepare: prepare,
		results: make([][]FragmentEdges, len(items)),
		ready:   make([]chan struct{}, len(items)),
		window:  make(chan struct{}, workers*fragmentEdgeWindow),
		stop:    make(chan struct{}),
	}
	for i := range build.ready {
		build.ready[i] = make(chan struct{})
	}
	jobs := build.dispatch()
	var wg sync.WaitGroup
	for range workers {
		fork := forkForFragmentEdges(ctx)
		wg.Go(func() { build.work(fork, jobs) })
	}
	build.consumeInOrder(consume)
	wg.Wait()
}

// PlanFragmentEdgeItems cuts the edge build into work items of about
// FragmentEdgeItemCallers caller-callee pairs, in calleeKeys order.
func PlanFragmentEdgeItems(graph *callgraph.CallGraph, calleeKeys []string) [][]FragmentEdgePiece {
	var items [][]FragmentEdgePiece
	var item []FragmentEdgePiece
	pairs := 0
	closeItem := func() {
		if len(item) > 0 {
			items = append(items, item)
			item, pairs = nil, 0
		}
	}
	for _, calleeKey := range calleeKeys {
		callers := graph.Callers[calleeKey]
		if len(callers) <= FragmentEdgeItemCallers {
			item = append(item, FragmentEdgePiece{CalleeKey: calleeKey})
			// A callee counts at least one, so callees without callers
			// still fill items.
			if pairs += max(len(callers), 1); pairs >= FragmentEdgeItemCallers {
				closeItem()
			}
			continue
		}
		closeItem()
		sorted := SortedFragmentCallers(graph, calleeKey)
		for lo := 0; lo < len(sorted); lo += FragmentEdgeItemCallers {
			hi := min(lo+FragmentEdgeItemCallers, len(sorted))
			items = append(items, []FragmentEdgePiece{{CalleeKey: calleeKey, Callers: sorted[lo:hi:hi]}})
		}
	}
	closeItem()
	return items
}

// buildFragmentEdgePiece builds the edges piece names and, when prepare is
// set, runs it over them.
func buildFragmentEdgePiece(ctx *Context, piece FragmentEdgePiece, prepare func(*FragmentEdges)) FragmentEdges {
	callers := piece.Callers
	if callers == nil {
		callers = SortedFragmentCallers(ctx.Graph, piece.CalleeKey)
	}
	edges := BuildResolvedFragmentEdgesFrom(ctx, piece.CalleeKey, callers)
	if prepare != nil {
		prepare(&edges)
	}
	return edges
}

// fragmentEdgeBuild is the shared state of one parallel edge build: the
// worker of items[i] stores its edges in results[i] and closes ready[i].
type fragmentEdgeBuild struct {
	items   [][]FragmentEdgePiece
	prepare func(*FragmentEdges)
	results [][]FragmentEdges
	ready   []chan struct{}
	// window holds a token per work item handed out and not yet consumed.
	window chan struct{}
	// stop is closed when the consumer quits early.
	stop chan struct{}
}

// dispatch hands out the work items in order, never more than the window
// allows ahead of the consumer.
func (b *fragmentEdgeBuild) dispatch() <-chan int {
	jobs := make(chan int)
	go func() {
		defer close(jobs)
		for i := range b.items {
			select {
			case b.window <- struct{}{}:
			case <-b.stop:
				return
			}
			select {
			case jobs <- i:
			case <-b.stop:
				return
			}
		}
	}()
	return jobs
}

func (b *fragmentEdgeBuild) work(ctx *Context, jobs <-chan int) {
	for i := range jobs {
		batch := make([]FragmentEdges, 0, len(b.items[i]))
		for _, piece := range b.items[i] {
			batch = append(batch, buildFragmentEdgePiece(ctx, piece, b.prepare))
		}
		b.results[i] = batch
		close(b.ready[i])
	}
}

// consumeInOrder hands the built edges to consume in work item order.
func (b *fragmentEdgeBuild) consumeInOrder(consume func(FragmentEdges) bool) {
	for i := range b.results {
		<-b.ready[i]
		batch := b.results[i]
		b.results[i] = nil
		for _, edges := range batch {
			if !consume(edges) {
				close(b.stop)
				return
			}
		}
		<-b.window
	}
}

// forkForFragmentEdges returns a copy of ctx one edge-building goroutine can
// use while others use theirs. The graph, the indexes built before forking
// (prepareFragmentEdgeForks) and the Memo caches stay shared; what the
// edge build writes outside a Memo (ReturnInlining, the recursion guard
// of one walk) is the fork's own. A cache the edge build starts to fill must
// be a Memo, built in prepareFragmentEdgeForks or reset here, or the
// forks race on it.
func forkForFragmentEdges(ctx *Context) *Context {
	fork := *ctx
	fork.ReturnInlining = nil
	return &fork
}

// prepareFragmentEdgeForks builds, before ctx is forked, the lazy indexes the
// edge build reads.
func prepareFragmentEdgeForks(ctx *Context) {
	if ctx.Graph != nil && ctx.CallsReverseIndex == nil {
		ctx.CallsReverseIndex = buildCallsReverseIndex(ctx.Graph)
	}
}
