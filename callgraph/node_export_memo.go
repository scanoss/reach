// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import sitter "github.com/smacker/go-tree-sitter"

// node_export_memo.go remembers what a module exports under each name.
// NodeShapes.exportValue follows re-exports from module to module, and
// modules that `export *` from each other form a cycle: followed without a
// memory, every route through the cycle is walked again down to the depth
// cap, which for four modules re-exporting each other never ends.
//
// An answer is a function of the module and the name alone as long as the
// depth cap cut nothing, so it is kept and served again. A lookup that comes
// back to an export still being resolved finds nothing new there and answers
// nil. Whatever was resolved on the way to such a lookup holds only while
// that export is being resolved, so it is kept until then and dropped after.

// nodeExportRef names one export of one module.
type nodeExportRef struct {
	module *nodeShapeModule
	name   string
}

// nodeExportAnswer is the value an export resolves to. need is how many
// levels below its own the resolution descended: served at a depth where
// those levels pass the cap, the uncached resolution would have been cut, so
// the answer does not apply there.
type nodeExportAnswer struct {
	value  *sitter.Node
	module *nodeShapeModule
	need   int
}

// nodeExportFrame is one export being resolved.
type nodeExportFrame struct {
	key nodeExportRef
	// low is the index of the lowest frame the resolution came back to; its
	// own index when it came back to none below itself.
	low int
	// deepest is the greatest depth the resolution asked an export at.
	deepest int
}

type nodeExportMemo struct {
	// settled holds the answers that depend on no export still being resolved.
	settled map[nodeExportRef]nodeExportAnswer
	// pending holds the answers found while a frame below was being resolved,
	// each with the index of the lowest such frame.
	pending      map[nodeExportRef]nodeExportPending
	pendingByLow map[int][]nodeExportRef
	active       map[nodeExportRef]int
	stack        []nodeExportFrame
}

type nodeExportPending struct {
	answer nodeExportAnswer
	low    int
}

// reached records that the resolution in progress asked an export at depth.
func (c *nodeExportMemo) reached(depth int) {
	if n := len(c.stack); n > 0 && depth > c.stack[n-1].deepest {
		c.stack[n-1].deepest = depth
	}
}

// cameBackTo records that the resolution in progress depends on the frame at
// index low.
func (c *nodeExportMemo) cameBackTo(low int) {
	if n := len(c.stack); n > 0 && low < c.stack[n-1].low {
		c.stack[n-1].low = low
	}
}

// resolve answers key at depth, from memory when it holds the answer and with
// compute otherwise.
func (c *nodeExportMemo) resolve(key nodeExportRef, depth int, compute func() (*sitter.Node, *nodeShapeModule)) (*sitter.Node, *nodeShapeModule) {
	if answer, ok := c.settled[key]; ok && depth+answer.need <= nodeShapeDepth {
		c.reached(depth + answer.need)
		return answer.value, answer.module
	}
	if index, ok := c.active[key]; ok {
		c.cameBackTo(index)
		return nil, nil
	}
	if held, ok := c.pending[key]; ok && depth+held.answer.need <= nodeShapeDepth {
		c.cameBackTo(held.low)
		c.reached(depth + held.answer.need)
		return held.answer.value, held.answer.module
	}
	if c.settled == nil {
		c.settled = make(map[nodeExportRef]nodeExportAnswer)
		c.pending = make(map[nodeExportRef]nodeExportPending)
		c.pendingByLow = make(map[int][]nodeExportRef)
		c.active = make(map[nodeExportRef]int)
	}
	index := len(c.stack)
	c.stack = append(c.stack, nodeExportFrame{key: key, low: index, deepest: depth})
	c.active[key] = index
	value, module := compute()
	frame := c.stack[index]
	c.stack = c.stack[:index]
	delete(c.active, key)
	for _, held := range c.pendingByLow[index] {
		delete(c.pending, held)
	}
	delete(c.pendingByLow, index)
	c.reached(frame.deepest)
	if frame.deepest > nodeShapeDepth {
		// The cap cut the resolution: the answer holds at this depth only.
		c.cameBackTo(frame.low)
		return value, module
	}
	answer := nodeExportAnswer{value: value, module: module, need: frame.deepest - depth}
	if frame.low >= index {
		c.settled[key] = answer
		return value, module
	}
	c.cameBackTo(frame.low)
	c.pending[key] = nodeExportPending{answer: answer, low: frame.low}
	c.pendingByLow[frame.low] = append(c.pendingByLow[frame.low], key)
	return value, module
}
