// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package appreach

import gf "github.com/scanoss/reach/graphfrag"

// The stitch model, under the names this package's API uses (the same types,
// not copies).
type (
	// ComponentKey is the identity of a component in a stitch.
	ComponentKey = gf.ComponentKey
	// DependencyGraph is the dependency graph a stitch walks.
	DependencyGraph = gf.DependencyGraph
	// Fragment is the graph fragment of one component.
	Fragment = gf.Fragment
	// ScanMeta is the scan metadata of a callgraph export.
	ScanMeta = gf.ScanMeta
	// CallgraphExport is the callgraph a stitch exports.
	CallgraphExport = gf.CallgraphExport
	// ExportFindingGraph is the call chains of one finding in the export.
	ExportFindingGraph = gf.ExportFindingGraph
	// ExportChainNode is a frame of an exported call chain.
	ExportChainNode = gf.ExportChainNode
	// StitchOptions is the options of a stitch.
	StitchOptions = gf.StitchOptions
	// Result is the result of a stitch.
	Result = gf.Result
)
