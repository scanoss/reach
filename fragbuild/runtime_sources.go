// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import "github.com/scanoss/reach/callgraph"

// ExportRuntimeSources lists the runtime inputs nodes read their value from,
// keyless ones included. A runtime node's children are its key, not its
// value, so the walk stops at it.
func ExportRuntimeSources(nodes []ExportSourceNode) []callgraph.RuntimeSource {
	var sources []callgraph.RuntimeSource
	for i := range nodes {
		if nodes[i].Runtime != nil {
			sources = append(sources, *nodes[i].Runtime)
			continue
		}
		sources = append(sources, ExportRuntimeSources(nodes[i].SourceNodes)...)
	}
	return sources
}

func exportRuntimeSource(node *callgraph.SourceNode) *callgraph.RuntimeSource {
	if source, ok := node.RuntimeSource(); ok {
		return &source
	}
	return nil
}
