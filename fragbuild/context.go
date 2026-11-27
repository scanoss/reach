// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/callgraph/contracts"
)

// Context holds what building a graph fragment reads: the call graph, the
// artifacts it covers and the indexes built over it. A fork for concurrent
// edge building copies it by value.
type Context struct {
	Graph     *callgraph.CallGraph
	Ecosystem string
	Artifacts
	// ExportLocations memoizes NormalizeExportPath by the path it was given.
	ExportLocations         *Memo[ExportLocation]
	FragmentEdgeResolutions map[string][]EdgeResolution
	UserPackages            map[string]bool
	PackageSeparator        string
	// KB holds the ecosystem's callgraph contracts; nil for ecosystems with
	// none.
	KB            *contracts.KnowledgeBase
	DeclsByMethod map[string][]ContractDeclaration // method name → definitions
	// CallsBySignature caches, per caller FunctionID key, an index of that
	// caller's FunctionCalls grouped by the (Package, Type, BaseFunctionName)
	// tuple matchingCallsForCallee compares — the same fuzzy key an
	// overload/dispatch-expanded calleeKey still matches against its one
	// underlying source call. Built lazily (one caller's Calls slice is
	// indexed at most once, on first lookup) via CallSignatureIndexForCaller,
	// so a caller with heavy dispatch fan-out (many resolved edges, one
	// source call site) pays the O(len(Calls)) index-build cost once instead
	// of once per edge.
	CallsBySignature     *Memo[map[string][]*callgraph.FunctionCall]
	CalleeSignatureKeys  *Memo[string]
	ChainIDsByCallerLine *Memo[map[int]string]
	// ReturnInlining holds the call targets whose return sources are being
	// inlined on the current provenance path, so a recursive callee is not
	// re-inlined into itself.
	ReturnInlining map[string]bool
	// CallsReverseIndex maps callee FunctionID.String() → caller keys, built once
	// from Functions[].Calls (and merged with graph.Callers), so it is
	// complete even when a graph omits Callers.
	CallsReverseIndex map[string][]string
	// CombinedHierarchy caches graph.TypeHierarchy plus the source hierarchy
	// from FunctionDecl.OwnerBases and SourceSupertypes. A graph built without
	// jars indexes no bytecode, so without the source edges every fragment
	// function would export empty CompatibleCanonicalSignatures. Built lazily by combinedTypeHierarchy.
	CombinedHierarchy map[string][]string
	// Tracer is shared by every trace so the edge index it builds on first
	// use is built once per export.
	Tracer *callgraph.Tracer
	// ExcerptSource reads the source lines the fragment quotes. Built on first
	// use.
	ExcerptSource *SourceExcerpts
}
