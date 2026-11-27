// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"sort"
	"time"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/callgraph/contracts"
	"github.com/scanoss/reach/graphfrag"
)

// Input is the call graph a fragment is built from and what locates its files.
type Input struct {
	// Graph is the call graph to export; nil gives a fragment with metadata
	// only.
	Graph *callgraph.CallGraph
	// Ecosystem is the graph's ecosystem, one of the Ecosystem constants.
	Ecosystem string
	// RootModule is the project's module or package name, recorded in the
	// scan metadata; empty when the project declares none.
	RootModule string
	// ProjectRoot is the directory the graph was built from. File paths below
	// it are exported relative to it, a dependency's files relative to its
	// Dir, and a path outside every root as given.
	ProjectRoot string
	// Dependencies are the source directories of the dependencies the graph
	// covers; an entry with an empty Dir is ignored.
	Dependencies []Dependency
	// UserPackages marks the project's own packages for entry-point
	// detection; a package takes the value of its nearest listed ancestor.
	// Nil treats every type declared in the scanned source as the project's.
	UserPackages map[string]bool
	// KB holds the ecosystem's contracts; nil for none.
	KB *contracts.KnowledgeBase
}

// Build returns the graph fragment of in.Graph: functions, edges, call sites
// and the facts the cards matcher reads.
func Build(in Input) graphfrag.GraphFragmentExport {
	out := graphfrag.GraphFragmentExport{SchemaVersion: graphfrag.SchemaVersion, ScanMetadata: NewScanMetadata(in.Ecosystem, in.RootModule, in.Graph != nil)}
	if in.Graph == nil {
		return out
	}
	ctx := NewContext(in)
	BuildStructure(&ctx, &out)
	return out
}

// NewScanMetadata returns the scan metadata of a fragment of ecosystem.
func NewScanMetadata(ecosystem, rootModule string, hasGraph bool) graphfrag.GraphFragmentScanMetadata {
	return graphfrag.GraphFragmentScanMetadata{
		Ecosystem:        ecosystem,
		RootModule:       rootModule,
		GraphAlgoVersion: graphfrag.GraphAlgoVersionFor(ecosystem),
		ExportedAt:       time.Now().UTC().Format(time.RFC3339),
		EntryKinds:       hasGraph,
		AbstractMethods:  hasGraph && (ecosystem == EcosystemJava || ecosystem == EcosystemPython || ecosystem == EcosystemRust),
	}
}

// NewContext returns the context the fragment builders read for in.
func NewContext(in Input) Context {
	ctx := Context{
		Graph:                   in.Graph,
		Ecosystem:               in.Ecosystem,
		Artifacts:               NewArtifacts(in.ProjectRoot, in.Dependencies),
		FragmentEdgeResolutions: IndexFragmentEdgeResolutions(in.Graph),
		ExportLocations:         NewMemo[ExportLocation](),
		CallsBySignature:        NewMemo[map[string][]*callgraph.FunctionCall](),
		CalleeSignatureKeys:     NewMemo[string](),
		ChainIDsByCallerLine:    NewMemo[map[int]string](),
		UserPackages:            in.UserPackages,
		PackageSeparator:        ExportPackageSeparator(in.Ecosystem),
		KB:                      in.KB,
	}
	if in.Graph != nil {
		ctx.DeclsByMethod = make(map[string][]ContractDeclaration)
		for _, fn := range in.Graph.Functions {
			for _, fqn := range ContractDeclKeys(&ctx, fn.ID) {
				_, method := SplitFunctionName(fqn)
				ctx.DeclsByMethod[method] = append(ctx.DeclsByMethod[method], ContractDeclaration{DeclFQN: fqn, Decl: fn})
			}
		}
		for method := range ctx.DeclsByMethod {
			sort.Slice(ctx.DeclsByMethod[method], func(i, j int) bool {
				left, right := ctx.DeclsByMethod[method][i], ctx.DeclsByMethod[method][j]
				if left.DeclFQN != right.DeclFQN {
					return left.DeclFQN < right.DeclFQN
				}
				return left.Decl.ID.String() < right.Decl.ID.String()
			})
		}
	}
	return ctx
}

// BuildStructure fills out with the structural part of the fragment of
// ctx.Graph and returns each function's index in out.Functions by key.
func BuildStructure(ctx *Context, out *graphfrag.GraphFragmentExport) map[string]int {
	graph := ctx.Graph
	functionKeys := make([]string, 0, len(graph.Functions))
	for key := range graph.Functions {
		functionKeys = append(functionKeys, key)
	}
	sort.Strings(functionKeys)
	functionIndex := make(map[string]int, len(functionKeys))
	for _, key := range functionKeys {
		decl := graph.Functions[key]
		functionIndex[key] = len(out.Functions)
		out.Functions = append(out.Functions, BuildGraphFragmentFunction(ctx, decl.ID, decl))
	}
	out.InternalEdges, out.ExternalCalls = BuildGraphFragmentResolvedEdges(ctx)
	out.Supertypes = graph.ExportSupertypes()
	out.ServiceProviders = graph.ServiceProviders
	out.ConstantRefs = BuildGraphFragmentConstantRefs(ctx, functionIndex)
	out.AttributeStores = BuildGraphFragmentAttributeStores(ctx, functionIndex)
	out.LocalBindings = BuildGraphFragmentLocalBindings(ctx, functionIndex)
	out.Declarations, out.Casts = BuildGraphFragmentDeclarations(ctx, functionIndex)
	out.CallAnchors = BuildGraphFragmentCallAnchors(ctx, functionIndex)
	out.ExternalSignatures = BuildGraphFragmentExternalSignatures(ctx)
	out.SourceLines = GraphFragmentSourceLines(ctx, out)
	out.RebindLines = BuildGraphFragmentRebinds(ctx, functionIndex)
	out.Imports = BuildGraphFragmentImports(ctx)
	out.GoValues = BuildGraphFragmentGoValues(ctx)
	out.GoBlocks = BuildGraphFragmentGoBlocks(ctx)
	out.ObjectLiterals = BuildGraphFragmentObjectLiterals(ctx)
	out.PropertyReads = BuildGraphFragmentPropertyReads(ctx)
	out.Items = BuildGraphFragmentItems(ctx)
	out.BinaryExprs = BuildGraphFragmentBinaryExprs(ctx)
	if literals := BuildGraphFragmentStrings(ctx); len(literals) > 0 {
		out.Strings = literals
	}
	out.Exports = FragmentExports(graph)
	out.PublicPaths = graph.PythonPublicPaths
	out.PublicTypePaths = graph.PublicTypePaths
	out.ScanMetadata.RebindLines = WritesRebindLines(ctx)
	out.ScanMetadata.FunctionCount, out.ScanMetadata.InternalEdges, out.ScanMetadata.ExternalCalls = len(out.Functions), len(out.InternalEdges), len(out.ExternalCalls)
	return functionIndex
}
