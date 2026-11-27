// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"cmp"
	"slices"

	"github.com/scanoss/reach/graphfrag"
)

// BuildGraphFragmentDeclarations lists the declarations and the casts of
// every exported function (graph-fragment-1.18), each in function index
// order, then line and column.
func BuildGraphFragmentDeclarations(ctx *Context, functionIndex map[string]int) ([]graphfrag.GraphFragmentDeclaration, []graphfrag.GraphFragmentCast) {
	if ctx == nil || ctx.Graph == nil {
		return nil, nil
	}
	var declarations []graphfrag.GraphFragmentDeclaration
	var casts []graphfrag.GraphFragmentCast
	for _, key := range SortedKeys(ctx.Graph.Functions) {
		index, ok := functionIndex[key]
		if !ok {
			continue
		}
		fn := ctx.Graph.Functions[key]
		for _, d := range fn.Declarations {
			declarations = append(declarations, graphfrag.GraphFragmentDeclaration{
				Function: index, Line: d.Line, StartCol: d.StartCol, EndCol: d.EndCol, EndLine: d.EndLine,
				Type: d.Type, Name: d.Name, Init: d.Init,
			})
		}
		for _, c := range fn.Casts {
			casts = append(casts, graphfrag.GraphFragmentCast{
				Function: index, Line: c.Line, StartCol: c.StartCol, EndCol: c.EndCol, EndLine: c.EndLine,
				Type: c.Type, InnerLine: c.InnerLine, InnerCol: c.InnerCol,
			})
		}
	}
	slices.SortStableFunc(declarations, func(a, b graphfrag.GraphFragmentDeclaration) int {
		return cmp.Or(cmp.Compare(a.Function, b.Function), cmp.Compare(a.Line, b.Line), cmp.Compare(a.StartCol, b.StartCol))
	})
	slices.SortStableFunc(casts, func(a, b graphfrag.GraphFragmentCast) int {
		return cmp.Or(cmp.Compare(a.Function, b.Function), cmp.Compare(a.Line, b.Line), cmp.Compare(a.StartCol, b.StartCol))
	})
	return declarations, casts
}

// BuildGraphFragmentCallAnchors lists every call of every exported function
// (graph-fragment-1.20) with its syntax-tree position, and, in a fragment
// that carries calls (FragmentCarriesCalls), the call itself (1.21): its target, text, arguments and their
// provenance. They are in function index order, each function's calls in
// the order the parser recorded them.
func BuildGraphFragmentCallAnchors(ctx *Context, functionIndex map[string]int) []graphfrag.GraphFragmentCallAnchor {
	if ctx == nil || ctx.Graph == nil {
		return nil
	}
	var anchors []graphfrag.GraphFragmentCallAnchor
	for _, key := range SortedKeys(ctx.Graph.Functions) {
		index, ok := functionIndex[key]
		if !ok {
			continue
		}
		for i := range ctx.Graph.Functions[key].Calls {
			call := &ctx.Graph.Functions[key].Calls[i]
			anchor := graphfrag.GraphFragmentCallAnchor{
				Function: index, Line: call.Line, StartCol: call.StartCol, EndCol: call.EndCol,
				Kind: call.ASTKind, Path: call.NamedASTPath, ChainID: call.ChainID,
			}
			if FragmentCarriesCalls(ctx) {
				anchor.Callee, anchor.Raw, anchor.Arguments = call.Callee.String(), call.Raw, call.Arguments
				anchor.ArgumentSources = fragmentArgumentSources(ctx, call.ArgumentSources)
			}
			anchors = append(anchors, anchor)
		}
	}
	slices.SortStableFunc(anchors, func(a, b graphfrag.GraphFragmentCallAnchor) int { return cmp.Compare(a.Function, b.Function) })
	return anchors
}
