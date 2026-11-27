// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"path/filepath"

	"github.com/scanoss/reach/callgraph"
)

// BuildCallSiteParameters returns the parameters of a call site. Every export
// of a call site uses it so they all describe its parameters the same way.
func BuildCallSiteParameters(ctx *Context, call *callgraph.FunctionCall) []CallGraphParameter {
	if call == nil {
		return nil
	}
	callee := ctx.Graph.Functions[call.Callee.String()]
	sourcePath := filepath.ToSlash(call.FilePath)
	if ctx.Graph != nil {
		sourcePath = NormalizeExportPath(ctx, call.FilePath).FilePath
	}
	return MergeCallParameters(
		ctx,
		nil,
		&call.Callee,
		callee,
		call.Arguments,
		call.ArgumentSources,
		sourcePath,
		call.Line,
	)
}
