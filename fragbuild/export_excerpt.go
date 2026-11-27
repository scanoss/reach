// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import "os"

// Excerpts returns the context's source reader, creating it on first use.
func Excerpts(ctx *Context) *SourceExcerpts {
	if ctx.ExcerptSource == nil {
		ctx.ExcerptSource = NewSourceExcerpts(&ctx.Artifacts, os.ReadFile)
	}
	return ctx.ExcerptSource
}
