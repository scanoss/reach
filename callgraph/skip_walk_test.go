// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	"github.com/scanoss/reach/skip"
)

// skipCallgraphWalkDir mirrors Builder.skipWalkDirectory for tests that
// walk a fixture themselves instead of going through the builder.
func skipCallgraphWalkDir(name string) bool {
	return strings.HasPrefix(name, ".") || skip.DefaultDirMatcher().ShouldSkip(name, true)
}
