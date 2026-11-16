// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package skip

import "strings"

// UserExcludeSource provides skip patterns supplied directly via the CLI
// (--exclude <pattern> flag, repeatable). Patterns are taken verbatim and
// only trimmed; empty entries (e.g. from accidental --exclude "") are
// dropped to avoid emitting meaningless arguments to downstream scanners.
//
// Deduplication is intentionally NOT performed here — MultiSource.Load()
// deduplicates across all sources, keeping the single-responsibility
// principle: sources provide raw data, MultiSource normalises it.
type UserExcludeSource struct {
	patterns []string
}

// NewUserExcludeSource creates a source wrapping CLI --exclude patterns.
//
// Parameters:
//   - patterns: Raw pattern strings as received from the cobra flag.
//
// Returns:
//   - *UserExcludeSource: Source ready to be added to a MultiSource.
func NewUserExcludeSource(patterns []string) *UserExcludeSource {
	return &UserExcludeSource{patterns: patterns}
}

// Load returns the user-supplied patterns with whitespace trimmed and empty
// entries removed. This source never fails — it does no I/O.
//
// Returns:
//   - []string: Trimmed, non-empty patterns
//   - error: Always nil (included for interface compatibility)
func (u *UserExcludeSource) Load() ([]string, error) {
	out := make([]string, 0, len(u.patterns))
	for _, p := range u.patterns {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

// Name returns a descriptive name for this pattern source.
// The flag name "--exclude" is embedded so that log messages like
// "Using N skip patterns from cli-flags(--exclude)" are immediately
// actionable — users can search their invocation for "--exclude".
func (u *UserExcludeSource) Name() string {
	return "cli-flags(--exclude)"
}
