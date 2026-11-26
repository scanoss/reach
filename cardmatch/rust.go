// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package cardmatch

import "strings"

const ecosystemRust = "rust"

// rustRule: the rule is read with the Rust shapes (its languages name rust).
func rustRule(r *OMap) bool {
	for _, l := range asOr[[]any](r.GetOr("languages")) {
		if s, ok := l.(string); ok && strings.EqualFold(s, ecosystemRust) {
			return true
		}
	}
	return false
}
