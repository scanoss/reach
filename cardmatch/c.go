// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package cardmatch

import "strings"

// The C and C++ ecosystems, as the call graph and the ruleset directories name them.
const (
	ecosystemC   = "c"
	ecosystemCPP = "cpp"
)

// cRule: the rule is read with the C shapes (its languages name c, cpp or
// c++). C rules name both c and cpp; C++ rules name cpp.
func cRule(r *OMap) bool {
	for _, l := range asOr[[]any](r.GetOr("languages")) {
		if s, ok := l.(string); ok {
			switch strings.ToLower(s) {
			case ecosystemC, ecosystemCPP, "c++":
				return true
			}
		}
	}
	return false
}
