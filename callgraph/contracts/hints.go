// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package contracts

import "sync/atomic"

// Hints is language-level knowledge the engine consults beside the
// per-library contracts: data that tunes a parser or the inference pass for
// the application's domain rather than describing one library's API. The
// application installs it with SetHints, next to its contracts source.
type Hints struct {
	// JavaWildcardTypePackages maps a simple Java class name to the package a
	// wildcard import resolves it to when several wildcard imports of a file
	// could declare it ("Cipher" -> "javax.crypto").
	JavaWildcardTypePackages map[string]string
	// InferenceTriggerTypes are declared return types, besides the engine's
	// generic ones (raw Object, type parameters, primitives, ...), vague
	// enough that return-type inference refines them ("java.security.Key").
	InferenceTriggerTypes map[string]struct{}
}

var hints atomic.Pointer[Hints]

// SetHints installs h as the engine's hints; the zero Hints removes them.
func SetHints(h Hints) {
	hints.Store(&h)
}

// CurrentHints returns the installed hints, the zero Hints when none are.
func CurrentHints() *Hints {
	if h := hints.Load(); h != nil {
		return h
	}
	return &Hints{}
}
