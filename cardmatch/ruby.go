// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package cardmatch

import "strings"

// The Ruby ecosystem, as the call graph and the ruleset directories name it.
const ecosystemRuby = "ruby"

// rubyRule: the rule is read with the Ruby shapes (its languages name ruby).
func rubyRule(r *OMap) bool {
	for _, l := range asOr[[]any](r.GetOr("languages")) {
		if s, ok := l.(string); ok && strings.EqualFold(s, ecosystemRuby) {
			return true
		}
	}
	return false
}

// rubyTypeMetavarMatch: the call's constant path is what the entry's type
// metavariable stands for, and matches the type regex when the rule gives one.
// Two shapes reach here, and the ruleset uses both:
//
//	$ALGO.hexdigest(...)             the whole receiver is the metavariable,
//	                                 pinned by `^Digest::MD5$`
//	OpenSSL::Digest::$ALGO.new(...)  the last segment of a path, pinned by
//	                                 `^(SHA224|SHA256|...)$`
//
// The name bound is what the regex is read against and what fills the rule's
// metadata, so the first shape binds the whole path and the second its last
// segment -- exactly what each rule's regex is written for.
func rubyTypeMetavarMatch(e *Entry, cls string, _ *Site, groups Groups) bool {
	if cls == "" || e.Type == nil || e.TypeMetavar == nil {
		return false
	}
	// A key is "<package>.(Type).method", and the package of a Ruby call is
	// the scanned file's directory, not a namespace: a constant path is
	// absolute. Read the path alone, the way the exact-type comparison does
	// with its "."+type suffix.
	if i := strings.LastIndex(cls, "."); i >= 0 {
		cls = cls[i+1:]
	}
	name := ""
	switch *e.Type {
	case *e.TypeMetavar:
		name = cls
	default:
		prefix, ok := strings.CutSuffix(*e.Type, rubyScopeSeparator+*e.TypeMetavar)
		if !ok {
			return false
		}
		rest, ok := strings.CutPrefix(cls, prefix+rubyScopeSeparator)
		if !ok || strings.Contains(rest, rubyScopeSeparator) {
			return false
		}
		name = rest
	}
	if e.TypeRegex != nil {
		g := reMatch(*e.TypeRegex, name)
		if g == nil {
			return false
		}
		for k, v := range g {
			groups[k] = v
		}
	}
	groups[strings.TrimPrefix(*e.TypeMetavar, "$")] = name
	return true
}

// rubyScopeSeparator joins the segments of a Ruby constant path.
const rubyScopeSeparator = "::"
