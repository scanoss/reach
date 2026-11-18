// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"path"
	"strings"
)

// ruby_requires.go makes a `require` the call it is. Loading a Ruby file runs
// every statement outside a method in it: `require 'openssl'` runs the
// constants openssl/ssl.rb builds -- a Diffie-Hellman group, a default
// certificate store -- and a consumer that follows calls alone never reaches
// them, so it reports findings on code the program certainly ran.
//
// The target is the module init of the required file, keyed as the loader
// keys it: a gem publishes `lib/<path>.rb` for `require '<path>'`, which is
// how every gem on rubygems.org is laid out. Within a component
// `require_relative` resolves against the requiring file's own directory.

// rubyRequireRoot is the directory a gem's require paths resolve against.
const rubyRequireRoot = "lib"

// resolveRubyRequires adds the module init each require runs, beside the
// `require` call itself, which stays the site a rule may read.
func resolveRubyRequires(graph *CallGraph) {
	var added []struct {
		fn   *FunctionDecl
		call FunctionCall
	}
	for _, fn := range graph.Functions {
		if fn == nil {
			continue
		}
		for i := range fn.Calls {
			call := &fn.Calls[i]
			required, ok := rubyRequiredModule(fn, call)
			if !ok {
				continue
			}
			candidate := *call
			candidate.Callee = required
			// The key is a full one, not a method to dispatch on: either the
			// closure holds that module init or it holds nothing, and a
			// require of a gem laid out differently joins nothing at all.
			added = append(added, struct {
				fn   *FunctionDecl
				call FunctionCall
			}{fn, candidate})
		}
	}
	for _, a := range added {
		a.fn.Calls = append(a.fn.Calls, a.call)
	}
}

// rubyRequiredModule is the module init a require call runs.
func rubyRequiredModule(fn *FunctionDecl, call *FunctionCall) (FunctionID, bool) {
	name := BaseFunctionName(call.Callee.Name)
	if call.Callee.Type != "" || call.RubyDispatchCandidate {
		return FunctionID{}, false
	}
	if len(call.Arguments) != 1 {
		return FunctionID{}, false
	}
	required := strings.Trim(strings.TrimSpace(call.Arguments[0]), `"'`)
	if required == "" || strings.ContainsAny(required, "#{}$@ ") {
		return FunctionID{}, false // interpolated: the path is not in the source
	}
	switch name {
	case "require":
		return FunctionID{Package: rubyPackageOf(rubyRequireRoot, required), Name: moduleInitMethodName}, true
	case "require_relative":
		// Relative to the requiring file, which the module init's own
		// package already names: its last segment is that file's stem.
		dir := fn.ID.Package
		if i := strings.LastIndex(dir, rubyScopeSeparator); i >= 0 {
			dir = dir[:i]
		} else {
			dir = ""
		}
		return FunctionID{Package: rubyPackageOf(dir, required), Name: moduleInitMethodName}, true
	}
	return FunctionID{}, false
}

// rubyPackageOf is the package a required path keys its module init under:
// the separators a Ruby package path uses, under the require root.
func rubyPackageOf(root, required string) string {
	required = strings.TrimSuffix(strings.TrimPrefix(path.Clean(required), "./"), ".rb")
	var segments []string
	if root != "" {
		segments = strings.Split(root, rubyScopeSeparator)
	}
	for _, segment := range strings.Split(required, "/") {
		switch segment {
		case "", ".":
		case "..":
			if len(segments) > 0 {
				segments = segments[:len(segments)-1]
			}
		default:
			segments = append(segments, segment)
		}
	}
	return strings.Join(segments, rubyScopeSeparator)
}
