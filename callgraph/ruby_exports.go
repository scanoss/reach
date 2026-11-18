// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// resolveRubyExports maps the public path of every Ruby method of the graph
// to its declaration, so a client's call of that path joins it through the
// stitch's public-name index.
//
// A Ruby constant is public where it is defined: there is no __init__.py, no
// re-export and no __all__, so the path is the method's own module and class
// nesting. Two things are deliberately dropped from the key:
//
//   - the package, which for Ruby is the directory a file sits in and means
//     nothing to a caller: `JWT.encode` is `JWT.encode` whatever tree the gem
//     unpacks into;
//   - the arity, because optional parameters are the norm in Ruby, so a count
//     is meaningless to a caller. `JWT.encode(payload, key, 'HS256')` reaches
//     a `def self.encode(payload, key, algorithm = 'HS256', headers = {})`.
//     Python's keys carry none for the same reason.
//
// A path two declarations share keeps the first: an ambiguous export would
// make a call reach a method it may not, and the stitch's other routes are
// better evidence than a guess.
func resolveRubyExports(graph *CallGraph) map[string]string {
	var out map[string]string
	for _, fn := range graph.Functions {
		if fn == nil || fn.ID.Type == "" || fn.ID.Name == "" {
			continue
		}
		if !strings.Contains(fn.FilePath, ".rb") {
			continue
		}
		public := rubyPublicPath(fn.ID)
		if public == "" {
			continue
		}
		if out == nil {
			out = make(map[string]string)
		}
		if _, taken := out[public]; !taken {
			out[public] = fn.ID.String()
		}
	}
	return out
}

// rubyPublicPath is the path a caller writes to reach a declaration:
// "(JWT).encode" for `JWT.encode`, with the owner in parentheses as a call's
// target key spells it and with no arity.
func rubyPublicPath(id FunctionID) string {
	name := BaseFunctionName(id.Name)
	if name == "" || strings.HasPrefix(name, "<") {
		return "" // a module body or another synthetic declaration
	}
	return "(" + id.Type + ")." + name
}
