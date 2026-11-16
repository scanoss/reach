// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// SelectExternalOverload picks the overload of a method declared outside the
// graph (a type-only dependency, indexed from its bytecode) that a call
// invokes. Candidates are the signatures with the call's arity; each known
// argument type (a literal, or a value with a declared type) scores the
// candidates whose parameter at that position has the same erased simple
// name. It returns the unique best candidate, or false when no candidate has
// the call's arity or two candidates tie, so a caller never commits to a guess.
func SelectExternalOverload(signatures []ExternalMethodSignature, call *FunctionCall) (ExternalMethodSignature, bool) {
	if call == nil {
		return ExternalMethodSignature{}, false
	}
	arity := len(call.Arguments)
	var candidates []ExternalMethodSignature
	for _, sig := range signatures {
		if len(sig.ParameterTypes) == arity {
			candidates = append(candidates, sig)
		}
	}
	switch len(candidates) {
	case 0:
		return ExternalMethodSignature{}, false
	case 1:
		return candidates[0], true
	}
	hints := make([]string, arity)
	for i := range arity {
		hints[i] = JavaArgumentType(call, i)
	}
	best, bestScore, tied := -1, -1, false
	for idx, sig := range candidates {
		score := 0
		for i, hint := range hints {
			if hint == "" {
				continue
			}
			if erasedSimpleName(sig.ParameterTypes[i]) == erasedSimpleName(hint) {
				score++
			}
		}
		switch {
		case score > bestScore:
			best, bestScore, tied = idx, score, false
		case score == bestScore:
			tied = true
		}
	}
	if tied || bestScore <= 0 {
		return ExternalMethodSignature{}, false
	}
	return candidates[best], true
}

// JavaArgumentType is the static type of a call's i-th argument when the
// parser knows it without a type checker: a literal, or a single data-flow
// origin with a declared type. Empty when unknown.
func JavaArgumentType(call *FunctionCall, i int) string {
	if i < len(call.ArgumentSources) && len(call.ArgumentSources[i]) == 1 {
		node := call.ArgumentSources[i][0]
		if t := strings.TrimSpace(node.DeclaredType); t != "" {
			return t
		}
		if node.Type == "VALUE" {
			if t := javaLiteralType(node.Value); t != "" {
				return t
			}
		}
	}
	if i < len(call.Arguments) {
		return javaLiteralType(call.Arguments[i])
	}
	return ""
}

// erasedSimpleName reduces a type to the simple name a bytecode signature and
// a source declaration share: generics stripped, package dropped, varargs as
// an array.
func erasedSimpleName(t string) string {
	t = strings.TrimSpace(t)
	if i := strings.Index(t, "<"); i >= 0 {
		if j := strings.LastIndex(t, ">"); j > i {
			t = t[:i] + t[j+1:]
		}
	}
	t = strings.ReplaceAll(t, "...", "[]")
	if i := strings.LastIndex(t, "."); i >= 0 {
		t = t[i+1:]
	}
	if i := strings.LastIndex(t, "$"); i >= 0 {
		t = t[i+1:]
	}
	return t
}
