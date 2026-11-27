// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"regexp"
	"strings"
)

const rustMutableBorrowPrefix = "&mut "

const rustSharedBorrowPrefix = "&"

const rustSomeWrapperPrefix = "Some("

const rustIntoConversion = ".into()"

const keywordArgumentSign = "="

// PassedVariable is the variable a call argument passes, as trace compares
// it with the name it follows, and the argument's keyword.
func PassedVariable(arg, ecosystem string) (keyword, name string) {
	keyword, value := SplitKeywordArgument(arg, ecosystem)
	return keyword, BareArgument(value, ecosystem)
}

// SplitKeywordArgument splits a Python (`name=value`) or Ruby (`name: value`)
// keyword argument into its keyword and value. Other ecosystems and positional
// arguments return an empty keyword and the argument unchanged.
func SplitKeywordArgument(arg, ecosystem string) (keyword, value string) {
	if ecosystem == ecosystemRuby {
		return splitRubyKeywordArgument(arg)
	}
	if ecosystem != EcosystemPython {
		return "", arg
	}
	if m := PythonKeywordArgumentPattern.FindStringSubmatch(strings.TrimSpace(arg)); len(m) == 3 && !strings.HasPrefix(m[2], keywordArgumentSign) {
		return m[1], strings.TrimSpace(m[2])
	}
	return "", arg
}

// splitRubyKeywordArgument reads `format: "json"`, the Ruby spelling of a
// keyword argument. A second colon is a constant path (`Net::HTTP`), not a
// keyword, and `a ? b : c` never reaches the name
// pattern.
func splitRubyKeywordArgument(arg string) (keyword, value string) {
	m := rubyKeywordArgumentPattern.FindStringSubmatch(strings.TrimSpace(arg))
	if len(m) < 3 || strings.HasPrefix(m[2], ":") {
		return "", arg
	}
	if value = strings.TrimSpace(m[2]); value == "" {
		return "", arg
	}
	return m[1], value
}

// BareArgument strips the borrow, Option wrapping and `.into()` conversion a
// Rust argument passes a variable with (`&mut buf`, `&data`, `Some(&opts)`,
// `(&buf).into()`), so the variable itself is compared. `.into()` changes the
// type the value is held in, not the value.
func BareArgument(arg, ecosystem string) string {
	arg = strings.TrimSpace(arg)
	if ecosystem != EcosystemRust {
		return arg
	}
	if strings.HasPrefix(arg, rustSomeWrapperPrefix) && strings.HasSuffix(arg, ")") {
		arg = strings.TrimSpace(arg[len(rustSomeWrapperPrefix) : len(arg)-1])
	}
	arg = strings.TrimSuffix(arg, rustIntoConversion)
	if strings.HasPrefix(arg, "(") && strings.HasSuffix(arg, ")") {
		arg = strings.TrimSpace(arg[1 : len(arg)-1])
	}
	arg = strings.TrimPrefix(arg, rustMutableBorrowPrefix)
	return strings.TrimSpace(strings.TrimPrefix(arg, rustSharedBorrowPrefix))
}

// LineMayRebind reports whether a source line, not a comment, matches one of
// a name's rebind patterns.
func LineMayRebind(text string, patterns []*regexp.Regexp) bool {
	if isCommentLine(text) {
		return false
	}
	for _, re := range patterns {
		if re.MatchString(text) {
			return true
		}
	}
	return false
}

func isCommentLine(text string) bool {
	trimmed := strings.TrimSpace(text)
	for _, prefix := range []string{"//", "#", "/*", "*"} {
		if strings.HasPrefix(trimmed, prefix) {
			return true
		}
	}
	return false
}

// RebindPatternCache caches, by name, the patterns that recognize a
// rebinding of it.
type RebindPatternCache map[string][]*regexp.Regexp

// Patterns are the shapes of a line that may give name another value or
// overwrite the buffer it holds: an assignment (also compound, indexed, a
// tuple or destructuring target, or Go's :=), a declaration or loop whose
// target is the name (let, var, const, for, as, del; not one that only reads
// it), a mutable borrow, and the standard in-place fills.
func (c RebindPatternCache) Patterns(name string) []*regexp.Regexp {
	if patterns, ok := c[name]; ok {
		return patterns
	}
	n := regexp.QuoteMeta(name)
	word := `(?:^|[^\w.$])` + n
	patterns := []*regexp.Regexp{
		regexp.MustCompile(word + `\s*(?:\[[^\]]*\]\s*)?(?:[-+*/%&|^]|<<|>>|\?\?|:)?=(?:[^=>]|$)`),
		regexp.MustCompile(word + `\s*,[^=]*:?=(?:[^=>]|$)`),
		// The name closing a destructuring target: `(buf, n) = ...`, `[a, b] = ...`.
		regexp.MustCompile(word + `\s*[)\]][^=()]*:?=(?:[^=>]|$)`),
		// A declaration or binder whose target is the name, not one that only
		// reads it (`let n = Wrapper::from_slice(&buf)` keeps buf).
		regexp.MustCompile(`\b(?:let(?:\s+mut)?|var|const|as|del)\s+` + n + `\b`),
		regexp.MustCompile(`\bfor\b[^:{]*?` + word + `\b[^:{]*?\b(?:in|of)\b`),
		regexp.MustCompile(`&mut\s+` + n + `\b`),
		regexp.MustCompile(`\bcopy\s*\(\s*` + n + `\b`),
		regexp.MustCompile(word + `\s*\.\s*(?:copy_from_slice|clone_from_slice|fill|fill_bytes|try_fill_bytes|set|write)\s*\(`),
		regexp.MustCompile(`arraycopy\s*\([^)]*,\s*` + n + `\s*,`),
		regexp.MustCompile(`Arrays\s*\.\s*fill\s*\(\s*` + n + `\b`),
	}
	c[name] = patterns
	return patterns
}
