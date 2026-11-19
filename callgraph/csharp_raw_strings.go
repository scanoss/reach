// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

// C# 11 raw string literals ("""...""") are newer than the grammar, which
// fails on one and loses the structure of the whole file with it: a file that
// writes one parsed as a flat error, its types gone and the calls of some of
// its methods with them. They hold no call the graph can follow -- a raw
// literal is text -- so each is rewritten, before parsing, into a verbatim
// string of exactly the same bytes: `@"` then blanks then `"`, newlines kept.
// Every line, column and offset outside the literal is the source's own.

// csharpRewriteRawStrings returns src with every raw string literal blanked,
// and whether it rewrote any.
func csharpRewriteRawStrings(src []byte) ([]byte, bool) {
	if !csharpHasRawString(src) {
		return src, false
	}
	out := make([]byte, len(src))
	copy(out, src)
	rewrote := false
	for i := 0; i < len(out); {
		switch {
		case csharpSkipsComment(out, &i):
			continue
		case out[i] == '"' && csharpQuoteRun(out, i) >= 3:
			i = csharpBlankRawString(out, i)
			rewrote = true
			continue
		case out[i] == '"' || out[i] == '\'':
			i = csharpSkipQuoted(out, i)
			continue
		}
		i++
	}
	return out, rewrote
}

// csharpHasRawString reports a source that writes three quotes in a row.
func csharpHasRawString(src []byte) bool {
	for i := 0; i+2 < len(src); i++ {
		if src[i] == '"' && src[i+1] == '"' && src[i+2] == '"' {
			return true
		}
	}
	return false
}

// csharpQuoteRun is how many quotes start at i.
func csharpQuoteRun(src []byte, i int) int {
	n := 0
	for i+n < len(src) && src[i+n] == '"' {
		n++
	}
	return n
}

// csharpBlankRawString rewrites the raw literal whose opening run starts at
// i, and returns the index just past it. A literal with no closing run runs
// to the end of the file, which is what an unterminated one does anyway.
func csharpBlankRawString(src []byte, i int) int {
	open := csharpQuoteRun(src, i)
	end := len(src)
	for j := i + open; j < len(src); j++ {
		if src[j] != '"' {
			continue
		}
		if run := csharpQuoteRun(src, j); run >= open {
			end = j + run
			break
		}
		j += csharpQuoteRun(src, j) - 1
	}
	// `@"` opens a verbatim string, which may span lines as a raw one does;
	// the last byte closes it, and everything between is blank but for the
	// newlines, so every later line keeps its number.
	src[i], src[i+1] = '@', '"'
	for j := i + 2; j < end-1; j++ {
		if src[j] != '\n' && src[j] != '\r' {
			src[j] = ' '
		}
	}
	src[end-1] = '"'
	return end
}

// csharpSkipQuoted moves past an ordinary string, verbatim string or
// character literal, so a `"""` written inside one is not read as a raw
// literal's opening.
func csharpSkipQuoted(src []byte, i int) int {
	quote := src[i]
	verbatim := i > 0 && src[i-1] == '@'
	for j := i + 1; j < len(src); j++ {
		switch {
		case !verbatim && src[j] == '\\':
			j++
		case src[j] == quote && verbatim && j+1 < len(src) && src[j+1] == quote:
			j++
		case src[j] == quote:
			return j + 1
		case !verbatim && src[j] == '\n':
			return j
		}
	}
	return len(src)
}

// csharpSkipsComment moves i past a line or block comment and reports it.
func csharpSkipsComment(src []byte, i *int) bool {
	j := *i
	if j+1 >= len(src) || src[j] != '/' {
		return false
	}
	switch src[j+1] {
	case '/':
		for j += 2; j < len(src) && src[j] != '\n'; j++ {
		}
		*i = j
		return true
	case '*':
		for j += 2; j+1 < len(src); j++ {
			if src[j] == '*' && src[j+1] == '/' {
				*i = j + 2
				return true
			}
		}
		*i = len(src)
		return true
	}
	return false
}
