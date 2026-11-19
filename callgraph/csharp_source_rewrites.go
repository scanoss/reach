// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

// Two string forms are newer than the grammar, and each loses the structure
// of the whole file: the file parses as a flat error, its types gone and the
// calls of some of its methods with them. Both are rewritten before parsing,
// byte for byte, so every line, column and offset outside them is the
// source's own.
//
// C# 11 raw string literals ("""...""") hold no call the graph can follow --
// a raw literal is text -- so each becomes a verbatim string of the same
// bytes: `@"` then blanks then `"`, newlines kept.
//
// A verbatim interpolated string writes a quote as two ($@"a ""b"" c"), which
// the grammar reads as a close and a reopen; it recovers inside the line and
// loses the file from the second such string on. The two quotes become two
// blanks, which leaves the interpolation holes -- and the calls inside them --
// where they are.
//
// Dereferencing a pointer cast (*(ulong*)p) is the one unsafe form the grammar
// does not read; the dereference and the cast become blanks, which leaves the
// operand, and no call is written inside either.

// csharpRewriteSource returns src with those two forms blanked, and whether
// it rewrote any.
func csharpRewriteSource(src []byte) ([]byte, bool) {
	if !csharpHasRawString(src) && !csharpHasVerbatimInterpolation(src) && !csharpHasPointerCast(src) {
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
			var blanked bool
			i, blanked = csharpSkipQuoted(out, i)
			rewrote = rewrote || blanked
			continue
		case out[i] == '*':
			if end, ok := csharpPointerCast(out, i); ok {
				for j := i; j < end; j++ {
					out[j] = ' '
				}
				i, rewrote = end, true
				continue
			}
		}
		i++
	}
	return out, rewrote
}

// csharpHasVerbatimInterpolation reports a source that opens a verbatim
// interpolated string, in either prefix order.
func csharpHasVerbatimInterpolation(src []byte) bool {
	for i := 0; i+2 < len(src); i++ {
		if src[i+2] != '"' {
			continue
		}
		if (src[i] == '@' && src[i+1] == '$') || (src[i] == '$' && src[i+1] == '@') {
			return true
		}
	}
	return false
}

// csharpHasPointerCast reports a source that dereferences a cast.
func csharpHasPointerCast(src []byte) bool {
	for i := 0; i+1 < len(src); i++ {
		if src[i] == '*' && src[i+1] == '(' {
			return true
		}
	}
	return false
}

// csharpPointerCast returns the index just past the `*(T*)` written at i, and
// whether one is there. Multiplying by a cast to a pointer type is not C#, so
// the shape is the dereference and nothing else.
func csharpPointerCast(src []byte, i int) (int, bool) {
	if src[i] != '*' || i+1 >= len(src) || src[i+1] != '(' {
		return i, false
	}
	j := csharpSkipBlanks(src, i+2)
	start := j
	for j < len(src) && (csharpIsIdentByte(src[j]) || src[j] == '.' || src[j] == ':') {
		j++
	}
	if j == start {
		return i, false
	}
	j = csharpSkipBlanks(src, j)
	stars := j
	for j < len(src) && src[j] == '*' {
		j++
	}
	if j == stars {
		return i, false
	}
	j = csharpSkipBlanks(src, j)
	if j >= len(src) || src[j] != ')' {
		return i, false
	}
	return j + 1, true
}

// csharpSkipBlanks moves past spaces and tabs.
func csharpSkipBlanks(src []byte, i int) int {
	for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
		i++
	}
	return i
}

// csharpIsIdentByte reports a byte a type name may be written with.
func csharpIsIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
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
// literal's opening. It blanks the escaped quotes of a verbatim interpolated
// string and reports having done so.
func csharpSkipQuoted(src []byte, i int) (int, bool) {
	quote := src[i]
	verbatim, interpolated := csharpStringPrefix(src, i)
	blanked := false
	for j := i + 1; j < len(src); j++ {
		switch {
		case !verbatim && src[j] == '\\':
			j++
		case src[j] == quote && verbatim && j+1 < len(src) && src[j+1] == quote:
			if interpolated {
				src[j], src[j+1] = ' ', ' '
				blanked = true
			}
			j++
		case src[j] == quote:
			return j + 1, blanked
		case !verbatim && src[j] == '\n':
			return j, blanked
		}
	}
	return len(src), blanked
}

// csharpStringPrefix reads the `@` and `$` the string opening at i is written
// with, in either order.
func csharpStringPrefix(src []byte, i int) (verbatim, interpolated bool) {
	for j := i - 1; j >= 0; j-- {
		switch src[j] {
		case '@':
			verbatim = true
		case '$':
			interpolated = true
		default:
			return verbatim, interpolated
		}
	}
	return verbatim, interpolated
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
