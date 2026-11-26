// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package rulesetguard

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
)

// salt prefixes every hashed value, so the denylist is no table of plain
// SHA-256 sums.
const salt = "reach-rulesetguard-1\x00"

// hashLen is the hex length a hash is truncated to: 64 bits, against some
// twenty thousand entries and a few million tokens.
const hashLen = 16

// minMessage is the shortest message hashed: shorter ones are generic.
const minMessage = 20

// Hash is a denylist entry for value.
func Hash(value string) string {
	sum := sha256.Sum256([]byte(salt + value))
	return hex.EncodeToString(sum[:])[:hashLen]
}

// NormalizeMessage is a message as hashed: trimmed, unquoted, spaces folded.
func NormalizeMessage(m string) string {
	m = strings.TrimSpace(m)
	if len(m) >= 2 && (m[0] == '"' || m[0] == '\'') && m[len(m)-1] == m[0] {
		m = m[1 : len(m)-1]
	}
	return strings.Join(strings.Fields(m), " ")
}

// HashedMessage reports whether a message is long enough to be hashed.
func HashedMessage(m string) bool { return len(m) >= minMessage }

var (
	tokenRE   = regexp.MustCompile(`[A-Za-z0-9_][A-Za-z0-9_.\-]{14,}[A-Za-z0-9_]`)
	messageRE = regexp.MustCompile(`message:\s*(.+)$`)
	// idShapeRE is the shape of a ruleset rule id: a language, then at least
	// two dotted, lower-case segments, one of them with a dash.
	idShapeRE = regexp.MustCompile(`\b(?:c|cpp|csharp|go|java|javascript|python|ruby|rust|typescript)(?:\.[a-z0-9_]+(?:-[a-z0-9_]+)*){2,}\b`)
)

// Finding is one match of the guard in a file.
type Finding struct {
	Line   int
	Reason string
}

// Scan returns what the guard finds in text: denied ids and messages, and
// rule-id-shaped tokens allowed does not list.
func Scan(text string, denied, allowed map[string]bool) []Finding {
	var out []Finding
	for i, line := range strings.Split(text, "\n") {
		for _, tok := range tokenRE.FindAllString(line, -1) {
			if denied[Hash(strings.Trim(tok, ".-"))] {
				out = append(out, Finding{i + 1, "a token is a private ruleset rule id"})
			}
		}
		if m := messageRE.FindStringSubmatch(line); m != nil {
			if msg := NormalizeMessage(m[1]); HashedMessage(msg) && denied[Hash(msg)] {
				out = append(out, Finding{i + 1, "a message is a private ruleset rule message"})
			}
		}
		for _, id := range idShapeRE.FindAllString(line, -1) {
			if strings.Contains(id, "-") && !allowed[id] {
				out = append(out, Finding{i + 1, "a rule-id-shaped token (" + id + ") is not in allowed_ids.txt"})
			}
		}
	}
	return out
}
