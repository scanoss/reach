// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

// Package rulesetguard keeps the content of private detection rulesets out
// of this repository. reach is public, and so is its history; the rulesets
// that applications run on it (crypto-finder's cards, for one) are not.
//
// The guard test reads every file of the repository and fails on:
//
//   - a token or a `message:` value whose hash is in denylist.txt. The list
//     holds truncated, salted SHA-256 hashes of the rule ids and messages of
//     the private rulesets, so it names nothing itself. Refresh it with
//     `go run ./internal/rulesetguard/gen -ruleset <dir>` against a ruleset
//     checkout, never committing the ruleset.
//   - a YAML file outside testdata whose rules carry a CycloneDX crypto block
//     (`metadata.crypto.assetType` or a card's `crypto.assetType`): the shape
//     of a detection ruleset, whatever its ids (CryptoRules).
//   - a token shaped like a ruleset rule id (`<language>.<namespace>.<name>`
//     with a dash), unless allowed_ids.txt lists it as invented. This catches
//     an id the denylist has not been refreshed with yet.
//
// Tests that need rules build small invented ones (acme, example.com).
package rulesetguard
