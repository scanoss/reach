// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

// Package rulesetguard keeps the content of private detection rulesets out
// of this repository. reach is public, and so is its history; the rulesets
// that applications run on it (crypto-finder's cards, for one) are not.
//
// The guard test reads every file of the repository and fails on:
//
//   - a token shaped like a ruleset rule id (`<language>.<namespace>.<name>`
//     with a dash), unless allowed_ids.txt lists it as invented.
//   - a YAML or card file outside testdata whose rules carry a CycloneDX
//     crypto block (`metadata.crypto.assetType` or a card's
//     `crypto.assetType`): the shape of a detection ruleset, whatever its ids
//     (CryptoRules).
//   - a rule or card file under testdata without the line
//     `# rulesetguard: invented` (InventedMarker), which says its rules were
//     made up for the test.
//
// None of these checks knows the content of a private ruleset: the guard
// holds no list of its ids or messages, hashed or not, because a public list
// can be probed. It catches a pasted rule file by its shape.
//
// Tests that need rules build small invented ones (acme, example.com).
package rulesetguard
