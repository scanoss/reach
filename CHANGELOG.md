# Changelog

Notable changes to reach. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are the
module's tags. Releases before this file are described by their tags and
pull requests.

## [Unreleased]

### Added

- `cardmatch`: the cards matcher, moved from crypto-finder
  (`internal/cardmatch`) and relicensed MIT. It matches card files or
  OpenGrep-style rules against a graph fragment's call sites.
  `cardmatch.Options` sets the rule metadata key (default `crypto`), extra
  v3 rules-entry keys, the card-file language function and the comparison
  policies. See [docs/CARDMATCH.md](docs/CARDMATCH.md).
- `parsememo`: the cross-process parse memo the matcher uses, enabled with
  `parsememo.Enable(dir)`.
- `github.com/dlclark/regexp2` is an allowed module (`internal/importguard`):
  cards and rules use Python `re` patterns (lookahead, named groups), which
  Go's RE2 rejects.
- CI step `Ruleset content guard` (`internal/rulesetguard`): fails on an
  unlisted rule-id-shaped token, on a YAML or card file outside `testdata/`
  whose rules carry a CycloneDX crypto block, and on a rule or card file
  under `testdata/` without the line `# rulesetguard: invented`.

### Changed

- CI's `gofmt` step skips `testdata/`: source fixtures keep the layout their
  recorded fragments pin.

### Removed

- The ruleset guard no longer carries a list of hashed rule ids and messages
  (`internal/rulesetguard/denylist.txt`) or its generator
  (`internal/rulesetguard/gen`): a public hash list can be probed. The guard
  keeps the checks that need no knowledge of a private ruleset.
