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
- CI step `Ruleset content guard` (`internal/rulesetguard`): fails on a rule
  id or message of a private ruleset (a list of salted hashes, never the
  content), on an unlisted rule-id-shaped token, and on a YAML file outside
  `testdata/` whose rules carry a CycloneDX crypto block.

### Changed

- CI's `gofmt` step skips `testdata/`: source fixtures keep the layout their
  recorded fragments pin.

### Fixed

- `cardmatch` tests pass when run from the module cache. The Go fixtures
  under `cardmatch/testdata` held a `go.mod`, so the module zip left their
  directories out (`stat testdata/go_producer: no such file or directory`).
  They keep it as `go.mod.fixture` now, and `internal/moduleguard` fails on
  any `go.mod` below the module root.
