# Changelog

Notable changes to reach. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions are the
module's tags. Releases before this file are described by their tags and
pull requests.

## [Unreleased]

### Added

- `appreach`: application reachability, moved from crypto-finder
  (`pkg/appreach`, the part that knows nothing of findings or responses) and
  relicensed MIT. `ParseDependencies` canonicalizes a pinned closure (purls,
  PEP 503 names, PEP 440 versions) into `Pins`; `NewClosure` names modules,
  splices components without a graph out of the dependency graph and builds
  the application's root fragment from its call sites; `Closure.Run`
  stitches with a fixed policy and returns the callgraph export and one
  `Verdict` per finding id (`reachable`, `unreachable`, or `unknown` with a
  reason such as `ambiguous_dispatch` or `dependency_without_graph`). Also
  `PurlToModule`, `ParsePurl`, `PyPIVersion`, `ComputeFindingID`,
  `FindingOwners`, `StitchIDs` and `DecodeProducerGraph`.
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

- `graphfrag`: a C# external call carries `candidate_owners`
  (`graph-fragment-1.40`), the fully qualified types its owner can be: the
  caller's own namespace first, then one per `using` of the file. The stitch
  re-keys a C# call on them when nothing else resolves it and keeps the one
  owner a dependency declares, so an application's call into a NuGet
  dependency is no longer always unreachable. Two owners that resolve to
  different declarations take no edge. A fragment before 1.40 carries none and
  stitches as before.

### Changed

- C# graphs move to `graph-algo-cs-3`: a receiver spelled with the name of a
  field, property or event the file declares is read as that value, not as a
  type a `using` could name, so it carries no owner alternatives. Stored
  `graph-algo-cs-2` C# graphs must be mined again.
- CI's `gofmt` step skips `testdata/`: source fixtures keep the layout their
  recorded fragments pin.

### Fixed

- `cardmatch` tests pass when run from the module cache. The Go fixtures
  under `cardmatch/testdata` held a `go.mod`, so the module zip left their
  directories out (`stat testdata/go_producer: no such file or directory`).
  They keep it as `go.mod.fixture` now, and `internal/moduleguard` fails on
  any `go.mod` below the module root.
- A dependency purl is no longer prefixed twice when the module the graph
  records is already a purl (NuGet, npm, Cargo and gem dependencies):
  `pkg:nuget/pkg:nuget%2FAcme.Crypto@2.4.0` is now `pkg:nuget/Acme.Crypto@2.4.0`,
  on chain frames and on the file-level dependency purl alike.

### Removed

- The ruleset guard no longer carries a list of hashed rule ids and messages
  (`internal/rulesetguard/denylist.txt`) or its generator
  (`internal/rulesetguard/gen`): a public hash list can be probed. The guard
  keeps the checks that need no knowledge of a private ruleset.
