# Contributing to reach

Run the four checks below before a pull request; CI runs the same ones
(`.github/workflows/ci.yml`). Then check the rules table: most review
comments come from it.

## Before a pull request

```sh
gofmt -l .        # must print nothing
go build ./...
go vet ./...
go test -race ./...
```

A change to `callgraph` should also pass the tests that need a contracts
knowledge base. They skip without one:

```sh
REACH_TEST_CONTRACTS=/path/to/contracts go test ./callgraph/
```

`/path/to/contracts` holds one directory per ecosystem of `*.yaml`
contracts, the layout `contracts.SetSource` reads. crypto-finder runs these
tests against its KB with `make test-reach`.

## What CI runs

| Check | Step in `ci.yml` (job `build-test`) |
|---|---|
| Formatting | `gofmt` |
| Build and vet | `Build`, `Vet` |
| Import guard | `Import guard` (also in `Test`) |
| All tests, race detector | `Test` |

CI has no contracts KB, so the tests that need one skip here. They run in
crypto-finder's `make test-reach` (job `guards` of its `test.yml`), against
its crypto KB, on every pull request there. A reach change that breaks them
shows up when crypto-finder takes the new tag, so run the command above
against a KB before tagging.

## Rules

| Rule | What it means | Enforced by |
|---|---|---|
| No domain knowledge in the engine | Library contracts and hints arrive through `contracts.SetSource` and `contracts.SetHints`. A parser or resolver never hard-codes knowledge of a particular library or domain. | Review |
| No imports from applications | reach imports only the standard library, its own packages and the modules in `internal/importguard.AllowedModules`. Adding a module there is deliberate: every application on reach inherits it. | `go test ./internal/importguard` |
| Stored formats are versioned | Graph-fragment and callgraph JSON keep their keys (`crypto_*` included). A wire change bumps `graphfrag.SchemaVersion` or the callgraph schema version. | Review |
| Graph changes bump the graph algorithm id | A change that alters the structural graph of an ecosystem bumps that ecosystem's id (`graphfrag.GraphAlgoVersion`, `GraphAlgoVersionPython` or `GraphAlgoVersionRust`) and documents the bump above the constant. Bump only the ecosystem that changed. | crypto-finder's `TestGraphAlgoVersionGuard`, after the reach bump |
| Errors | Return wrapped errors with a stable package prefix: `fmt.Errorf("callgraph: ...: %w", err)`. The application decides what an error means to its user. | Review |
| Headers | Every Go file starts with the two lines below. | Review |
| Commits | [Conventional Commits](https://www.conventionalcommits.org/). | Review |

```go
// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT
```

Why the versioning rules matter and how the guard works:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#schema-versioning).

## Releasing an engine change to crypto-finder

1. Merge the change here, with its id bump if graphs changed.
2. Tag a reach release (`vX.Y.Z`).
3. In crypto-finder, require the new tag in `go.mod` and run its tests,
   including the graph algorithm guard; refresh the guard's golden there if
   an id was bumped.

## License

By contributing you agree that your contributions are licensed under the
MIT license of this repository.
