# Contributing to reach

## Before a pull request

```sh
gofmt -l .        # must print nothing
go build ./...
go vet ./...
go test -race ./...
```

CI runs the same commands (`.github/workflows/ci.yml`).

Changes to `callgraph` should also pass the tests that need a contracts
knowledge base. They skip without one; run them against crypto-finder's
crypto KB:

```sh
REACH_TEST_CONTRACTS=/path/to/crypto-finder/internal/cryptokb go test ./callgraph/
```

## Rules

- **No domain knowledge in the engine.** Library contracts and hints come from
  the application through `contracts.SetSource` and `contracts.SetHints`.
  Do not hard-code knowledge about a particular library or domain in a parser
  or resolver.
- **No imports from applications.** reach imports only the standard library,
  its own packages and the third-party modules listed in
  `internal/importguard.AllowedModules`; `go test ./internal/importguard`
  enforces it. Adding a module to that list is a deliberate change: every
  application that builds on reach inherits it.
- **Stored formats are versioned.** The graph-fragment and callgraph JSON keep
  their keys (including `crypto_*`) and carry schema versions
  (`graphfrag.SchemaVersion`, `graphfrag.CallgraphSchemaVersion`). A change to
  how a graph is built that changes stored graphs bumps the ecosystem's graph
  algorithm id (`graphfrag.GraphAlgoVersion` or `GraphAlgoVersionPython`).
- **Errors.** Return wrapped errors with a stable package prefix
  (`fmt.Errorf("callgraph: ...: %w", err)`); the application decides what an
  error means to its user.
- **Headers.** Every Go file starts with:

  ```go
  // Copyright (C) 2026 SCANOSS.COM
  // SPDX-License-Identifier: MIT
  ```

- **Commits** follow [Conventional Commits](https://www.conventionalcommits.org/).

## License

By contributing you agree that your contributions are licensed under the MIT
license of this repository.
