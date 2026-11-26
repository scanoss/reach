# reach

reach is a Go library for static reachability analysis. It parses an
application and its dependencies, builds a typed function-level call graph,
and answers which application code reaches a given library function, with
the call chains that prove it.

reach knows nothing about any domain. An application built on it (a
*domain*) supplies what it knows about library APIs as data, and decides
which functions are targets. The first domain is
[crypto-finder](https://github.com/scanoss/crypto-finder) (cryptography
detection); reach was extracted from it at commit `08570a91`.

## Quick path

```sh
go get github.com/scanoss/reach@v0.1.1
```

1. Install your knowledge base once, before the first build:
   `contracts.SetSource(fsys)` (optional: `contracts.SetHints(...)`).
2. Build the call graph of a directory:
   `callgraph.NewBuilderForEcosystem(eco, callgraph.NewParserForEcosystem(eco)).BuildFromDirectories(...)`.
3. Walk back from a target: `graph.Callers[target]` gives its callers.

A runnable version is `ExampleSetSource` in
[`callgraph/contracts/example_test.go`](callgraph/contracts/example_test.go).
To reuse graphs across runs and stitch a dependency closure, see
`ExampleStitch` in [`graphfrag/example_test.go`](graphfrag/example_test.go)
and [docs/NEW_DOMAIN.md](docs/NEW_DOMAIN.md).

## What it does

| Capability | Where | Notes |
|---|---|---|
| Parse source | `callgraph` | tree-sitter parsers for Java, Python, Go, JavaScript/TypeScript, C, C++, Rust |
| Build the call graph | `callgraph.Builder`, `CallGraph` | Links call sites to declarations, including dispatch through interfaces, supertypes and fluent chains. `CallGraph.Callers` is the reverse index. |
| Resolve types | `callgraph` resolvers | Java bytecode and JDK platform signatures, Python dependency signatures, per-language manifests, and return types from library contracts |
| Store one component's graph | `graphfrag` | The graph-fragment JSON format, encode and decode |
| Stitch a dependency closure | `graphfrag.Stitch` | Composes stored fragments into root-to-target chains; renders the callgraph JSON |
| Walk backwards | `graphwalk` | The traversal shared by the live graph and the stitcher |
| Start chains at real entry points | `callgraph/entrypoints` | One embedded YAML file per framework (web, task queues, CLI, containers) |
| Match a ruleset against call sites | `cardmatch` | Card files and rules supplied by the application; see [docs/CARDMATCH.md](docs/CARDMATCH.md) |

## Packages

| Package | Contents |
|---|---|
| `callgraph` | Parsers, type resolvers, `Builder`, `CallGraph`, tracing, condensed reachability |
| `callgraph/contracts` | Contracts loader, types and validation; `SetSource`, `SetHints` |
| `callgraph/entrypoints` | Framework entry-point catalog (embedded YAML) |
| `graphfrag` | Graph-fragment model, export, ingest, stitcher, callgraph JSON renderer |
| `graphfrag/equiv` | Semantic diff of two callgraph exports |
| `graphwalk` | Backward reachability traversal |
| `paramcondition` | Parser for the `param[<selector>]<op><value>` condition grammar |
| `purl` | Package URLs for dependency metadata |
| `language` | Language detection of a directory (go-enry) |
| `skip` | Which files and directories a walk skips |
| `javaruntime` | Java runtime selection for bytecode and platform signature indexing |
| `perf` | Opt-in wall-clock, CPU and allocation timings of build phases |
| `cardmatch` | The cards matcher: loads card files or compiles rules, matches them against a graph fragment |
| `parsememo` | Cross-process memo of parsed files, by content, bound to the binary |

How they fit together: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What a domain supplies

| Input | API | Required |
|---|---|---|
| Library contracts (what a method returns, parameter roles, type hierarchy) | `contracts.SetSource(fs.FS)`, one directory per ecosystem of `*.yaml` | Yes, for typed calls into libraries |
| Language-level hints | `contracts.SetHints(contracts.Hints{...})` | No |
| Cache root for type indexes | `callgraph.NewDiskBytecodeIndexCache(root)`, `callgraph.NewDiskPythonSignatureIndexCache(root)` | No |
| Targets (the functions whose reachability matters) | Walk from them in `CallGraph.Callers`, or attach them to fragments before `Stitch` | Yes |

Details and a worked example: [docs/NEW_DOMAIN.md](docs/NEW_DOMAIN.md).

## Domains

| Domain | Status |
|---|---|
| Cryptography: [crypto-finder](https://github.com/scanoss/crypto-finder) | In production. Installs its crypto KB from `internal/cryptokb`. |
| Vulnerability reachability (does the application reach a dependency's vulnerable function) | Possible with the current API; not built |
| AI usage detection (does it reach a model or provider SDK call) | Possible with the current API; not built |

Some names still carry the crypto origin: the graph-fragment JSON keys
`crypto_*`, Go identifiers such as `CryptoCall` and `CryptoOperation`, and
doc comments. The JSON keys are a stored format and stay as they are.

## Building and testing

```sh
go build ./...
go vet ./...
go test ./...
```

Requires Go 1.26.

Many `callgraph` tests type calls through library contracts. reach carries
no contracts, so those tests skip unless `REACH_TEST_CONTRACTS` names a
contracts directory (one subdirectory per ecosystem):

```sh
REACH_TEST_CONTRACTS=/path/to/contracts go test ./callgraph/
```

crypto-finder runs them against its KB with `make test-reach`.

## Stability

| Item | Status |
|---|---|
| Go API | `v0.x`: may change between minor releases |
| Graph-fragment JSON | Versioned by `graphfrag.SchemaVersion` |
| Callgraph JSON | Versioned by `graphfrag.CallgraphSchemaVersion` and `CallgraphInternedSchemaVersion` |
| Graph construction | Versioned per ecosystem by `graphfrag.GraphAlgoVersion`, `GraphAlgoVersionPython`, `GraphAlgoVersionRust`, `GraphAlgoVersionNode`, `GraphAlgoVersionGo`, `GraphAlgoVersionC` and `GraphAlgoVersionCPP` |

Why the stored formats must stay stable, and when each id bumps:
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md#schema-versioning).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MIT. See [LICENSE](LICENSE). Third-party dependencies keep their own
licenses (`go list -m all` lists them).
