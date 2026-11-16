# reach

reach is a Go library for static reachability analysis of source code. It
parses a project and its dependencies, builds a function-level call graph with
type resolution, and answers which application code reaches a given library
call. It stores per-component graphs as reusable fragments and stitches a
dependency closure of fragments back into root-to-call chains.

reach holds no knowledge of any domain. A domain (an application built on
reach) installs what it knows about library APIs as data: contracts that type
calls, and hints that tune the parsers. The engine does the rest.

reach was extracted from [crypto-finder](https://github.com/scanoss/crypto-finder)
at commit `08570a91`, where it was the engine of its cryptography detection.

## What it does

- **Language parsers** (tree-sitter): Java, Python, Go, JavaScript/TypeScript,
  C, C++ and Rust. Each parser extracts declarations, call sites, imports and
  type facts from source.
- **Call graph**: `callgraph.Builder` parses package directories and links
  call sites to declarations, including dispatch through interfaces,
  supertypes and fluent chains. `CallGraph.Callers` is the reverse index that
  reachability walks.
- **Type resolution**: tree-sitter facts plus per-language resolvers (Java
  bytecode and JDK platform signatures, Python dependency signatures, Go,
  Node, C, C++ and Rust manifests), and return-type inference through
  library contracts.
- **Graph fragments** (`graphfrag`): the structural graph of one component,
  serialized as JSON, plus a stitcher that composes the fragments of a
  dependency closure into reachability chains, and the callgraph JSON
  renderer.
- **Reachability** (`graphwalk`): the backward traversal shared by the live
  call graph and the stitcher.
- **Entry points** (`callgraph/entrypoints`): a catalog of the functions that
  web frameworks, task queues, CLI libraries and containers call, one YAML
  file per framework, so that a chain can start at a route or handler rather
  than at a function with no callers.

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
| `skip` | Which files and directories a walk skips (defaults, `.gitignore`-style user patterns, generated and built output) |
| `javaruntime` | Java runtime selection for bytecode and platform signature indexing |
| `perf` | Opt-in wall-clock, CPU and allocation timings of build phases |

The layout is flat: every package sits at the module root, under the name it
had in crypto-finder (`internal/callgraph` became `callgraph`, `pkg/graphfrag`
became `graphfrag`). Applications import these packages, so none of them is
under `internal/`. `language`, `skip`, `javaruntime` and `perf` are support
packages the builder needs; grouping them under a `source/` directory would
add a path segment without changing what imports what, so they stay flat.
`internal/importguard` is a test-only package that keeps the module's imports
inside the standard library, reach and the third-party modules it lists.

## Injecting domain knowledge

reach ships no contracts. An application installs its knowledge base once,
before the first build:

- `contracts.SetSource(fsys fs.FS)`: one directory per ecosystem (`java`,
  `python`, `go`, `node`, `c`, `cpp`, `rust`), each holding the `*.yaml`
  contract files of that ecosystem. A contract states what a library method
  returns, its parameter roles and the type hierarchy, so the builder can type
  calls into that library.
- `contracts.SetHints(contracts.Hints{...})`: language-level hints, such as
  which package a Java wildcard import resolves a simple class name to, and
  which declared return types are vague enough for inference to refine.

A minimal example (it runs as `ExampleSetSource` in
`callgraph/contracts/example_test.go`):

```go
contracts.SetSource(fstest.MapFS{
	"python/werkzeug.yaml": &fstest.MapFile{Data: []byte(`schema_version: "2"
ecosystem: python
library:
  name: werkzeug
  coordinates: [Werkzeug]
  version_range: ">=2.3,<4.0"
contracts:
  - method: werkzeug.security.generate_password_hash
    arity: 1
    return: { type: builtins.str, confidence: high }
    role: output
hierarchy:
  builtins.str: [builtins.object]
  builtins.object: []
`)},
})

builder := callgraph.NewBuilderForEcosystem("python", callgraph.NewParserForEcosystem("python"))
graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
if err != nil {
	return err
}
// graph.Callers["werkzeug.security.generate_password_hash"] == ["app.store"]
// graph.Callers["app.store"] == ["app.signup"]
```

An application typically embeds its YAML with `go:embed` and calls
`SetSource` and `SetHints` from an `init` function of its knowledge-base
package, so that importing that package is enough to install it.

## Domains

- **Cryptography**: [crypto-finder](https://github.com/scanoss/crypto-finder)
  installs its crypto KB (`internal/cryptokb`) and reports which cryptographic
  calls the application reaches.

The engine is not specific to cryptography. It is designed to serve other
domains the same way, among them vulnerability reachability (does the
application reach the vulnerable function of a dependency) and AI usage
detection (does it reach a model or provider SDK call). Some names still carry
the crypto origin: the graph-fragment JSON keys `crypto_*`, Go identifiers such
as `CryptoCall`, and doc comments. The JSON keys and schema versions are a
stored format and stay as they are.

## Building and testing

```sh
go build ./...
go vet ./...
go test ./...
```

Go 1.26.

Many `callgraph` tests type calls through library contracts and were written
against crypto-finder's crypto KB. reach does not carry it, so those tests skip
unless `REACH_TEST_CONTRACTS` names a contracts directory:

```sh
REACH_TEST_CONTRACTS=/path/to/crypto-finder/internal/cryptokb go test ./callgraph/
```

crypto-finder runs them this way (`make test-reach`).

## Stability

reach has no tagged release yet, and its API may change between commits.
The graph-fragment and callgraph JSON formats carry their own schema versions
(`graphfrag.SchemaVersion`, `graphfrag.CallgraphSchemaVersion`) and graph
algorithm ids (`graphfrag.GraphAlgoVersion`, `graphfrag.GraphAlgoVersionPython`);
a change to what they mean bumps them.

## License

MIT. See [LICENSE](LICENSE). Third-party dependencies keep their own licenses
(`go list -m all` lists them).
