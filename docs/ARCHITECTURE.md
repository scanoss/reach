# reach architecture

reach turns source code into a typed call graph and answers "which code
reaches this function?". It does that in two settings: on one live graph
built from source, and across a dependency closure stitched from stored
per-component graphs (fragments). A domain supplies the knowledge and the
targets; reach supplies everything between.

## Data flow

```
source tree (+ dependency JARs / installed packages, type-only)
   │
   ▼
1. Parse              callgraph parsers (tree-sitter, one per ecosystem)
   │                  → FileAnalysis: declarations, call sites, imports, type facts
   ▼
2. Build graph        callgraph.Builder.BuildFromDirectories
   │                  → CallGraph: Functions, Callers (reverse index), supertypes
   ▼
3. Resolve types      TypeResolver (bytecode, JDK platform signatures, Python
   │                  dependency signatures, manifests) + contracts from the
   │                  domain's KB → call targets corrected, return types inferred
   ▼
4a. Live reachability graphwalk over CallGraph.Callers, from a target back to
   │                  roots or entry points (callgraph/entrypoints)
   ▼
4b. Fragment          graphfrag.Fragment: one component's structural graph and
   │                  its target annotations, stored as graph-fragment JSON
   ▼
5. Stitch             graphfrag.Stitch over the dependency closure's fragments
                      → Result.Chains; Result.ToCallgraphExport renders JSON
```

| Step | Entry point | Input | Output |
|---|---|---|---|
| 1 Parse | `callgraph.NewParserForEcosystem` | Source files | Per-file analyses |
| 2 Build | `Builder.BuildFromDirectories(packages, typeOnlyPackages)` | Package directories; type-only ones are indexed, not parsed | `*CallGraph` |
| 3 Resolve | `Builder.SetTypeResolver`, `callgraph.NewTypeResolverForEcosystem` | JARs, JDK, installed packages, contracts | Typed edges in the same `CallGraph` |
| 4a Walk | `graphwalk.Reach`, `Routes`, `Count` | Adjacency function + target | Reachable set, routes |
| 4b Store | `graphfrag.EncodeFragment`, `DecodeFragment`, `GraphFragmentExport.ToFragment` | `Fragment` / JSON | JSON / `Fragment` |
| 5 Stitch | `graphfrag.Stitch`, `StitchWithOptions` | Root, `DependencyGraph`, fragments | `*Result` |

Steps 2 and 3 run inside one `BuildFromDirectories` call: the builder parses,
indexes callers, then runs type resolution and the contract passes that
correct call targets.

Turning a `CallGraph` into a `Fragment` is not in reach yet. crypto-finder
does it in its own scan code. A new domain either builds `Fragment` values
itself or stays on the live graph (step 4a).

## Packages

| Package | Role | Imports |
|---|---|---|
| `callgraph` | Parsers, builder, type resolvers, tracing | `callgraph/contracts`, `callgraph/entrypoints`, `graphwalk`, `skip`, `javaruntime`, `perf` |
| `callgraph/contracts` | KB loader and validation; `SetSource`, `SetHints` | standard library, YAML |
| `callgraph/entrypoints` | Framework entry-point catalog (embedded YAML per framework) | YAML |
| `graphfrag` | Fragment model and wire schema, stitcher, callgraph renderer | `graphwalk`, `purl` |
| `graphfrag/equiv` | Semantic diff of two callgraph exports | `graphfrag` |
| `graphwalk` | Generic backward traversal (`Reach`, `Condense`, `Count`, `Routes`, `Select`) | standard library |
| `skip`, `javaruntime`, `perf`, `purl` | Support packages the builder and stitcher use | — |
| `language`, `paramcondition` | For domains: language detection of a directory; the `param[<selector>]<op><value>` condition parser. No reach package imports them | — |
| `internal/importguard` | Test-only: keeps reach's imports to the standard library, reach and an allowed module list | — |

The layout is flat on purpose: every package is importable by applications,
so none is under `internal/` except the test-only guard. `graphfrag` does not
import `callgraph`: a service that only stitches stored fragments does not
pull in the parsers.

## What a domain injects

| Injection | API | Effect | Default |
|---|---|---|---|
| Contracts KB | `contracts.SetSource(fsys fs.FS)` | One directory per ecosystem (`java`, `python`, `go`, `node`, `c`, `cpp`, `rust`) of `*.yaml` contracts: return types, parameter roles, type hierarchy | None: every ecosystem loads an empty KB |
| Hints | `contracts.SetHints(contracts.Hints{...})` | `JavaWildcardTypePackages` (which package a wildcard import resolves a simple class name to), `InferenceTriggerTypes` (declared return types vague enough to refine) | Zero hints |
| Cache root | `callgraph.NewDiskBytecodeIndexCache(root)` → `JavaBytecodeTypeResolver.SetBytecodeIndexCache`; `callgraph.NewDiskPythonSignatureIndexCache(root)` → `PythonTypeResolverChain.SetSignatureIndexCache` | Reuses JAR and Python package indexes across runs, in `root/bytecode/` and `root/python-signatures/` | No disk cache |
| Targets | The functions the domain asks about | Live: start a walk at them. Stitch: annotate them on the fragment that declares them | — |

Install the KB and hints once, before the first build. A common pattern is an
`init` in the domain's KB package that embeds the YAML (`go:embed`) and calls
both setters, so importing that package installs it. `SetSource` drops the
KBs parsed from the previous source.

Rule for engine code: no domain knowledge. A parser or resolver never
hard-codes a particular library; that knowledge arrives through the KB.

## Schema versioning

Five identifiers ship in stored and served JSON. They are independent.

| Identifier | Constant | Bumps when | Who reads it |
|---|---|---|---|
| Graph-fragment schema | `graphfrag.SchemaVersion` (`graph-fragment-1.x`) | The fragment wire format changes | `DecodeFragment`; decodes older versions |
| Callgraph schema | `graphfrag.CallgraphSchemaVersion` (inlined frames), `CallgraphInternedSchemaVersion` (interned frames) | The rendered callgraph contract changes | Consumers of `ToCallgraphExport` |
| Graph algorithm, Java and default | `graphfrag.GraphAlgoVersion` (`graph-algo-N`) | Graph construction changes the structural graph of Java (or of an ecosystem without its own id) | Fragment caches |
| Graph algorithm, Python | `graphfrag.GraphAlgoVersionPython` (`graph-algo-py-N`) | Graph construction changes the structural graph of Python | Fragment caches |
| Graph algorithm, Rust | `graphfrag.GraphAlgoVersionRust` (`graph-algo-rs-N`) | Graph construction changes the structural graph of Rust | Fragment caches |
| Graph algorithm, Node | `graphfrag.GraphAlgoVersionNode` (`graph-algo-node-N`) | Graph construction changes the structural graph of JavaScript or TypeScript | Fragment caches |

`graphfrag.GraphAlgoVersionFor(ecosystem)` returns the id for an ecosystem.
A fragment carries its id in `scan_metadata.graph_algo_version`.

### Why outputs must stay stable

| Consumer | What breaks if a graph changes without a bump |
|---|---|
| Stored fragments (a mining service keys cached structural graphs on the graph algorithm id) | Old graphs are served as if current; stitched answers mix construction versions |
| Re-detection on a stored graph (crypto-finder `annotate`) | Detection runs on a graph that no longer matches what a fresh build produces |
| Callgraph JSON consumers | Keys or meaning change under an unchanged schema version |

The converse also costs: bumping an id re-mines every stored graph of that
ecosystem. Bump only the ecosystem whose graphs changed.

### The guard

reach defines the ids; the test that enforces them lives in crypto-finder
(`internal/graphalgoguard`, `TestGraphAlgoVersionGuard`), because it drives
crypto-finder's scan over a fixed corpus per ecosystem. It hashes the
structural part of each fragment and fails when a hash changes while the
ecosystem's id stays the same. An engine change that alters graphs therefore
lands as: bump the id here, tag reach, bump reach in crypto-finder, refresh
the guard's golden there.

Each bump is documented in the comment above its constant
(`graphfrag/graph_algo.go`, `graphfrag/export.go`).

## Next step

To build a new domain on reach, read [NEW_DOMAIN.md](NEW_DOMAIN.md).
