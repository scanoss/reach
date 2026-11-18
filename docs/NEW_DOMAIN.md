# Building a new domain on reach

A domain is an application that asks reach "does this code reach that
function?" for its own reasons: cryptography (crypto-finder), vulnerability
reachability (does the application reach the vulnerable function of a
dependency), AI usage detection (does it reach a model or provider SDK
call). The domain supplies knowledge and targets; reach returns call graphs,
reachable sets and call chains.

## Quick path

1. **Install knowledge** (optional for untyped questions, needed for typed
   calls into libraries): `contracts.SetSource(fsys)` and, if useful,
   `contracts.SetHints(...)`.
2. **Build** the application's call graph:
   `callgraph.NewBuilderForEcosystem(eco, callgraph.NewParserForEcosystem(eco))`,
   then `BuildFromDirectories(packages, typeOnlyPackages)`.
3. **Ask**: walk `graph.Callers` back from each target, or use `graphwalk`
   for depth, routes and counts.
4. **Scale out** (optional): store one `graphfrag.Fragment` per dependency
   version, annotate the targets on the fragments that declare them, and
   `graphfrag.Stitch` the closure.

Both paths have runnable examples:

| Example | File | Shows |
|---|---|---|
| `ExampleSetSource` | [`callgraph/contracts/example_test.go`](../callgraph/contracts/example_test.go) | Install a one-library KB, build a Python graph, walk back from a library call |
| `ExampleStitch` | [`graphfrag/example_test.go`](../graphfrag/example_test.go) | Two stored fragments (application, library), a vulnerable function as target, the stitched chain |

## What the domain supplies

| Input | How | When you need it |
|---|---|---|
| Library contracts | `contracts.SetSource(fs.FS)`: `<ecosystem>/*.yaml` (`java`, `python`, `go`, `node`, `c`, `cpp`, `rust`) | When the target is reached through library objects whose types the parser cannot see (a method on a returned object) |
| Hints | `contracts.SetHints(contracts.Hints{JavaWildcardTypePackages, InferenceTriggerTypes})` | Java code with wildcard imports; vague declared return types |
| Dependency types | `typeOnlyPackages` of `BuildFromDirectories`, plus a type resolver (`Builder.SetTypeResolver`, `callgraph.NewTypeResolverForEcosystem`) | Calls into dependencies must resolve to exact targets |
| Cache root | `callgraph.NewDiskBytecodeIndexCache(root)`, `callgraph.NewDiskPythonSignatureIndexCache(root)` | Repeated runs over the same JARs or packages |
| Targets | Function keys the domain chooses | Always |
| Entry points | `callgraph/entrypoints` (embedded catalog) | Chains should start at a route, handler or `main`, not at any function nothing calls |

A contract file, minimally (from `ExampleSetSource`):

```yaml
schema_version: "2"
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
```

One file is one library version range. The loader merges every file of an
ecosystem and fails on conflicting returns or hierarchies.

## What the domain gets back

| Output | Type | Meaning |
|---|---|---|
| Call graph | `*callgraph.CallGraph` | `Functions` (declarations by key), `Callers` (callee key → caller keys), type hierarchy |
| Reachable set | `graphwalk.Reachable[T]` | Every node that reaches a target, its distance, one shortest route (`Route`) |
| Routes | `graphwalk.Routes`, `Count` | Up to a budget of routes, and how many exist |
| Stitched chains | `graphfrag.Result.Chains` | Per target: frames from a root of the closure to the target, with components and call sites |
| Callgraph JSON | `Result.ToCallgraphExport(root, meta)` | The rendered, versioned export (`graphfrag.CallgraphSchemaVersion`) |
| Suppressed edges | `Result.Suppressed` | Edges the stitch refused to follow (uncertain dispatch): why a target is not reachable |

## Worked example: vulnerability reachability

Question: does `com.acme:app` reach `org.example.Codec.decode` in
`org.example:lib@2.3.1`, a function an advisory names?

```go
app := graphfrag.ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0.0"}
lib := graphfrag.ComponentKey{Purl: "pkg:maven/org.example/lib", Version: "2.3.1"}

appFragment, _ := graphfrag.DecodeFragment(app, appJSON) // stored per component
libFragment, _ := graphfrag.DecodeFragment(lib, libJSON) // target annotated on it

result, err := graphfrag.Stitch(app,
	graphfrag.DependencyGraph{app: {lib}, lib: nil},
	map[graphfrag.ComponentKey]graphfrag.Fragment{app: appFragment, lib: libFragment})
if err != nil {
	return err // *graphfrag.ErrMissingFragment names closure members without a fragment
}
for _, chain := range result.Chains {
	// chain.FindingID is the target's id; chain.Frames run app → lib target.
}
```

The full, compiling version with both fragments inline is `ExampleStitch`;
`go test ./graphfrag -run ExampleStitch` runs it. It prints:

```
vuln-1
  pkg:maven/com.acme/app@1.0.0 com.acme.(App).main#1
  pkg:maven/org.example/lib@2.3.1 org.example.(Parser).parse#1
  pkg:maven/org.example/lib@2.3.1 org.example.(Codec).decode#1
```

The target is attached as a fragment annotation (`crypto_annotations` in the
JSON, `Fragment.CryptoOperations` in Go). The names are crypto-era; the
stitcher treats an annotation as "a target in this function", whatever the
domain.

For AI usage detection the shape is the same: the targets are the SDK calls
that send a prompt or load a model, and contracts type the client objects
(`client.chat.completions.create` on the object a constructor returns).

## Rules and limits

| Topic | What to know |
|---|---|
| Building fragments from a `CallGraph` | Not in reach yet. crypto-finder builds them in its scan code. Build `graphfrag.Fragment` (or `GraphFragmentExport`) yourself, or stay on the live graph. Copy `CallGraph.PythonExports` or `CallGraph.NodePackageExports` into the fragment's `exports`: without it a stitch cannot join a client's call spelled with a dependency's public names (`jwt.encode`, `acme-sign.sign`) to the dependency's declaration. |
| Global state | `SetSource` and `SetHints` are process-wide. Install once before the first build; two domains in one process share them. |
| Stored format | Fragments and callgraph JSON keep their keys (`crypto_*` included) and carry schema and graph algorithm ids. Key your caches on `GraphAlgoVersionFor(ecosystem)`. See [ARCHITECTURE.md](ARCHITECTURE.md#schema-versioning). |
| Fail-closed stitch | The stitcher does not follow name-only or ambiguous dispatch by default; a target behind such an edge is not reached and the edge is in `Result.Suppressed`. `StitchOptions` changes the policy. |
| Static analysis | Reflection, calls through stored function values, and calls on values the parser cannot type are not followed precisely; a domain reports them as unknown, not as unreachable. |

## Checklist

- [ ] The KB is installed before the first `BuildFromDirectories`.
- [ ] Dependencies are passed as `typeOnlyPackages` with a type resolver, so calls into them are typed.
- [ ] Every fragment edge carries a `resolution` (`exact`, `interface_dispatch`, `name_only`); an edge without one is never traversed.
- [ ] Targets use the graph's function keys (`pkg.(Type).method#arity` in fragments).
- [ ] Stored fragments are keyed by component, version and graph algorithm id.
- [ ] Unreached targets are checked against `Result.Suppressed` before being reported unreachable.

## Next step

Read [ARCHITECTURE.md](ARCHITECTURE.md) for the data flow and versioning
rules, then copy `ExampleStitch` or `ExampleSetSource` as a starting point.
