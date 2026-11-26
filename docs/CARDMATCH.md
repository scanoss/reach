# cardmatch: the cards matcher

`cardmatch` matches a detection ruleset against the call sites of a graph
fragment (`graphfrag`) and returns findings with the metadata of the rules
that matched. The ruleset is data the application supplies. reach ships no
rules and knows no domain: crypto-finder runs it with its cryptography
ruleset, and another domain can run it with its own.

It moved here from crypto-finder (`internal/cardmatch`) in 2026-11, with its
JavaScript pattern sub-package (`cardmatch/internal/jspat`) and the parse
memo (`parsememo`).

## Quick path

```go
assets, err := cardmatch.Load("", "rules/cards", "", cardmatch.Options{
	MetadataKey: "usage", // the rule metadata block findings carry
})
if err != nil { ... }
var frag cardmatch.FragmentJSON // a graph fragment, as graphfrag exports it
if err := json.Unmarshal(fragmentJSON, &frag); err != nil { ... }
findings, sites, err := assets.Match(&frag)
for _, f := range findings {
	fmt.Println(f.RuleID, f.File, f.Line, f.MetadataFields())
}
```

## Inputs

| Input | Where it comes from |
|---|---|
| Card files | A directory of v3 card files (`format: scanoss-cards/3`): a `rules:` map (id → `severity`, `message`, `purl`, the metadata block, `conditioned`, `pending`) and `cards:` (site cards, the compiled index, and hand cards). When the directory holds v3 files they are the whole ruleset. |
| Rule YAML | OpenGrep-style rule files under `rulesDir`, compiled into the index (`CompileIndex`) when there is no v3 card file and no compiled index. |
| Fragment | The graph fragment of the code to scan (`FragmentJSON`, the `graphfrag` wire format). |

## API

| Call | What it does |
|---|---|
| `Load(indexPath, cardsDir, rulesDir, Options)` | Loads the ruleset once: v3 card files, or a compiled index (`indexPath`, or compiled from `rulesDir`) plus hand cards. |
| `(*Assets).Match(frag)` | The findings on one fragment and the number of call sites read. A card or rule the matcher cannot evaluate is an error naming it, never a panic. |
| `(*Assets).Explain(frag, rule, file, line)` | Why one rule did or did not match the call sites of one line. |
| `CompileIndex`, `ExportRules`, `VerifyV3` | Compile OpenGrep-style rules into the index, export each rule as site cards, and check v3 card files against the rules they replace. |
| `SaveMemo()` | Writes the card files this process parsed to the parse memo. |
| `(*Finding).MetadataFields()` | A finding's filled metadata as a map. |

## Options

| Field | Default | Effect |
|---|---|---|
| `MetadataKey` | `"crypto"` (`DefaultMetadataKey`) | The rule metadata block a finding carries: `metadata.<key>` of a rule YAML, `<key>` of a v3 rules entry. |
| `ExtraRuleKeys` | none | More keys a v3 rules entry may hold. Any other key is an error. |
| `LanguageOf` | `CardsDirLanguage` (`cards/<language>/...`) | The language of a card file. A card file holds cards of its language's rules only, a v3 rule is a Rust rule when its file is Rust's, and parsed files are memoised per language. |
| `ConstantComparisons` | report a constant in a comparison only when the compared value can be it | `ComparisonsAll` reports every one, as OpenGrep does; `ComparisonsOff` none. |
| `PyMembership` | as a comparison | How a Python constant in an `in` test is reported; `ComparisonsAll` for debugging. |

## The parse memo

`parsememo` keeps what a process parsed from a file, by content, for the
next process: a mining run starts one process per component against the
same cards. It is off until `parsememo.Enable(dir)`. Enable it only when the
ruleset is already on disk in clear: the memo stores the parse in clear.
Each memo file is bound to the binary that wrote it.

## Limits

- One load or match runs at a time in a process. The matcher memoises regex
  results and per-pattern tests in package-level maps behind one mutex, so
  concurrent `Match` calls, on any `Assets`, serialize. A server that embeds
  the matcher gets no parallelism from it until that state moves onto
  `Assets`.
- The matcher reproduces the reference (Python) matcher it was ported from,
  branch for branch. Its equivalence suites (`CARDMATCH_PARITY_*`,
  `CARDMATCH_E2E_*`) run only against a real ruleset outside this
  repository and skip here.

## Ruleset content

reach is public. Tests build small invented rules (acme, example.com). The
ruleset guard (`internal/rulesetguard`, CI step `Ruleset content guard`)
fails a pull request that adds a token shaped like a rule id that
`allowed_ids.txt` does not list as invented, a YAML or card file outside
`testdata/` whose rules carry a CycloneDX crypto block, or a rule or card
file under `testdata/` without the line `# rulesetguard: invented`. It knows
nothing of any private ruleset: it catches a pasted rule file by its shape.
