// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"sync"

	"github.com/scanoss/reach/callgraph/entrypoints"
)

// Catalog languages, as the entry-point catalog directories name them.
const (
	entryLanguageJava   = "java"
	entryLanguageNode   = "node"
	entryLanguagePython = "python"
	entryLanguageGo     = "go"
	entryLanguageRust   = "rust"
	entryLanguageCSharp = "csharp"
)

// entryCatalog is the framework entry-point catalog built into the binary
// (callgraph/entrypoints). It is validated by that package's tests,
// so a failure to load is a build defect, not an input error.
var entryCatalog = sync.OnceValue(func() *entrypoints.Catalog {
	catalog, err := entrypoints.LoadEmbedded()
	if err != nil {
		panic(fmt.Sprintf("callgraph: embedded entry-point catalog: %v", err))
	}
	return catalog
})

// EntryMark is what makes a declaration an entry point: its root kind and,
// when a catalog entry matched, that entry's ID (entrypoints.Entry.ID).
type EntryMark struct {
	Kind RootKind
	Rule string
}

// catalogEntryMark is the mark a matched catalog entry gives.
func catalogEntryMark(entry *entrypoints.Entry) EntryMark {
	return EntryMark{Kind: RootKind(entry.RootKind), Rule: entry.ID}
}
