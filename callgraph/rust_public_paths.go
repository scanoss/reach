// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"maps"
	"slices"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// rustPublicTypePaths reads a file's `pub use` items and records in
// facts.publicTypePaths, for each type one of them re-exports, its public path
// mapped to the path it names: `pub use self::signing_key::SigningKey;` in
// rsa's src/pkcs1v15.rs gives
// "rsa::pkcs1v15::SigningKey" -> "rsa::pkcs1v15::signing_key::SigningKey".
// Only a plain `pub` re-export makes a path public; `pub(crate) use` and a
// private `use` bind a name a consumer can never import.
func (p *RustParser) rustPublicTypePaths(scope *sitter.Node, src []byte, modulePath string, facts *rustFileFacts) {
	if scope == nil {
		return
	}
	for i := 0; i < int(scope.NamedChildCount()); i++ {
		child := scope.NamedChild(i)
		switch child.Type() {
		case rustNodeModItem:
			if !p.includeTests && rustModuleIsTestOnly(child, src) {
				continue
			}
			if name := nodeFieldText(child, "name", src); name != "" {
				p.rustPublicTypePaths(child.ChildByFieldName("body"), src, rustQualifyFactKey(modulePath, name), facts)
			}
		case rustNodeUseDeclaration:
			if rustItemVisibility(child, src) == "pub" {
				p.recordRustPublicUse(child, src, modulePath, facts)
			}
		case rustNodeTypeItem:
			if rustItemVisibility(child, src) == "pub" {
				p.recordRustPublicTypeAlias(child, src, modulePath, facts)
			}
		}
	}
}

// recordRustPublicUse records the types one `pub use` item re-exports from
// modulePath.
func (p *RustParser) recordRustPublicUse(useDecl *sitter.Node, src []byte, modulePath string, facts *rustFileFacts) {
	staging := &FileAnalysis{
		PackagePath:   modulePath,
		Imports:       make(map[string]string),
		ImportAliases: make(map[string]string),
		// The file's own facts, so `pub use keys::PublicKeyParts;` beside
		// `mod keys;` resolves to that module, not a crate.
		rustFacts: facts,
	}
	p.processUseDecl(useDecl, src, staging, "")
	for name, pkg := range staging.Imports {
		if pkg == "" {
			continue
		}
		public, target := rustQualifyFactKey(modulePath, name), rustQualifyFactKey(pkg, name)
		if rustIsTypeCase(name) {
			facts.publicTypePaths[public] = target
		}
		facts.publicPaths[public] = target
	}
	for alias, target := range staging.ImportAliases {
		leaf := target
		if i := strings.LastIndex(target, "::"); i >= 0 {
			leaf = target[i+2:]
		}
		if rustIsTypeCase(alias) && rustIsTypeCase(leaf) {
			facts.publicTypePaths[rustQualifyFactKey(modulePath, alias)] = target
		}
		if target != "" {
			facts.publicPaths[rustQualifyFactKey(modulePath, alias)] = target
		}
	}
	for _, glob := range staging.WildcardImports {
		if !slices.Contains(facts.publicGlobs[modulePath], glob) {
			facts.publicGlobs[modulePath] = append(facts.publicGlobs[modulePath], glob)
		}
	}
}

// recordRustPublicTypeAlias records the path a `pub type A = X<..>;` item
// gives the type it names: `pub type MlKem768 = kem::Kem<MlKem768Params>;` in
// ml-kem's lib.rs makes "ml_kem::MlKem768" name "ml_kem::kem::Kem", whose
// methods a consumer calls as `MlKem768::generate(..)`. A bare target is a
// type of the alias's own module. Only publicPaths: the alias is not a
// re-export of the type, so the type keeps its public type paths.
func (p *RustParser) recordRustPublicTypeAlias(item *sitter.Node, src []byte, modulePath string, facts *rustFileFacts) {
	staging := &FileAnalysis{
		PackagePath:   modulePath,
		Imports:       make(map[string]string),
		ImportAliases: make(map[string]string),
		rustFacts:     facts,
	}
	p.recordRustTypeAlias(item, src, staging)
	for alias, target := range staging.ImportAliases {
		if !strings.Contains(target, "::") {
			target = rustQualifyFactKey(modulePath, target)
		}
		facts.publicPaths[rustQualifyFactKey(modulePath, alias)] = target
	}
}

// rustItemVisibility returns an item's visibility modifier as written, or ""
// for a private item.
func rustItemVisibility(item *sitter.Node, src []byte) string {
	for i := 0; i < int(item.NamedChildCount()); i++ {
		if child := item.NamedChild(i); child.Type() == "visibility_modifier" {
			return strings.Join(strings.Fields(child.Content(src)), "")
		}
	}
	return ""
}

// mergePublicTypePaths folds one file's public re-exports into the crate's,
// dropping a public path two files point at different types.
func (f *rustFileFacts) mergePublicTypePaths(other *rustFileFacts) {
	for public, target := range other.publicTypePaths {
		if f.conflicting["public:"+public] {
			continue
		}
		if existing, seen := f.publicTypePaths[public]; seen && existing != target {
			delete(f.publicTypePaths, public)
			f.conflicting["public:"+public] = true
			continue
		}
		f.publicTypePaths[public] = target
	}
	for public, target := range other.publicPaths {
		if f.conflicting["publicpath:"+public] {
			continue
		}
		if existing, seen := f.publicPaths[public]; seen && existing != target {
			delete(f.publicPaths, public)
			f.conflicting["publicpath:"+public] = true
			continue
		}
		f.publicPaths[public] = target
	}
	for module, globs := range other.publicGlobs {
		for _, glob := range globs {
			if !slices.Contains(f.publicGlobs[module], glob) {
				f.publicGlobs[module] = append(f.publicGlobs[module], glob)
			}
		}
	}
}

// resolveRustPublicTypeChains follows each public path through the re-exports
// it names to the path that declares the type: lib.rs's
// `pub use crate::pkcs1v15::SigningKey;` would otherwise name another
// re-export, not the `signing_key` module the declaration lives in.
func resolveRustPublicTypeChains(facts *rustFileFacts) {
	const maxHops = 8
	for public, target := range facts.publicTypePaths {
		seen := map[string]bool{public: true}
		for hop := 0; hop < maxHops; hop++ {
			next, ok := facts.publicTypePaths[target]
			if !ok || seen[target] {
				break
			}
			seen[target] = true
			target = next
		}
		facts.publicTypePaths[public] = target
	}
}

// PublicTypePaths returns, for every type a parsed crate re-exports, the
// declaring path mapped to the sorted public paths it is re-exported under.
// A declaration keyed by the module that defines it can then also be found by
// the path a consumer imports, which is the path a contract names.
func (p *RustParser) PublicTypePaths() map[string][]string {
	index := p.crateIndex
	if index == nil {
		return nil
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	out := make(map[string][]string)
	for _, facts := range index.crates {
		if facts == nil {
			continue
		}
		for public, declaring := range facts.publicTypePaths {
			if public != declaring {
				out[declaring] = append(out[declaring], public)
			}
		}
	}
	for declaring, public := range out {
		slices.Sort(public)
		out[declaring] = slices.Compact(public)
	}
	return out
}

// PublicPaths returns what the parsed crates' plain `pub use` items
// re-export: each public path mapped to the path it names, as written, and
// each module mapped to the paths its glob re-exports name.
func (p *RustParser) PublicPaths() (paths map[string]string, globs map[string][]string) {
	index := p.crateIndex
	if index == nil {
		return nil, nil
	}
	index.mu.Lock()
	defer index.mu.Unlock()
	paths, globs = make(map[string]string), make(map[string][]string)
	for _, facts := range index.crates {
		if facts == nil {
			continue
		}
		maps.Copy(paths, facts.publicPaths)
		for module, targets := range facts.publicGlobs {
			globs[module] = append(globs[module], targets...)
		}
	}
	return paths, globs
}

// rustStandardCrates are the crates of the standard library: their source is
// never in a closure, so a re-export of one of their items joins nothing.
var rustStandardCrates = map[string]bool{"std": true, "core": true, "alloc": true, "proc_macro": true, "test": true}

// rustExports maps each public path of the graph's Rust declarations, in
// function-key form, to the declaration (CallGraph.RustExports): a module at
// its own path ("ring.hmac" -> "ring::hmac"), and every name a `pub use`
// item re-exports at the path it gives the name, followed through the other
// re-exports and globs to the module that declares it. What a path names is
// read from the graph: a module some declaration lives in, a type some method
// belongs to, else a type by its case or a function. A path that names
// nothing the graph declares or re-exports is left out.
func rustExports(functions map[string]*FunctionDecl, paths map[string]string, globs map[string][]string) map[string]string {
	modules, types := make(map[string]bool), make(map[string]bool)
	members := make(map[string]map[string]bool) // module -> names it declares
	addMember := func(module, name string) {
		if members[module] == nil {
			members[module] = make(map[string]bool)
		}
		members[module][name] = true
	}
	for _, fn := range functions {
		pkg := fn.ID.Package
		if pkg == "" || strings.ContainsAny(pkg, "<>( ") {
			continue
		}
		for m := pkg; ; {
			modules[m] = true
			i := strings.LastIndex(m, "::")
			if i < 0 {
				break
			}
			addMember(m[:i], m[i+2:])
			m = m[:i]
		}
		switch {
		case strings.HasPrefix(fn.ID.Name, "<"):
			// A pseudo function (`<varinit:..>`) names nothing a caller writes.
		case fn.ID.Type != "":
			types[pkg+"::"+fn.ID.Type] = true
			addMember(pkg, fn.ID.Type)
		case fn.ID.Name != "":
			addMember(pkg, fn.ID.Name)
		}
	}
	if len(modules) == 0 {
		return nil
	}
	all := maps.Clone(paths)
	resolve := func(path string) string {
		seen := map[string]bool{path: true}
		for hop := 0; hop < 8; hop++ {
			next, ok := all[path]
			if !ok || seen[next] {
				break
			}
			seen[next] = true
			path = next
		}
		return path
	}
	// A glob re-export makes every name its target declares or re-exports
	// public in the module that writes it, and so does a re-exported module
	// at its public path (`pub use native::scrypt;` makes
	// `age::scrypt::Identity` public). Globs of globs, and modules re-exported
	// inside re-exported modules, need a few rounds.
	globs = maps.Clone(globs)
	for round := 0; round < 4; round++ {
		for public := range all {
			if target := resolve(public); target != public && modules[target] && !slices.Contains(globs[public], target) {
				globs[public] = append(globs[public], target)
			}
		}
		added := false
		for module, targets := range globs {
			for _, target := range targets {
				names := maps.Clone(members[target])
				prefix := target + "::"
				for public := range all {
					if rest, ok := strings.CutPrefix(public, prefix); ok && !strings.Contains(rest, "::") {
						if names == nil {
							names = make(map[string]bool)
						}
						names[rest] = true
					}
				}
				for name := range names {
					public := module + "::" + name
					if _, seen := all[public]; !seen && !members[module][name] {
						all[public] = prefix + name
						added = true
					}
				}
			}
		}
		if !added {
			break
		}
	}
	crates := make(map[string]bool)
	for module := range modules {
		root, _, _ := strings.Cut(module, "::")
		crates[root] = true
	}
	declaration := func(path string) (string, bool) {
		if modules[path] {
			return path, true
		}
		i := strings.LastIndex(path, "::")
		if i <= 0 {
			return "", false
		}
		owner, name := path[:i], path[i+2:]
		if !modules[owner] {
			// A re-export of another crate's item (`pub use rand_core::OsRng;`
			// in rand) names it as that crate keys it; the stitch finds the
			// declaration in the closure. What the other crate names a
			// lowercase item is unknown here, so it is read as a function.
			root, _, _ := strings.Cut(owner, "::")
			if crates[root] || rustStandardCrates[root] {
				return "", false
			}
			if rustIsTypeCase(name) {
				return owner + ".(" + name + ")", true
			}
			return owner + "." + name, true
		}
		if types[path] || rustIsTypeCase(name) {
			return owner + ".(" + name + ")", true
		}
		return owner + "." + name, true
	}
	out := make(map[string]string)
	for module := range modules {
		if i := strings.LastIndex(module, "::"); i > 0 {
			out[module[:i]+"."+module[i+2:]] = module
		}
	}
	for public := range all {
		i := strings.LastIndex(public, "::")
		if i <= 0 {
			continue
		}
		if decl, ok := declaration(resolve(public)); ok {
			out[public[:i]+"."+public[i+2:]] = decl
		}
	}
	return out
}
