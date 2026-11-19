// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// node_package_exports.go publishes, for each Node package of a build, the
// keys a caller spells through the package's specifier next to the functions
// they name. An application keys `require('acme-sign').sign(..)` and `import
// { sign } from 'acme-sign'` as acme-sign.sign, while acme-sign's own graph
// declares the function in its entry module, acme-sign/index.sign. A graph
// built with both links the call (linkNodePackageCalls); a stitch of two
// stored graphs joins it through this table, which a dependency's fragment
// carries as its `exports`, as a Python one does.

const (
	// nodeExportMemberCap bounds the members listed below one export.
	nodeExportMemberCap = 256
	// nodePublicModuleCap bounds the modules one package publishes through
	// wildcard exports and directory indexes.
	nodePublicModuleCap = 1024
)

// nodePublicModule is a module a specifier loads: spec as a caller writes it
// (acme-sign, acme-sign/lib/x, @acme/sign) and the file it resolves to.
type nodePublicModule struct {
	spec, file string
}

// recordNodePackageExports fills graph.NodePackageExports: for each package
// of the build, the key of every call through one of its specifiers that
// names a function the package declares under another key.
func (b *Builder) recordNodePackageExports(graph *CallGraph) {
	if b.ecosystem != ecosystemNode || len(b.nodePackageDirs) == 0 {
		return
	}
	r := newNodePackageCalls(graph, b.nodePackageDirs)
	defer r.shapes.Close()
	pkgs := make([]string, 0, len(b.nodePackageDirs))
	for pkg := range b.nodePackageDirs {
		if !nodeBuiltinModules[pkg] {
			pkgs = append(pkgs, pkg)
		}
	}
	sort.Strings(pkgs)
	out := make(map[string]string)
	conflict := make(map[string]bool)
	for _, pkg := range pkgs {
		for _, module := range nodePublicModules(pkg, b.nodePackageDirs[pkg], b.nodeRelativeLoaders) {
			r.publishModule(module, out, conflict)
		}
	}
	for public := range conflict {
		delete(out, public)
	}
	for _, pkg := range pkgs {
		count := 0
		for _, module := range nodePublicModules(pkg, b.nodePackageDirs[pkg], b.nodeRelativeLoaders) {
			names := nodeExportedNames(module.file, map[string]bool{}, 0)
			names[nodeDefaultExport] = true
			sorted := make([]string, 0, len(names))
			for name := range names {
				sorted = append(sorted, name)
			}
			sort.Strings(sorted)
			r.publishValues(module, sorted, out, conflict, &count)
		}
	}
	if len(out) > 0 {
		graph.NodePackageExports = out
	}
}

// publishModule adds the exports of one public module to out: each name it
// exports, its default export, and the members of an export whose members
// are known statically (`module.exports = { hotp }`, hotp.gen). A public key
// two declarations claim is marked in conflict and left out.
func (r *nodePackageCalls) publishModule(module nodePublicModule, out map[string]string, conflict map[string]bool) {
	names := nodeExportedNames(module.file, map[string]bool{}, 0)
	names[nodeDefaultExport] = true
	sorted := make([]string, 0, len(names))
	for name := range names {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	add := func(path ...string) {
		file, line, col, ok := r.shapes.definitionStart(module.file, path[0], path[1:])
		if !ok {
			return
		}
		// The definition must be a function's own node: an object on the
		// line of the function it holds is not that function.
		key := r.starts[nodeDeclStart{file: filepath.Clean(file), line: line, col: col}]
		public := module.spec + "." + strings.Join(path, ".")
		if path[0] == nodeDefaultExport && len(path) > 1 {
			// A caller reads the default import's members as the module's:
			// `import acme from 'acme'; acme.sign()` calls acme.sign.
			public = module.spec + "." + strings.Join(path[1:], ".")
		}
		if key == "" || key == public {
			return
		}
		if prev, taken := out[public]; taken && prev != key {
			conflict[public] = true
			return
		}
		out[public] = key
	}
	for _, name := range sorted {
		add(name)
		members, ok := r.shapes.ExportMembers(module.file, name)
		if !ok || len(members) > nodeExportMemberCap {
			continue
		}
		memberNames := make([]string, 0, len(members))
		for member := range members {
			memberNames = append(memberNames, member)
		}
		sort.Strings(memberNames)
		for _, member := range memberNames {
			add(name, member)
		}
	}
}

// nodeExportedNames lists the names file exports, those it re-exports
// wholesale from a relative module (`export * from './x'`) included.
func nodeExportedNames(file string, seen map[string]bool, depth int) map[string]bool {
	names := make(map[string]bool)
	if seen[file] || depth > nodeShapeDepth {
		return names
	}
	seen[file] = true
	exports, err := NodeModuleExports(file)
	if err != nil {
		return names
	}
	for name := range exports.Lines {
		names[name] = true
	}
	for _, from := range exports.StarFrom {
		if !isNodeRelativeSpecifier(from) {
			continue
		}
		target := nodeSourceFile(filepath.Dir(file), from)
		if target == "" {
			continue
		}
		for name := range nodeExportedNames(target, seen, depth+1) {
			if name != nodeDefaultExport {
				names[name] = true
			}
		}
	}
	return names
}

// nodePublicModules lists the modules a caller can load from the package in
// dir by a specifier: with package.json "exports", the subpaths it lists
// (a pattern such as "./*" expanded over the files it matches); without, the
// package itself through "main" (else index), each directory with an index
// module, and each file that re-exports or requires a relative module at its
// top level (loaders lists them). Any other file a caller names by its own
// path needs no entry: what it exports it declares, keyed by that path
// already.
func nodePublicModules(pkg, dir string, loaders map[string]bool) []nodePublicModule {
	var manifest struct {
		Exports json.RawMessage `json:"exports"`
	}
	if data, err := os.ReadFile(filepath.Join(dir, "package.json")); err == nil && json.Unmarshal(data, &manifest) != nil {
		return nil // Node refuses a package whose manifest does not parse
	}
	var out []nodePublicModule
	if len(manifest.Exports) > 0 && string(manifest.Exports) != nodeLiteralNull {
		var subpaths map[string]json.RawMessage
		if json.Unmarshal(manifest.Exports, &subpaths) != nil || !nodeHasSubpathKeys(subpaths) {
			if file := nodePackageEntry(dir, "."); file != "" {
				out = append(out, nodePublicModule{spec: pkg, file: file})
			}
			return out
		}
		keys := make([]string, 0, len(subpaths))
		for key := range subpaths {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			target, ok := nodeConditionTarget(subpaths[key])
			if !ok {
				continue
			}
			if strings.Contains(key, "*") {
				out = append(out, nodeWildcardModules(pkg, dir, key, target, nodePublicModuleCap-len(out))...)
				continue
			}
			if file := nodeSourceFile(dir, target); file != "" && nodeSourceFileName(file) {
				out = append(out, nodePublicModule{spec: pkg + strings.TrimPrefix(key, "."), file: file})
			}
		}
		return out
	}
	if file := nodePackageEntry(dir, "."); file != "" {
		out = append(out, nodePublicModule{spec: pkg, file: file})
	}
	out = append(out, nodeDirectoryIndexes(pkg, dir)...)
	return append(out, nodeReExportingFiles(pkg, dir, loaders, nodePublicModuleCap-len(out))...)
}

// nodeReExportingFiles lists the package's files among loaders, other than
// index modules, those of nested packages and the files the build did not
// parse: a caller's `require('acme/lib/x').f` may reach a function another
// file declares when lib/x.js does `module.exports = require('./impl')`.
func nodeReExportingFiles(pkg, dir string, loaders map[string]bool, limit int) []nodePublicModule {
	prefix := filepath.Clean(dir) + string(filepath.Separator)
	files := make([]string, 0, len(loaders))
	for file := range loaders {
		if strings.HasPrefix(file, prefix) {
			files = append(files, file)
		}
	}
	sort.Strings(files)
	var out []nodePublicModule
	for _, file := range files {
		if len(out) >= limit {
			break
		}
		rel := strings.TrimPrefix(file, prefix)
		if strings.HasPrefix(filepath.Base(rel), "index.") || !nodeSourceFileName(rel) ||
			slices.Contains(strings.Split(filepath.ToSlash(rel), "/"), "node_modules") {
			continue
		}
		rel = filepath.ToSlash(strings.TrimSuffix(rel, filepath.Ext(rel)))
		out = append(out, nodePublicModule{spec: pkg + "/" + rel, file: file})
	}
	return out
}

// nodeLoadsRelativeModule reports whether a file requires or re-exports a
// relative module at its top level.
func nodeLoadsRelativeModule(imports []NodeImport) bool {
	for _, imp := range imports {
		if !imp.Local && (imp.Kind == NodeImportRequire || imp.Kind == NodeImportExport) && isNodeRelativeSpecifier(imp.Module) {
			return true
		}
	}
	return false
}

// nodeHasSubpathKeys reports whether an "exports" object maps subpaths
// ("." and "./x") rather than conditions.
func nodeHasSubpathKeys(object map[string]json.RawMessage) bool {
	for key := range object {
		if strings.HasPrefix(key, ".") {
			return true
		}
	}
	return false
}

// nodeSourceFileName reports whether file has a JavaScript or TypeScript
// extension, so a subpath to package.json or a stylesheet is not read.
func nodeSourceFileName(file string) bool {
	ext := filepath.Ext(file)
	for _, candidate := range nodeSourceExtensions {
		if strings.EqualFold(ext, candidate) {
			return true
		}
	}
	return false
}

// nodeWildcardModules expands a subpath pattern ("./*" -> "./dist/*.js")
// over the package's files that match its target, at most limit of them.
func nodeWildcardModules(pkg, dir, key, target string, limit int) []nodePublicModule {
	if strings.Count(key, "*") != 1 || strings.Count(target, "*") != 1 || limit <= 0 {
		return nil
	}
	prefix, suffix, _ := strings.Cut(strings.TrimPrefix(target, "./"), "*")
	var out []nodePublicModule
	nodeWalkPackageFiles(dir, func(rel string) bool {
		if !strings.HasPrefix(rel, prefix) || !strings.HasSuffix(rel, suffix) || len(rel) < len(prefix)+len(suffix) {
			return true
		}
		file := filepath.Join(dir, filepath.FromSlash(rel))
		if !nodeSourceFileName(file) {
			return true
		}
		star := rel[len(prefix) : len(rel)-len(suffix)]
		out = append(out, nodePublicModule{spec: pkg + strings.TrimPrefix(strings.Replace(key, "*", star, 1), "."), file: file})
		return len(out) < limit
	})
	return out
}

// nodeDirectoryIndexes lists each directory of the package below its root
// that holds an index module: `require('acme/lib')` loads lib/index.js, which
// is keyed acme/lib/index.
func nodeDirectoryIndexes(pkg, dir string) []nodePublicModule {
	var out []nodePublicModule
	seen := make(map[string]bool)
	nodeWalkPackageFiles(dir, func(rel string) bool {
		sub := filepath.ToSlash(filepath.Dir(filepath.FromSlash(rel)))
		if sub == "." || seen[sub] || !strings.HasPrefix(filepath.Base(rel), "index.") {
			return true
		}
		// A file of the directory's name wins over its index, as in Node's
		// resolver: then the specifier names that file, keyed as written.
		if file := nodeSourceFile(dir, sub); file != "" && strings.HasPrefix(filepath.Base(file), "index.") && filepath.Dir(file) == filepath.Join(dir, filepath.FromSlash(sub)) {
			seen[sub] = true
			out = append(out, nodePublicModule{spec: pkg + "/" + sub, file: file})
		}
		return len(out) < nodePublicModuleCap
	})
	return out
}

// nodeWalkPackageFiles calls visit with the slash-separated path of each file
// of the package in dir, in lexical order, skipping nested packages
// (node_modules) and hidden directories, until visit returns false.
func nodeWalkPackageFiles(dir string, visit func(rel string) bool) {
	var walk func(rel string) bool
	walk = func(rel string) bool {
		entries, err := os.ReadDir(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return true
		}
		for _, entry := range entries {
			name := entry.Name()
			child := name
			if rel != "" {
				child = rel + "/" + name
			}
			if entry.IsDir() {
				if name == "node_modules" || strings.HasPrefix(name, ".") {
					continue
				}
				if !walk(child) {
					return false
				}
				continue
			}
			if entry.Type().IsRegular() && !visit(child) {
				return false
			}
		}
		return true
	}
	walk("")
}
