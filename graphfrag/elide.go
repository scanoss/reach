// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"bytes"
	"crypto/sha256"
	"strings"
)

// A graph-fragment-1.22 document writes once what 1.21 repeated, and says so
// in scan_metadata (GraphFragmentScanMetadata.SharedEntryCalls,
// ImplicitSourceFiles, DerivedFunctionNames, DerivedTargetNames).
// RestoreElided, which ToFragment runs first, puts back what was left out,
// so a reader sees the document a 1.21 producer would have written. A writer
// elides with the helpers below; the crypto sections are never elided.

// RestoreElided puts back what a 1.22 producer left out of a decoded
// document, as its scan_metadata flags say, and clears the flags, so it
// runs once however often it is called. A reader of the document's
// sections calls it after decoding; ToFragment calls it. It is not an
// UnmarshalJSON: a document runs to hundreds of megabytes, and a custom
// decoder makes encoding/json scan it twice more.
func (e *GraphFragmentExport) RestoreElided() {
	meta := &e.ScanMetadata
	if meta.DerivedFunctionNames {
		for i := range e.Functions {
			restoreFunctionNames(&e.Functions[i])
		}
		meta.DerivedFunctionNames = false
	}
	if meta.DerivedTargetNames {
		for i := range e.ExternalCalls {
			if call := &e.ExternalCalls[i]; call.TargetFunctionName == "" {
				call.TargetFunctionName, _ = derivedTargetName(call.TargetKey)
			}
		}
		meta.DerivedTargetNames = false
	}
	// Files before shared entry calls: an entry call shared by several edges
	// is then restored once, as written.
	if meta.ImplicitSourceFiles {
		e.restoreSourceFiles()
		meta.ImplicitSourceFiles = false
	}
	if meta.SharedEntryCalls {
		e.restoreSharedEntryCalls()
		meta.SharedEntryCalls = false
	}
}

// functionKeyParts splits a method key, package.(Type).name or (Type).name,
// as callgraph.ParseFunctionID does. ok is false for any other key.
func functionKeyParts(key string) (pkg, typ, name string, ok bool) {
	open := strings.Index(key, ".(") + 1
	if !strings.HasPrefix(key, "(") && open == 0 {
		return "", "", "", false
	}
	if open == 1 || strings.HasPrefix(key, ".") {
		return "", "", "", false
	}
	pkg = strings.TrimSuffix(key[:open], ".")
	rest := key[open+1:]
	end := strings.Index(rest, ").")
	if end <= 0 || end+2 >= len(rest) {
		return "", "", "", false
	}
	return pkg, rest[:end], rest[end+2:], true
}

// derivedFunctionName is the function_name a method key implies: package,
// type and name without its #arity, joined by dots.
func derivedFunctionName(pkg, typ, name string) string {
	if i := strings.Index(name, "#"); i > 0 {
		name = name[:i]
	}
	if pkg == "" {
		return typ + "." + name
	}
	return pkg + "." + typ + "." + name
}

// ElideFunctionNames leaves out of functions what their keys and other
// fields give (DerivedFunctionNames): package, type and name when all three
// are the key's, function_name when it is the key's, display_symbol when it
// is function_name and erased_signature when it is canonical_signature. It
// reports false, changing nothing, when one function has a value that
// restoring could not tell from a left-out one (an empty field the rule
// would fill).
func ElideFunctionNames(functions []GraphFragmentFunction) bool {
	for i := range functions {
		if _, ok := elideFunctionNames(functions[i]); !ok {
			return false
		}
	}
	for i := range functions {
		functions[i], _ = elideFunctionNames(functions[i])
	}
	return true
}

func elideFunctionNames(fn GraphFragmentFunction) (GraphFragmentFunction, bool) {
	name := fn.FunctionName
	if pkg, typ, method, ok := functionKeyParts(fn.Key); ok {
		switch {
		case fn.Package == pkg && fn.Type == typ && fn.Name == method:
			fn.Package, fn.Type, fn.Name = "", "", ""
		case fn.Package == "" && fn.Type == "" && fn.Name == "":
			return fn, false
		}
		switch derived := derivedFunctionName(pkg, typ, method); fn.FunctionName {
		case derived:
			fn.FunctionName = ""
		case "":
			return fn, false
		}
	}
	switch {
	case name != "" && fn.DisplaySymbol == name:
		fn.DisplaySymbol = ""
	case name != "" && fn.DisplaySymbol == "":
		return fn, false
	}
	switch {
	case fn.CanonicalSignature != "" && fn.ErasedSignature == fn.CanonicalSignature:
		fn.ErasedSignature = ""
	case fn.CanonicalSignature != "" && fn.ErasedSignature == "":
		return fn, false
	}
	return fn, true
}

// derivedTargetName is the target_function_name an external call's target
// key implies: a method key's function name, or a bare name#arity without
// its arity.
func derivedTargetName(key string) (string, bool) {
	if pkg, typ, method, ok := functionKeyParts(key); ok {
		return derivedFunctionName(pkg, typ, method), true
	}
	if key == "" || strings.ContainsAny(key, ".()") {
		return "", false
	}
	if i := strings.Index(key, "#"); i > 0 {
		return key[:i], true
	}
	return key, true
}

// ElideTargetNames leaves out the target_function_name of external calls
// whose target key gives it (DerivedTargetNames). It reports false,
// changing nothing, when a call has none and its key gives one.
func ElideTargetNames(calls []GraphFragmentExternal) bool {
	for i := range calls {
		if derived, ok := derivedTargetName(calls[i].TargetKey); ok && derived != "" && calls[i].TargetFunctionName == "" {
			return false
		}
	}
	for i := range calls {
		if derived, ok := derivedTargetName(calls[i].TargetKey); ok && calls[i].TargetFunctionName == derived {
			calls[i].TargetFunctionName = ""
		}
	}
	return true
}

func restoreFunctionNames(fn *GraphFragmentFunction) {
	if pkg, typ, method, ok := functionKeyParts(fn.Key); ok {
		if fn.Package == "" && fn.Type == "" && fn.Name == "" {
			fn.Package, fn.Type, fn.Name = pkg, typ, method
		}
		if fn.FunctionName == "" {
			fn.FunctionName = derivedFunctionName(pkg, typ, method)
		}
	}
	if fn.DisplaySymbol == "" {
		fn.DisplaySymbol = fn.FunctionName
	}
	if fn.ErasedSignature == "" {
		fn.ErasedSignature = fn.CanonicalSignature
	}
}

// ElideLocationFile leaves out a source location's file when it is file, the
// file of the function the location's section belongs to
// (ImplicitSourceFiles). A location with a line and no file is marked
// NoFile, so it is not read as being in file.
func ElideLocationFile(loc *GraphFragmentSourceLoc, file string) {
	switch {
	case loc == nil || loc.Line <= 0:
	case loc.FilePath == "":
		loc.NoFile = true
	case loc.FilePath == file:
		loc.FilePath = ""
	}
}

func restoreLocationFile(loc *GraphFragmentSourceLoc, file string) {
	switch {
	case loc == nil || loc.Line <= 0:
	case loc.NoFile:
		loc.NoFile = false
	case loc.FilePath == "":
		loc.FilePath = file
	}
}

// ElideSourceFiles applies ElideLocationFile to every location of nodes and
// the nodes under them.
func ElideSourceFiles(nodes []GraphFragmentSourceNode, file string) {
	walkSourceNodes(nodes, file, ElideLocationFile)
}

// ElideRawSourceFiles applies ElideLocationFile to every location of nodes
// and the nodes under them.
func ElideRawSourceFiles(nodes []GraphFragmentRawSource, file string) {
	walkRawSources(nodes, file, ElideLocationFile)
}

// ElideCallSiteFiles applies ElideLocationFile to every location of a call
// site's arguments.
func ElideCallSiteFiles(call *GraphFragmentCallSite, file string) {
	walkCallSite(call, file, ElideLocationFile)
}

// ElideParameterFiles applies ElideLocationFile to every location of a
// parameter's provenance.
func ElideParameterFiles(param *GraphFragmentParameter, file string) {
	if param != nil {
		walkSourceNodes(param.SourceNodes, file, ElideLocationFile)
	}
}

func walkCallSite(call *GraphFragmentCallSite, file string, visit func(*GraphFragmentSourceLoc, string)) {
	if call == nil {
		return
	}
	for i := range call.Parameters {
		walkSourceNodes(call.Parameters[i].SourceNodes, file, visit)
	}
}

func walkSourceNodes(nodes []GraphFragmentSourceNode, file string, visit func(*GraphFragmentSourceLoc, string)) {
	for i := range nodes {
		visit(nodes[i].Location, file)
		walkSourceNodes(nodes[i].SourceNodes, file, visit)
	}
}

func walkRawSources(nodes []GraphFragmentRawSource, file string, visit func(*GraphFragmentSourceLoc, string)) {
	for i := range nodes {
		visit(nodes[i].Location, file)
		walkRawSources(nodes[i].SourceNodes, file, visit)
	}
}

// restoreSourceFiles gives every location left without its file the file of
// the function its section belongs to: an edge's caller, an anchor's or a
// constant reference's function, the function a return provenance is of.
func (e *GraphFragmentExport) restoreSourceFiles() {
	files := make([]string, len(e.Functions))
	byKey := make(map[string]string, len(e.Functions))
	for i := range e.Functions {
		files[i] = e.Functions[i].FilePath
		byKey[e.Functions[i].Key] = files[i]
	}
	at := func(index int) string {
		if index >= 0 && index < len(files) {
			return files[index]
		}
		return ""
	}
	for i := range e.Functions {
		walkRawSources(e.Functions[i].ReturnSources, files[i], restoreLocationFile)
	}
	for i := range e.InternalEdges {
		walkCallSite(e.InternalEdges[i].EntryCall, byKey[e.InternalEdges[i].CallerKey], restoreLocationFile)
	}
	for i := range e.CompactInternalEdges {
		walkCallSite(e.CompactInternalEdges[i].EntryCall, at(e.CompactInternalEdges[i].Caller), restoreLocationFile)
	}
	for i := range e.ExternalCalls {
		walkCallSite(e.ExternalCalls[i].EntryCall, byKey[e.ExternalCalls[i].CallerKey], restoreLocationFile)
	}
	for i := range e.CallAnchors {
		for _, sources := range e.CallAnchors[i].ArgumentSources {
			walkRawSources(sources, at(e.CallAnchors[i].Function), restoreLocationFile)
		}
	}
	for i := range e.ConstantRefs {
		if operand := e.ConstantRefs[i].Operand; operand != nil {
			walkSourceNodes(operand.SourceNodes, at(e.ConstantRefs[i].Function), restoreLocationFile)
		}
	}
	for i := range e.AttributeStores {
		walkSourceNodes(e.AttributeStores[i].Value.SourceNodes, at(e.AttributeStores[i].Function), restoreLocationFile)
	}
}

// entryCallSite identifies the call an edge stands for: its caller, span and
// argument count. The edges of a call to several targets share it.
type entryCallSite struct {
	caller                 string
	line, startCol, endCol int
	arity                  int
}

// noEntryCall is how a 1.22 document writes an edge without an entry call
// at a site an earlier edge gave one, which an omitted entry call would take.
// A producer never writes an empty entry call otherwise: a call site without
// a line and arguments has none.
var noEntryCall = []byte("{}")

func isNoEntryCall(call *GraphFragmentCallSite) bool {
	return call != nil && call.Line == 0 && len(call.Parameters) == 0
}

// EntryCallSharer writes each call's entry call once (SharedEntryCalls):
// an edge whose entry call is the one the last edge at its site wrote
// leaves it out, and a reader gives it that one back. Edges are offered in
// document order: internal edges, then external calls.
type EntryCallSharer struct {
	last map[entryCallSite][sha256.Size]byte
}

// NewEntryCallSharer returns a sharer for one document.
func NewEntryCallSharer() *EntryCallSharer {
	return &EntryCallSharer{last: make(map[entryCallSite][sha256.Size]byte)}
}

// Share returns what to write for an edge's entry call, given its JSON
// encoding (nil for none): nil to leave it out, noEntryCall's {} for none
// where an omission would read as the site's entry call, or encoded.
func (s *EntryCallSharer) Share(caller string, line, startCol, endCol, arity int, encoded []byte) []byte {
	site := entryCallSite{caller, line, startCol, endCol, arity}
	last, seen := s.last[site]
	if encoded == nil || bytes.Equal(encoded, noEntryCall) {
		if seen {
			return noEntryCall
		}
		return nil
	}
	digest := sha256.Sum256(encoded)
	if seen && digest == last {
		return nil
	}
	s.last[site] = digest
	return encoded
}

// restoreSharedEntryCalls gives each edge without an entry call the one the
// last edge at its site carried, and drops the {} that stands for none.
func (e *GraphFragmentExport) restoreSharedEntryCalls() {
	last := make(map[entryCallSite]*GraphFragmentCallSite)
	restore := func(site entryCallSite, call **GraphFragmentCallSite) {
		switch {
		case *call == nil:
			*call = last[site]
		case isNoEntryCall(*call):
			*call = nil
		default:
			last[site] = *call
		}
	}
	for i := range e.InternalEdges {
		edge := &e.InternalEdges[i]
		restore(entryCallSite{edge.CallerKey, edge.Line, edge.StartCol, edge.EndCol, edge.Arity}, &edge.EntryCall)
	}
	keys := graphFragmentFunctionKeys(e.Functions)
	for i := range e.CompactInternalEdges {
		edge := &e.CompactInternalEdges[i]
		restore(entryCallSite{functionKeyAt(keys, edge.Caller), edge.Line, edge.StartCol, edge.EndCol, edge.Arity}, &edge.EntryCall)
	}
	for i := range e.ExternalCalls {
		call := &e.ExternalCalls[i]
		restore(entryCallSite{call.CallerKey, call.Line, call.StartCol, call.EndCol, call.Arity}, &call.EntryCall)
	}
}
