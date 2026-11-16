// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"reflect"
	"testing"
)

// fullDocument is a 1.21-form document with every case the 1.22 elisions
// meet: a call to two targets whose edges share an entry call, an edge at
// that site without one, an external call at an internal edge's site,
// locations in the function's file, in another file and with a line and no
// file, and functions whose names their keys give or not.
func fullDocument() GraphFragmentExport {
	loc := func(file string, line int) *GraphFragmentSourceLoc {
		return &GraphFragmentSourceLoc{FilePath: file, Line: line}
	}
	call := func(line int, file string) *GraphFragmentCallSite {
		return &GraphFragmentCallSite{Line: line, Parameters: []GraphFragmentParameter{{
			ParameterIndex: 0, ArgumentExpression: "key",
			SourceNodes: []GraphFragmentSourceNode{{Type: "VARIABLE", Name: "key", Location: loc(file, line-1),
				SourceNodes: []GraphFragmentSourceNode{{Type: "CALL_RESULT", Location: loc("b/Other.java", 7)}}}},
		}}}
	}
	return GraphFragmentExport{
		SchemaVersion: SchemaVersion,
		ScanMetadata:  GraphFragmentScanMetadata{Ecosystem: "java", RootModule: "a:b"},
		Functions: []GraphFragmentFunction{
			{Key: "a.(Run).run#1", FunctionName: "a.Run.run", CanonicalSignature: "a.Run.run(Key): void", ErasedSignature: "a.Run.run(Key): void",
				Package: "a", Type: "Run", Name: "run#1", FilePath: "a/Run.java", DisplaySymbol: "a.Run.run",
				ReturnSources: []GraphFragmentRawSource{{Type: "VALUE", Value: "null", Location: loc("a/Run.java", 4)}}},
			{Key: "(Impl).<init>#0", FunctionName: "Impl.<init>", Type: "Impl", Name: "<init>#0", FilePath: "Impl.java", DisplaySymbol: "Impl.Impl",
				CanonicalSignature: "Impl.<init>(): Impl", ErasedSignature: "Impl.<init>(): Object"},
			{Key: "a.(Impl).use#1", FunctionName: "a.Impl.use", Package: "a", Type: "Impl", Name: "use#1", FilePath: "a/Impl.java", DisplaySymbol: "a.Impl.use"},
		},
		InternalEdgeStrings: []string{"", "exact", "interface_dispatch"},
		CompactInternalEdges: []GraphFragmentCompactEdge{
			{Caller: 0, Callee: 1, Line: 9, Resolution: 2, Arity: 1, StartCol: 3, EndCol: 20, EntryCall: call(9, "a/Run.java")},
			{Caller: 0, Callee: 2, Line: 9, Resolution: 2, Arity: 1, StartCol: 3, EndCol: 20, EntryCall: call(9, "a/Run.java")},
			{Caller: 0, Callee: 2, Line: 9, Resolution: 2, Arity: 1, StartCol: 3, EndCol: 20},
			{Caller: 0, Callee: 1, Line: 9, Resolution: 2, Arity: 2, StartCol: 3, EndCol: 20},
			{Caller: 2, Callee: 1, Line: 3, Resolution: 1, StartCol: 1, EndCol: 9, EntryCall: &GraphFragmentCallSite{Line: 3}},
		},
		ExternalCalls: []GraphFragmentExternal{
			{CallerKey: "a.(Run).run#1", TargetKey: "x.(Key).use#1", TargetFunctionName: "x.Key.use", Resolution: "name_only", Line: 9, Arity: 1, StartCol: 3, EndCol: 20, EntryCall: call(9, "a/Run.java")},
			{CallerKey: "a.(Run).run#1", TargetKey: "x.(Key).get#1", TargetFunctionName: "x.Key.fetch", Resolution: "exact", Line: 12, Arity: 1, StartCol: 3, EndCol: 20,
				EntryCall: &GraphFragmentCallSite{Line: 12, Parameters: []GraphFragmentParameter{{SourceNodes: []GraphFragmentSourceNode{{Type: "FIELD", Location: &GraphFragmentSourceLoc{Line: 2}}}}}}},
			{CallerKey: "a.(Run).run#1", TargetKey: "digest#1", TargetFunctionName: "digest", Resolution: "name_only", Line: 13, Arity: 1},
		},
		CallAnchors: []GraphFragmentCallAnchor{{Function: 0, Line: 9, StartCol: 3, EndCol: 20, Kind: "method_invocation", Path: "block[0]", Callee: "a.(Impl).use#1",
			Arguments: []string{"key"}, ArgumentSources: [][]GraphFragmentRawSource{{{Type: "PARAMETER", Location: loc("a/Run.java", 8)}}}}},
		ConstantRefs: []GraphFragmentConstantRef{{Function: 2, Line: 5, Text: "K.A", Context: "compare",
			Operand: &GraphFragmentParameter{SourceNodes: []GraphFragmentSourceNode{{Type: "VARIABLE", Location: loc("a/Impl.java", 4)}}}}},
	}
}

// elideAsAWriter leaves out of doc what a 1.22 producer does
// (internal/scan's graph-fragment writer).
func elideAsAWriter(t *testing.T, doc *GraphFragmentExport) {
	t.Helper()
	files := map[string]string{}
	for i := range doc.Functions {
		fn := &doc.Functions[i]
		files[fn.Key] = fn.FilePath
		ElideRawSourceFiles(fn.ReturnSources, fn.FilePath)
	}
	doc.ScanMetadata.DerivedFunctionNames = ElideFunctionNames(doc.Functions)
	sharer := NewEntryCallSharer()
	share := func(caller string, line, startCol, endCol, arity int, call **GraphFragmentCallSite) {
		ElideCallSiteFiles(*call, files[caller])
		var encoded []byte
		if *call != nil {
			encoded, _ = json.Marshal(*call)
		}
		switch shared := sharer.Share(caller, line, startCol, endCol, arity, encoded); {
		case shared == nil:
			*call = nil
		case string(shared) == "{}":
			*call = &GraphFragmentCallSite{}
		}
	}
	for i := range doc.CompactInternalEdges {
		e := &doc.CompactInternalEdges[i]
		share(doc.Functions[e.Caller].Key, e.Line, e.StartCol, e.EndCol, e.Arity, &e.EntryCall)
	}
	for i := range doc.ExternalCalls {
		c := &doc.ExternalCalls[i]
		share(c.CallerKey, c.Line, c.StartCol, c.EndCol, c.Arity, &c.EntryCall)
	}
	doc.ScanMetadata.DerivedTargetNames = ElideTargetNames(doc.ExternalCalls)
	for i := range doc.CallAnchors {
		for _, sources := range doc.CallAnchors[i].ArgumentSources {
			ElideRawSourceFiles(sources, doc.Functions[doc.CallAnchors[i].Function].FilePath)
		}
	}
	for i := range doc.ConstantRefs {
		ElideParameterFiles(doc.ConstantRefs[i].Operand, doc.Functions[doc.ConstantRefs[i].Function].FilePath)
	}
	doc.ScanMetadata.SharedEntryCalls, doc.ScanMetadata.ImplicitSourceFiles = true, true
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// A 1.22 document restores to the document a 1.21 producer writes, and
// leaves out what the elisions promise.
func TestElidedDocumentDecodesAsWritten(t *testing.T) {
	t.Parallel()
	want := mustJSON(t, fullDocument())
	doc := fullDocument()
	elideAsAWriter(t, &doc)
	elided := mustJSON(t, doc)

	if !doc.ScanMetadata.DerivedFunctionNames {
		t.Fatal("function names were not elided")
	}
	if doc.Functions[0].FunctionName != "" || doc.Functions[0].Package != "" || doc.Functions[0].ErasedSignature != "" || doc.Functions[0].DisplaySymbol != "" {
		t.Errorf("derivable names written: %+v", doc.Functions[0])
	}
	if doc.Functions[1].DisplaySymbol != "Impl.Impl" || doc.Functions[1].ErasedSignature != "Impl.<init>(): Object" {
		t.Errorf("names that differ from the derived ones were dropped: %+v", doc.Functions[1])
	}
	edges := doc.CompactInternalEdges
	if edges[0].EntryCall == nil || edges[1].EntryCall != nil || !isNoEntryCall(edges[2].EntryCall) || edges[3].EntryCall != nil {
		t.Errorf("entry calls not shared as expected: %s", mustJSON(t, edges))
	}
	if !doc.ScanMetadata.DerivedTargetNames || doc.ExternalCalls[0].TargetFunctionName != "" || doc.ExternalCalls[2].TargetFunctionName != "" ||
		doc.ExternalCalls[1].TargetFunctionName != "x.Key.fetch" {
		t.Errorf("target names not elided as expected: %s", mustJSON(t, doc.ExternalCalls))
	}
	if doc.ExternalCalls[0].EntryCall != nil {
		t.Error("an external call repeats the entry call of an internal edge at its site")
	}
	if got := edges[0].EntryCall.Parameters[0].SourceNodes[0].Location; got.FilePath != "" {
		t.Errorf("a location in the caller's file keeps it: %+v", got)
	}
	if got := edges[0].EntryCall.Parameters[0].SourceNodes[0].SourceNodes[0].Location; got.FilePath != "b/Other.java" {
		t.Errorf("a location in another file lost it: %+v", got)
	}
	if got := doc.ExternalCalls[1].EntryCall.Parameters[0].SourceNodes[0].Location; !got.NoFile {
		t.Errorf("a location with a line and no file is not marked: %+v", got)
	}

	var decoded GraphFragmentExport
	if err := json.Unmarshal(elided, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.RestoreElided()
	if got := mustJSON(t, decoded); string(got) != string(want) {
		t.Errorf("restored document differs from the written one\n got %s\nwant %s", got, want)
	}

	// scanoss.api decodes the sections into its own struct and projects
	// them with ToFragment alone.
	var api GraphFragmentExport
	if err := json.Unmarshal(elided, &api); err != nil {
		t.Fatal(err)
	}
	projected := api.ToFragment(ComponentKey{})
	original, err := DecodeFragment(ComponentKey{}, want)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projected, original) {
		t.Errorf("ToFragment of the elided sections differs\n got %s\nwant %s", mustJSON(t, projected), mustJSON(t, original))
	}
}

// A function whose empty field the restore would fill keeps the whole
// document's names: ElideFunctionNames changes nothing.
func TestElideFunctionNamesRefusesAnAmbiguousDocument(t *testing.T) {
	t.Parallel()
	for name, fn := range map[string]GraphFragmentFunction{
		"no function name":    {Key: "a.(T).m#0", Package: "a", Type: "T", Name: "m#0"},
		"no display symbol":   {Key: "a.(T).m#0", FunctionName: "a.T.m", Package: "a", Type: "T", Name: "m#0"},
		"no erased signature": {Key: "a.(T).m#0", FunctionName: "a.T.m", DisplaySymbol: "a.T.m", CanonicalSignature: "a.T.m(): void"},
	} {
		functions := []GraphFragmentFunction{fullDocument().Functions[0], fn}
		before := mustJSON(t, functions)
		if ElideFunctionNames(functions) {
			t.Errorf("%s: elided", name)
		}
		if after := mustJSON(t, functions); string(after) != string(before) {
			t.Errorf("%s: changed %s", name, after)
		}
	}
}

// An external call without a target name its key would give keeps every
// call's: ElideTargetNames changes nothing.
func TestElideTargetNamesRefusesAnAmbiguousDocument(t *testing.T) {
	t.Parallel()
	calls := []GraphFragmentExternal{{TargetKey: "x.(Key).use#1", TargetFunctionName: "x.Key.use"}, {TargetKey: "get#0"}}
	before := mustJSON(t, calls)
	if ElideTargetNames(calls) {
		t.Error("elided")
	}
	if after := mustJSON(t, calls); string(after) != string(before) {
		t.Errorf("changed %s", after)
	}
}

// A 1.21 document has no flags: restoring leaves an edge without an entry
// call and a location without a file so.
func TestUnflaggedDocumentIsReadAsWritten(t *testing.T) {
	t.Parallel()
	doc := fullDocument()
	doc.Functions[0].FunctionName = ""
	doc.CompactInternalEdges[1].EntryCall = nil
	doc.CompactInternalEdges[0].EntryCall.Parameters[0].SourceNodes[0].Location.FilePath = ""
	want := mustJSON(t, doc)
	var decoded GraphFragmentExport
	if err := json.Unmarshal(want, &decoded); err != nil {
		t.Fatal(err)
	}
	decoded.RestoreElided()
	if got := mustJSON(t, decoded); string(got) != string(want) {
		t.Errorf("decoding changed an unflagged document\n got %s\nwant %s", got, want)
	}
}
