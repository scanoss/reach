// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"fmt"
	"slices"
)

// ToFragment projects an exported graph fragment onto the stitch model for the
// given component. The component key is supplied by the caller because the
// export carries source-level identity (module, function keys) but not the
// (purl, version) it was requested for.
//
// All graph-fragment-1.2 fields (CanonicalSignature, EntryCall, CryptoCall,
// asset metadata) are mapped when present. Legacy 1.0/1.1 fragments decode with
// nil/zero for the new fields — safe structural-only degradation. What a
// 1.22 producer left out is restored in e first (RestoreElided).
func (e *GraphFragmentExport) ToFragment(component ComponentKey) Fragment {
	e.RestoreElided()
	frag := Fragment{
		Component:        component,
		Module:           e.ScanMetadata.RootModule,
		GraphAlgoVersion: e.ScanMetadata.GraphAlgoVersion,
		Supertypes:       e.Supertypes,
		Exports:          e.Exports,
		ServiceProviders: e.ServiceProviders,
		AbstractMethods:  e.ScanMetadata.AbstractMethods,
	}
	if e.ScanMetadata.EntryKinds {
		frag.EntryKinds = make(map[string]string)
	}

	// One table per fragment: a fragment repeats its callers, call targets,
	// file paths and argument provenance on every call, and the decoder
	// allocates each occurrence anew.
	in := make(internTable)
	appendFragmentFunctions(&frag, e.Functions, in)
	if constructsRecorded(e.ScanMetadata.Ecosystem, component) {
		for i := range e.Functions {
			frag.Functions[i].Constructs = constructedClass(e.Functions[i].ReturnSources)
		}
	}
	for i := range e.Functions {
		if kind := e.Functions[i].EntryKind; kind != "" && frag.EntryKinds != nil {
			frag.EntryKinds[e.Functions[i].Key] = kind
		}
	}
	functionKeys := graphFragmentFunctionKeys(e.Functions)
	if len(e.CompactInternalEdges) > 0 {
		appendCompactInternalEdges(&frag, functionKeys, e.InternalEdgeStrings, e.CompactInternalEdges, in)
	} else {
		appendInternalEdges(&frag, e.InternalEdges, in)
	}
	appendExternalCalls(&frag, e.ExternalCalls, in)
	appendCryptoOperations(&frag, e.CryptoAnnotations)
	appendSupportingCalls(&frag, e.SupportingCalls)
	frag.CryptoEntryPoints = appendCryptoEntryPoints(frag.CryptoEntryPoints, e.CryptoEntryPoints, functionKeys)
	return frag
}

func appendFragmentFunctions(frag *Fragment, functions []GraphFragmentFunction, in internTable) {
	frag.Functions = slices.Grow(frag.Functions, len(functions))
	for i := range functions {
		fn := &functions[i]
		frag.Functions = append(frag.Functions, Function{
			Signature:                     fn.Key,
			FunctionName:                  fn.FunctionName,
			DeclaringType:                 in.get(fn.Type),
			CanonicalSignature:            fn.CanonicalSignature,
			ErasedSignature:               fn.ErasedSignature,
			CompatibleCanonicalSignatures: append([]string(nil), fn.CompatibleCanonicalSignatures...),
			ReturnType:                    in.get(fn.ReturnType),
			ParameterTypes:                in.all(fn.ParameterTypes),
			Visibility:                    in.get(fn.Visibility),
			OwnerVisibility:               in.get(fn.OwnerVisibility),
			StartLine:                     fn.StartLine,
			EndLine:                       fn.EndLine,
			StartCol:                      fn.StartCol,
			EndCol:                        fn.EndCol,
			FilePath:                      in.get(fn.FilePath),
			DisplaySymbol:                 fn.DisplaySymbol,
			Aliases:                       append([]string(nil), fn.Aliases...),
			ReturnsCalls:                  append([]string(nil), fn.ReturnsCalls...),
			Abstract:                      fn.Abstract,
		})
	}
}

func graphFragmentFunctionKeys(functions []GraphFragmentFunction) []string {
	keys := make([]string, len(functions))
	for i := range functions {
		keys[i] = functions[i].Key
	}
	return keys
}

func appendCompactInternalEdges(
	frag *Fragment,
	functionKeys []string,
	strings []string,
	edges []GraphFragmentCompactEdge,
	in internTable,
) {
	frag.InternalEdges = slices.Grow(frag.InternalEdges, len(edges))
	for i := range edges {
		ie := &edges[i]
		frag.InternalEdges = append(frag.InternalEdges, InternalEdge{
			Caller:               functionKeyAt(functionKeys, ie.Caller),
			Callee:               functionKeyAt(functionKeys, ie.Callee),
			Resolution:           normalizeResolutionKind(stringAt(strings, ie.Resolution)),
			DeclaredType:         stringAt(strings, ie.DeclaredType),
			MethodName:           stringAt(strings, ie.MethodName),
			Arity:                ie.Arity,
			CallSite:             ie.Line,
			ReceiverVar:          stringAt(strings, ie.ReceiverVar),
			AssignedVar:          stringAt(strings, ie.AssignedVar),
			ChainID:              stringAt(strings, ie.ChainID),
			StartCol:             ie.StartCol,
			EndCol:               ie.EndCol,
			EntryCall:            toCallSite(ie.EntryCall, in),
			ResolvedReceiverType: stringAt(strings, ie.ResolvedReceiverType),
		})
	}
}

func appendInternalEdges(frag *Fragment, edges []GraphFragmentEdge, in internTable) {
	frag.InternalEdges = slices.Grow(frag.InternalEdges, len(edges))
	for i := range edges {
		ie := &edges[i]
		frag.InternalEdges = append(frag.InternalEdges, InternalEdge{
			Caller:               in.get(ie.CallerKey),
			Callee:               in.get(ie.CalleeKey),
			Resolution:           normalizeResolutionKind(ie.Resolution),
			DeclaredType:         in.get(ie.DeclaredType),
			MethodName:           in.get(ie.MethodName),
			Arity:                ie.Arity,
			CallSite:             ie.Line,
			ReceiverVar:          in.get(ie.ReceiverVar),
			AssignedVar:          in.get(ie.AssignedVar),
			ChainID:              in.get(ie.ChainID),
			StartCol:             ie.StartCol,
			EndCol:               ie.EndCol,
			EntryCall:            toCallSite(ie.EntryCall, in),
			ResolvedReceiverType: in.get(ie.ResolvedReceiverType),
		})
	}
}

func appendExternalCalls(frag *Fragment, calls []GraphFragmentExternal, in internTable) {
	frag.ExternalCalls = slices.Grow(frag.ExternalCalls, len(calls))
	for i := range calls {
		ec := &calls[i]
		frag.ExternalCalls = append(frag.ExternalCalls, ExternalCall{
			Caller:                   in.get(ec.CallerKey),
			TargetSignature:          in.get(ec.TargetKey),
			TargetCanonicalSignature: in.get(ec.TargetCanonicalSignature),
			Raw:                      in.get(ec.Raw),
			Resolution:               normalizeResolutionKind(ec.Resolution),
			DeclaredType:             in.get(ec.DeclaredType),
			MethodName:               in.get(ec.MethodName),
			Arity:                    ec.Arity,
			CallSite:                 ec.Line,
			ReceiverVar:              in.get(ec.ReceiverVar),
			AssignedVar:              in.get(ec.AssignedVar),
			ChainID:                  in.get(ec.ChainID),
			StartCol:                 ec.StartCol,
			EndCol:                   ec.EndCol,
			EntryCall:                toCallSite(ec.EntryCall, in),
			ResolvedReceiverType:     in.get(ec.ResolvedReceiverType),
			CandidateModules:         ec.CandidateModules,
			ReceiverProducer:         in.get(ec.ReceiverProducer),
		})
	}
}

func appendCryptoOperations(frag *Fragment, ops []GraphFragmentCryptoOp) {
	for i := range ops {
		op := &ops[i]
		frag.CryptoOperations = append(frag.CryptoOperations, CryptoOperation{
			Function:          op.FunctionKey,
			FindingID:         op.FindingID,
			OccurrenceKey:     op.OccurrenceKey,
			RuleID:            op.RuleID,
			Symbol:            op.Symbol,
			FilePath:          op.FilePath,
			StartLine:         op.StartLine,
			EndLine:           op.EndLine,
			Match:             op.Expression,
			CryptoCall:        toCryptoCall(op.CryptoCall),
			OID:               op.OID,
			Metadata:          op.Metadata,
			Source:            op.Source,
			PURL:              op.PURL,
			MatchedOperation:  toMatchedOp(op.MatchedOperation),
			SupportingCallIDs: append([]string(nil), op.SupportingCallIDs...),
		})
	}
}

func appendSupportingCalls(frag *Fragment, calls []GraphFragmentSupporting) {
	for i := range calls {
		s := &calls[i]
		frag.SupportingCalls = append(frag.SupportingCalls, SupportingCall{
			Function:           s.FunctionKey,
			SupportingID:       s.SupportingID,
			Category:           s.Category,
			FilePath:           s.FilePath,
			StartLine:          s.StartLine,
			EndLine:            s.EndLine,
			FunctionName:       s.FunctionName,
			CanonicalSignature: s.CanonicalSignature,
			DisplaySymbol:      s.DisplaySymbol,
			Aliases:            append([]string(nil), s.Aliases...),
			SupportingCall:     toCryptoCall(s.SupportingCall),
			Metadata:           s.Metadata,
			MatchedOperation:   toMatchedOp(s.MatchedOperation),
		})
	}
}

func functionKeyAt(values []string, idx int) string {
	if idx < 0 || idx >= len(values) {
		return ""
	}
	return values[idx]
}

func stringAt(values []string, idx int) string {
	if idx < 0 || idx >= len(values) {
		return ""
	}
	return values[idx]
}

func appendCryptoEntryPoints(
	dst []CryptoEntryPoint,
	src []GraphFragmentCryptoEntryPoint,
	functionKeys []string,
) []CryptoEntryPoint {
	for i := range src {
		ep := &src[i]
		dst = append(dst, CryptoEntryPoint{
			FunctionKey:              ep.FunctionKey,
			FunctionName:             ep.FunctionName,
			CanonicalSignature:       ep.CanonicalSignature,
			DisplaySymbol:            ep.DisplaySymbol,
			Aliases:                  append([]string(nil), ep.Aliases...),
			ReturnType:               ep.ReturnType,
			ParameterTypes:           append([]string(nil), ep.ParameterTypes...),
			Visibility:               ep.Visibility,
			OwnerVisibility:          ep.OwnerVisibility,
			ReachableFindings:        toReachableFindings(ep.ReachableFindings, functionKeys),
			ReachableSupportingCalls: toReachableSupportingCalls(ep.ReachableSupportingCalls),
			MethodRole:               ep.MethodRole,
			RoleProvenance:           toRoleProvenance(ep.RoleProvenance),
			ParameterRoles:           toParameterRoles(ep.ParameterRoles),
		})
	}
	return dst
}

// toRoleProvenance converts a GraphFragmentRoleProvenance pointer to a
// RoleProvenance pointer. Returns nil if src is nil (issue-103: absent on
// fragments with no KB role match, and on all fragments exported before
// schema graph-fragment-1.7 / callgraph 6.4).
func toRoleProvenance(src *GraphFragmentRoleProvenance) *RoleProvenance {
	if src == nil {
		return nil
	}
	rp := &RoleProvenance{
		Kind:               src.Kind,
		ContractMethod:     src.ContractMethod,
		InheritedFrom:      src.InheritedFrom,
		InheritedAmbiguous: src.InheritedAmbiguous,
	}
	if src.Inherited != nil {
		rp.Inherited = &InheritedRole{
			AlgorithmFamily: src.Inherited.AlgorithmFamily,
			Primitive:       src.Inherited.Primitive,
		}
	}
	return rp
}

// toParameterRoles converts a []GraphFragmentParameterRole to a []ParameterRole.
func toParameterRoles(src []GraphFragmentParameterRole) []ParameterRole {
	if len(src) == 0 {
		return nil
	}
	out := make([]ParameterRole, len(src))
	for i := range src {
		out[i] = ParameterRole{
			Index: src[i].Index,
			Name:  src[i].Name,
			Role:  src[i].Role,
		}
		if src[i].Contributes != nil {
			out[i].Contributes = &Contribution{
				Property:         src[i].Contributes.Property,
				Derivation:       src[i].Contributes.Derivation,
				ArgumentProperty: src[i].Contributes.ArgumentProperty,
			}
		}
	}
	return out
}

func toReachableFindings(src []GraphFragmentReachableFinding, functionKeys []string) []ReachableFinding {
	if len(src) == 0 {
		return nil
	}
	out := make([]ReachableFinding, len(src))
	for i := range src {
		out[i] = ReachableFinding{
			FindingID:       src[i].FindingID,
			ChainDepth:      src[i].ChainDepth,
			Route:           toRoute(src[i].Route, functionKeys),
			FindingGraphRef: src[i].FindingGraphRef,
		}
	}
	return out
}

// toRoute resolves route indexes to function keys. An index the fragment cannot
// resolve drops the whole route rather than a frame: a route with a hole would
// claim a call that is not there, and the depth still answers how far the crypto
// is.
func toRoute(indexes []int, functionKeys []string) []string {
	if len(indexes) == 0 {
		return nil
	}
	route := make([]string, 0, len(indexes))
	for _, idx := range indexes {
		key := functionKeyAt(functionKeys, idx)
		if key == "" {
			return nil
		}
		route = append(route, key)
	}
	return route
}

func toReachableSupportingCalls(src []GraphFragmentReachableSupportingCall) []ReachableSupportingCall {
	if len(src) == 0 {
		return nil
	}
	out := make([]ReachableSupportingCall, len(src))
	for i := range src {
		out[i] = ReachableSupportingCall{
			SupportingID:      src[i].SupportingID,
			ChainDepth:        src[i].ChainDepth,
			SupportingCallRef: src[i].SupportingCallRef,
		}
	}
	return out
}

// toCallSite converts a GraphFragmentCallSite pointer to a CallSite pointer.
// Returns nil if src is nil (1.0/1.1 fragments that have no entry_call).
func toCallSite(src *GraphFragmentCallSite, in internTable) *CallSite {
	if src == nil {
		return nil
	}
	return &CallSite{Line: src.Line, Parameters: toParameters(src.Parameters, in)}
}

// toParameters converts parameters into a slice of exactly their length; nil
// stays nil.
func toParameters(src []GraphFragmentParameter, in internTable) []Parameter {
	if len(src) == 0 {
		return nil
	}
	out := make([]Parameter, len(src))
	for i := range src {
		out[i] = toParameter(src[i], in)
	}
	return out
}

// toParameter converts a GraphFragmentParameter to a Parameter.
func toParameter(src GraphFragmentParameter, in internTable) Parameter {
	return Parameter{
		ParameterIndex:     src.ParameterIndex,
		Keyword:            in.get(src.Keyword),
		Type:               in.get(src.Type),
		VariableName:       in.get(src.VariableName),
		ArgumentExpression: in.get(src.ArgumentExpression),
		ResolvedValue:      in.get(src.ResolvedValue),
		SourceNodes:        toSourceNodes(src.SourceNodes, in),
	}
}

func toSourceNodes(src []GraphFragmentSourceNode, in internTable) []SourceNode {
	if len(src) == 0 {
		return nil
	}
	out := make([]SourceNode, len(src))
	for i := range src {
		out[i] = toSourceNode(src[i], in)
	}
	return out
}

// toSourceNode recursively converts a GraphFragmentSourceNode to a SourceNode.
func toSourceNode(src GraphFragmentSourceNode, in internTable) SourceNode {
	sn := SourceNode{
		Type:                in.get(src.Type),
		Name:                in.get(src.Name),
		DeclaredType:        in.get(src.DeclaredType),
		Value:               in.get(src.Value),
		ParameterIndex:      src.ParameterIndex,
		CallTarget:          in.get(src.CallTarget),
		MayValues:           src.MayValues,
		MayValuesExhaustive: src.MayValuesExhaustive,
		SourceNodes:         toSourceNodes(src.SourceNodes, in),
	}
	if src.Location != nil {
		sn.Location = &SourceLocation{
			FilePath: in.get(src.Location.FilePath),
			Line:     src.Location.Line,
		}
	}
	return sn
}

// internTable shares one copy of each string a fragment repeats. A nil table
// shares nothing.
type internTable map[string]string

func (t internTable) get(s string) string {
	if t == nil || s == "" {
		return s
	}
	if shared, ok := t[s]; ok {
		return shared
	}
	t[s] = s
	return s
}

// all interns the elements of values in place.
func (t internTable) all(values []string) []string {
	for i := range values {
		values[i] = t.get(values[i])
	}
	return values
}

// toCryptoCall converts a GraphFragmentCryptoCall pointer to a CryptoCall pointer.
// Returns nil if src is nil (1.0/1.1 fragments).
func toCryptoCall(src *GraphFragmentCryptoCall) *CryptoCall {
	if src == nil {
		return nil
	}
	cc := &CryptoCall{
		FunctionName:       src.FunctionName,
		CanonicalSignature: src.CanonicalSignature,
		ReturnType:         src.ReturnType,
		ParameterTypes:     src.ParameterTypes,
		DisplaySymbol:      src.DisplaySymbol,
		Aliases:            append([]string(nil), src.Aliases...),
		Line:               src.Line,
		ParameterRoles:     toParameterRoles(src.ParameterRoles),
		ResolvedKeyLength:  cloneResolvedKeyLength(src.ResolvedKeyLength),
	}
	cc.Parameters = toParameters(src.Parameters, nil)
	return cc
}

// toMatchedOp converts a GraphFragmentMatchedOp pointer to a MatchedOp pointer.
// Returns nil if src is nil (1.0/1.1 fragments).
func toMatchedOp(src *GraphFragmentMatchedOp) *MatchedOp {
	if src == nil {
		return nil
	}
	return &MatchedOp{
		Kind:       src.Kind,
		Symbol:     src.Symbol,
		Expression: src.Expression,
		Line:       src.Line,
	}
}

func normalizeResolutionKind(value string) ResolutionKind {
	switch kind := ResolutionKind(value); kind {
	case ResolutionExact, ResolutionInterfaceDispatch, ResolutionNameOnly, ResolutionUnknown:
		return kind
	default:
		return ResolutionUnknown
	}
}

// DecodeFragment parses one graph-fragment export (JSON) into a Fragment for the
// given component. Legacy fragments exported before the resolution fields
// existed decode to ResolutionUnknown, which the stitcher fails closed on —
// safe under-reporting, never a false positive.
func DecodeFragment(component ComponentKey, data []byte) (Fragment, error) {
	var e GraphFragmentExport
	if err := json.Unmarshal(data, &e); err != nil {
		return Fragment{}, fmt.Errorf("graphfrag: decode fragment for %s: %w", component, err)
	}
	return e.ToFragment(component), nil
}

// ExpandInternalEdges turns the compact internal edges of a decoded document
// (graph-fragment-1.7 and later) into InternalEdges, the form the exporter
// builds in memory, so a stored fragment reads as the one a scan built.
func (e *GraphFragmentExport) ExpandInternalEdges() {
	if len(e.CompactInternalEdges) == 0 {
		return
	}
	keys := graphFragmentFunctionKeys(e.Functions)
	edges := make([]GraphFragmentEdge, 0, len(e.InternalEdges)+len(e.CompactInternalEdges))
	edges = append(edges, e.InternalEdges...)
	for i := range e.CompactInternalEdges {
		ce := &e.CompactInternalEdges[i]
		edges = append(edges, GraphFragmentEdge{
			CallerKey:            functionKeyAt(keys, ce.Caller),
			CalleeKey:            functionKeyAt(keys, ce.Callee),
			Line:                 ce.Line,
			Resolution:           stringAt(e.InternalEdgeStrings, ce.Resolution),
			DeclaredType:         stringAt(e.InternalEdgeStrings, ce.DeclaredType),
			MethodName:           stringAt(e.InternalEdgeStrings, ce.MethodName),
			Arity:                ce.Arity,
			ReceiverVar:          stringAt(e.InternalEdgeStrings, ce.ReceiverVar),
			AssignedVar:          stringAt(e.InternalEdgeStrings, ce.AssignedVar),
			ChainID:              stringAt(e.InternalEdgeStrings, ce.ChainID),
			StartCol:             ce.StartCol,
			EndCol:               ce.EndCol,
			EndLine:              ce.EndLine,
			EntryCall:            ce.EntryCall,
			ResolvedReceiverType: stringAt(e.InternalEdgeStrings, ce.ResolvedReceiverType),
		})
	}
	e.InternalEdges, e.CompactInternalEdges, e.InternalEdgeStrings = edges, nil, nil
}
