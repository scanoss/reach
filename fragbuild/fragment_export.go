// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"sort"
	"strings"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
)

// exportComparedOperand is the operand a constant reference is compared
// with, traced as a fragment call site's argument is (BuildCallSiteParameters):
// return provenance inlined, no caller resolution (a consumer resolves a
// parameter from the fragment's own call sites), then the parameter object.
func exportComparedOperand(ctx *Context, fn *callgraph.FunctionDecl, ref callgraph.ConstantRef) *graphfrag.GraphFragmentParameter {
	if ref.Operand == nil {
		return nil
	}
	out := exportTracedValue(ctx, fn, *ref.Operand, ref.Line)
	return &out
}

// exportTracedValue is a value the parser traced in fn at line (a compared
// operand, a stored value) as a fragment parameter object.
func exportTracedValue(ctx *Context, fn *callgraph.FunctionDecl, value callgraph.ComparedOperand, line int) graphfrag.GraphFragmentParameter {
	p := CallGraphParameter{ArgumentExpression: value.Text}
	if IsSimpleIdentifier(value.Text) {
		p.VariableName = value.Text
	}
	if len(value.Sources) > 0 {
		p.SourceNodes = convertSourceNodes(ctx, resolveExportSourceNodes(ctx, nil, value.Sources, 0), NormalizeExportPath(ctx, fn.FilePath).FilePath, line)
	}
	p.ResolvedValue = ResolveSimpleExportParameterValue(p.ArgumentExpression, p.SourceNodes)
	return ConvertCallGraphParameterToFragment(p)
}

// BuildGraphFragmentConstantRefs lists the constant references of every
// exported function, in function index order, then line and column.
func BuildGraphFragmentConstantRefs(ctx *Context, functionIndex map[string]int) []graphfrag.GraphFragmentConstantRef {
	if ctx == nil || ctx.Graph == nil {
		return nil
	}
	var out []graphfrag.GraphFragmentConstantRef
	for _, key := range SortedKeys(ctx.Graph.Functions) {
		index, ok := functionIndex[key]
		if !ok {
			continue
		}
		fn := ctx.Graph.Functions[key]
		for _, ref := range fn.ConstantRefs {
			out = append(out, graphfrag.GraphFragmentConstantRef{
				Function: index, Line: ref.Line, StartCol: ref.StartCol, EndCol: ref.EndCol, EndLine: ref.EndLine,
				Text: ref.Text, Context: ref.Context, Operand: exportComparedOperand(ctx, fn, ref),
			})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Function != b.Function {
			return a.Function < b.Function
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		return a.StartCol < b.StartCol
	})
	return out
}

// BuildGraphFragmentResolvedEdges returns the fragment's internal edges and external calls, each with its resolution.
func BuildGraphFragmentResolvedEdges(ctx *Context) ([]graphfrag.GraphFragmentEdge, []graphfrag.GraphFragmentExternal) {
	if ctx == nil || ctx.Graph == nil {
		return nil, nil
	}

	internalEdges := make([]graphfrag.GraphFragmentEdge, 0, len(ctx.Graph.EdgeResolutions))
	var externalCalls []graphfrag.GraphFragmentExternal
	ForEachFragmentEdges(ctx, SortedKeys(ctx.Graph.Callers), nil, func(edges FragmentEdges) bool {
		internalEdges = append(internalEdges, edges.Internal...)
		externalCalls = append(externalCalls, edges.External...)
		return true
	})

	return SortedFragmentEdges(internalEdges), SortedFragmentExternalCalls(externalCalls)
}

// SortedFragmentCallers returns calleeKey's callers in the order its edges
// are built.
func SortedFragmentCallers(graph *callgraph.CallGraph, calleeKey string) []string {
	callers := append([]string(nil), graph.Callers[calleeKey]...)
	sort.Strings(callers)
	return callers
}

// BuildResolvedFragmentEdgesFrom builds the edges into calleeKey from callers,
// a run of SortedFragmentCallers: the internal edges in emission order and the
// External calls.
func BuildResolvedFragmentEdgesFrom(ctx *Context, calleeKey string, callers []string) FragmentEdges {
	var out FragmentEdges
	graph := ctx.Graph
	for _, callerKey := range callers {
		callerDecl := graph.Functions[callerKey]
		if callerDecl == nil {
			continue
		}
		resolutions := resolveFragmentEdges(ctx, callerKey, callerDecl, calleeKey)
		for i := range resolutions {
			buildResolvedFragmentEdge(ctx, callerKey, callerDecl, calleeKey, resolutions[i], &out)
		}
	}
	return out
}

func buildResolvedFragmentEdge(
	ctx *Context,
	callerKey string,
	callerDecl *callgraph.FunctionDecl,
	calleeKey string,
	res EdgeResolution,
	out *FragmentEdges,
) {
	line := fragmentEdgeLine(ctx, callerKey, callerDecl, calleeKey, res)
	call := findCallForCalleeAtSite(ctx, callerKey, callerDecl, calleeKey, line, res.StartCol, res.EndCol)
	if call == nil {
		call = findDispatchCallAtLine(callerDecl, line, res.StartCol, res.EndCol, res.MethodName, res.Arity)
	}
	if _, ok := ctx.Graph.Functions[calleeKey]; ok {
		edge := buildFragmentInternalEdge(ctx, callerDecl, call, callerKey, calleeKey, line, res)
		if edge.ChainID == "" {
			edge.ChainID = ChainIDForCallerLine(ctx, callerKey, callerDecl, line)
		}
		out.Internal = append(out.Internal, edge)
		return
	}
	external := BuildFragmentExternalCall(ctx, callerDecl, call, callerKey, calleeKey, line, res)
	if external.ChainID == "" {
		external.ChainID = ChainIDForCallerLine(ctx, callerKey, callerDecl, line)
	}
	out.External = append(out.External, external)
}

// findDispatchCallAtLine recovers the source invocation for a dispatch-expanded
// target whose concrete declaring type differs from the interface call recorded
// by the parser. It fails closed when the line contains more than one matching
// method+arity call.
func findDispatchCallAtLine(fn *callgraph.FunctionDecl, line, startCol, endCol int, method string, arity int) *callgraph.FunctionCall {
	if fn == nil || line <= 0 || method == "" {
		return nil
	}
	var match *callgraph.FunctionCall
	for i := range fn.Calls {
		call := &fn.Calls[i]
		if call.Line != line || (startCol > 0 && (call.StartCol != startCol || call.EndCol != endCol)) || callgraph.BaseFunctionName(call.Callee.Name) != method || len(call.Arguments) != arity {
			continue
		}
		if match != nil {
			return nil
		}
		match = call
	}
	return match
}

// buildFragmentCallSite constructs the GraphFragmentCallSite for a
// call edge using BuildCallSiteParameters when a matching FunctionCall is found
// in the callerDecl. Returns nil when the call cannot be located (e.g. the
// callee is reachable only through the caller index, not through a recorded
// FunctionCall in the source).
func buildFragmentCallSite(ctx *Context, call *callgraph.FunctionCall) *graphfrag.GraphFragmentCallSite {
	if call == nil {
		return nil
	}
	params := BuildCallSiteParameters(ctx, call)
	if len(params) == 0 && call.Line == 0 {
		return nil
	}
	cs := &graphfrag.GraphFragmentCallSite{
		Line: call.Line,
	}
	for _, p := range params {
		cs.Parameters = append(cs.Parameters, ConvertCallGraphParameterToFragment(p))
	}
	return cs
}

// ConvertCallGraphParameterToFragment converts a CallGraphParameter into its
// graph-fragment GraphFragmentParameter.
func ConvertCallGraphParameterToFragment(p CallGraphParameter) graphfrag.GraphFragmentParameter {
	fp := graphfrag.GraphFragmentParameter{
		ParameterIndex:     p.ParameterIndex,
		Keyword:            p.Keyword,
		Type:               p.Type,
		VariableName:       p.VariableName,
		ArgumentExpression: p.ArgumentExpression,
		ResolvedValue:      p.ResolvedValue,
	}
	for i := range p.SourceNodes {
		fp.SourceNodes = append(fp.SourceNodes, convertExportSourceNodeToFragment(p.SourceNodes[i]))
	}
	return fp
}

// convertExportSourceNodeToFragment converts an ExportSourceNode into
// the equivalent GraphFragmentSourceNode (recursive).
func convertExportSourceNodeToFragment(n ExportSourceNode) graphfrag.GraphFragmentSourceNode {
	fsn := graphfrag.GraphFragmentSourceNode{
		Type:                n.Type,
		Name:                n.Name,
		DeclaredType:        n.DeclaredType,
		Value:               n.Value,
		CallTarget:          n.CallTarget,
		MayValues:           n.mayValues,
		MayValuesExhaustive: n.mayValuesExhaustive,
	}
	if n.ParameterIndex != nil {
		idx := *n.ParameterIndex
		fsn.ParameterIndex = &idx
	}
	if n.Location != nil {
		fsn.Location = &graphfrag.GraphFragmentSourceLoc{
			FilePath: n.Location.FilePath,
			Line:     n.Location.Line,
		}
	}
	for i := range n.SourceNodes {
		fsn.SourceNodes = append(fsn.SourceNodes, convertExportSourceNodeToFragment(n.SourceNodes[i]))
	}
	return fsn
}

func buildFragmentInternalEdge(
	ctx *Context,
	_ *callgraph.FunctionDecl,
	call *callgraph.FunctionCall,
	callerKey, calleeKey string,
	line int,
	res EdgeResolution,
) graphfrag.GraphFragmentEdge {
	edge := graphfrag.GraphFragmentEdge{
		CallerKey:            callerKey,
		CalleeKey:            calleeKey,
		Line:                 line,
		Resolution:           res.Resolution,
		DeclaredType:         res.DeclaredType,
		MethodName:           res.MethodName,
		Arity:                res.Arity,
		EntryCall:            buildFragmentCallSite(ctx, call),
		ResolvedReceiverType: res.ResolvedReceiverType,
		StartCol:             res.StartCol,
		EndCol:               res.EndCol,
	}
	if call != nil {
		edge.ReceiverVar = call.ReceiverVar
		edge.AssignedVar = call.AssignedVar
		edge.ChainID = call.ChainID
		if call.StartCol > 0 && call.EndCol > call.StartCol {
			edge.StartCol = call.StartCol
			edge.EndCol = call.EndCol
		}
		edge.EndLine = fragmentCallEndLine(call, edge.Line)
	}
	return edge
}

// BuildFragmentExternalCall returns the external call a call site makes, with its arguments and resolution.
func BuildFragmentExternalCall( //nolint:gocognit,gocyclo // one decision per way an external call can be keyed
	ctx *Context,
	callerDecl *callgraph.FunctionDecl,
	call *callgraph.FunctionCall,
	callerKey string,
	calleeKey string,
	line int,
	res EdgeResolution,
) graphfrag.GraphFragmentExternal {
	external := graphfrag.GraphFragmentExternal{
		CallerKey:            callerKey,
		TargetKey:            calleeKey,
		Line:                 line,
		Resolution:           res.Resolution,
		DeclaredType:         res.DeclaredType,
		MethodName:           res.MethodName,
		Arity:                res.Arity,
		EntryCall:            buildFragmentCallSite(ctx, call),
		ResolvedReceiverType: res.ResolvedReceiverType,
		StartCol:             res.StartCol,
		EndCol:               res.EndCol,
	}
	if call != nil {
		external.CandidateModules = call.CandidateModules
		if ctx != nil && ctx.Ecosystem == EcosystemCSharp {
			// A C# call into a dependency is keyed on the caller's own
			// namespace: the stitch needs the usings to find the owner the
			// dependency declares. Java fills the same field for its own
			// in-build reanchoring, and must not carry it.
			external.CandidateOwners = call.OwnerAlternatives
		}
	}
	// A Java or Go call whose receiver type the parser could not name (a
	// fluent chain on a dependency's return value, a method on an untyped
	// local, a call of a func value) has a bare target. Nothing in the graph
	// typed it, so it is a name_only call, not an exact one: a stitcher then
	// matches it by name and reads what it reaches as unknown, as the live
	// tracer does.
	if call != nil && ctx != nil && (ctx.Ecosystem == EcosystemJava || ctx.Ecosystem == EcosystemGo) &&
		external.Resolution == string(callgraph.EdgeKindExact) &&
		call.Callee.Type == "" && call.Callee.Package == "" {
		external.Resolution = string(callgraph.EdgeKindNameOnly)
		if external.MethodName == "" {
			external.MethodName = callgraph.BaseFunctionName(call.Callee.Name)
		}
		if external.Arity == 0 {
			external.Arity = len(call.Arguments)
		}
	}
	// A Go call on an interface value of a package outside the graph
	// (`w.Write` on an io.Writer) names no implementation: the one
	// that runs lives in whichever dependency built the value. As exact it
	// would join nothing and read what it reaches as unreachable; as
	// name_only it reads unknown.
	// A call on a type of a module the source roots lack (not in the module
	// cache) may be on an interface too, so it is exported the same way.
	if call != nil && ctx != nil && ctx.Ecosystem == EcosystemGo && external.Resolution == string(callgraph.EdgeKindExact) &&
		(ctx.Graph.GoInterfaceCall(call) || ctx.Graph.GoUnreadTypeCall(call)) {
		external.Resolution = string(callgraph.EdgeKindNameOnly)
		external.DeclaredType = call.Callee.Package + "." + strings.TrimLeft(call.Callee.Type, "*")
		if external.MethodName == "" {
			external.MethodName = callgraph.BaseFunctionName(call.Callee.Name)
		}
		if external.Arity == 0 {
			external.Arity = len(call.Arguments)
		}
	}
	// A Python call nothing typed (a method on a duck-typed receiver, a call
	// of a parameter) is keyed by the receiver's text in the caller's module,
	// a function no component declares. As exact, a stitcher would find no
	// target for it and read the dependency method it may reach as
	// unreachable; as name_only it matches by method name, and what it
	// reaches reads unknown.
	if call != nil && ctx != nil && external.Resolution == string(callgraph.EdgeKindExact) && callgraph.PythonCallUntyped(ctx.Graph, call) {
		external.Resolution = string(callgraph.EdgeKindNameOnly)
		external.Arity = len(call.Arguments)
	}
	external.TargetFunctionName = fragmentTargetFunctionName(ctx, callerKey, callerDecl, calleeKey, &external)
	if calleeID, err := callgraph.ParseFunctionID(calleeKey); err == nil { //nolint:nestif // the parsed and unparsed callee keys resolve differently
		meta := BuildExportFunctionMetadata(ctx.Graph, calleeID, nil)
		if call != nil && call.Callee.String() == calleeKey {
			meta, _ = BuildCallExportFunctionMetadata(ctx, call, nil)
		}
		parameterTypes := meta.ParameterTypes
		if external.EntryCall != nil {
			callTypes := make([]string, len(external.EntryCall.Parameters))
			for i := range external.EntryCall.Parameters {
				callTypes[i] = external.EntryCall.Parameters[i].Type
			}
			parameterTypes = MergeExportParameterTypes(parameterTypes, callTypes)
		}
		// A method declared in a type-only dependency has every overload in the
		// bytecode index; the per-function metadata above takes the first one of
		// any arity. Pick the overload this call's arguments select, so a reader
		// joining on the signature reaches the right declaration.
		if call != nil && call.Callee.String() == calleeKey && ctx.Graph != nil {
			sigs := ctx.Graph.ExternalMethodSignatures[callgraph.ExternalMethodSignatureKey(call.Callee)]
			if sig, ok := callgraph.SelectExternalOverload(sigs, call); ok {
				parameterTypes = append([]string(nil), sig.ParameterTypes...)
				// A constructor's bytecode return is void; keep the declared-type spelling.
				if rt := strings.TrimSpace(sig.ReturnType); rt != "" && call.Callee.Name != ConstructorMethodName {
					meta.ReturnType = rt
				}
			}
		}
		external.TargetCanonicalSignature = CanonicalSignature(meta.FunctionName, parameterTypes, meta.ReturnType)
	}
	if call != nil {
		external.Raw = call.Raw
		external.ReceiverVar = call.ReceiverVar
		external.AssignedVar = call.AssignedVar
		external.ChainID = call.ChainID
		if call.StartCol > 0 && call.EndCol > call.StartCol {
			external.StartCol = call.StartCol
			external.EndCol = call.EndCol
		}
		external.EndLine = fragmentCallEndLine(call, external.Line)
	}
	return external
}

func fragmentTargetFunctionName(
	ctx *Context,
	callerKey string,
	callerDecl *callgraph.FunctionDecl,
	calleeKey string,
	external *graphfrag.GraphFragmentExternal,
) string {
	targetName := ""
	if calleeID, err := callgraph.ParseFunctionID(calleeKey); err == nil {
		targetName = FullFunctionName(calleeID)
	}
	if call := findCallForCalleeAtLine(ctx, callerKey, callerDecl, calleeKey, external.Line); call != nil {
		external.Raw = call.Raw
		if targetName == "" {
			targetName = FullFunctionName(call.Callee)
		}
	}
	return targetName
}

// SortedKeys returns the keys of values in order.
func SortedKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// SortedFragmentEdges sorts internal edges in their exported order.
func SortedFragmentEdges(values []graphfrag.GraphFragmentEdge) []graphfrag.GraphFragmentEdge {
	if len(values) == 0 {
		return nil
	}
	sort.SliceStable(values, func(i, j int) bool {
		return fragmentEdgeLess(values[i], values[j])
	})
	out := values[:0]
	for i := range values {
		if i+1 < len(values) && FragmentEdgeSameKey(values[i], values[i+1]) {
			continue
		}
		out = append(out, values[i])
	}
	return out
}

// SortedFragmentExternalCalls sorts external calls in their exported order.
func SortedFragmentExternalCalls(values []graphfrag.GraphFragmentExternal) []graphfrag.GraphFragmentExternal {
	if len(values) == 0 {
		return nil
	}
	sort.SliceStable(values, func(i, j int) bool {
		return fragmentExternalLess(&values[i], &values[j])
	})
	out := values[:0]
	for i := range values {
		if i+1 < len(values) && fragmentExternalSameKey(&values[i], &values[i+1]) {
			continue
		}
		out = append(out, values[i])
	}
	return out
}

func fragmentEdgeLess(a, b graphfrag.GraphFragmentEdge) bool {
	if a.CallerKey != b.CallerKey {
		return a.CallerKey < b.CallerKey
	}
	if a.CalleeKey != b.CalleeKey {
		return a.CalleeKey < b.CalleeKey
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.StartCol != b.StartCol {
		return a.StartCol < b.StartCol
	}
	if a.EndCol != b.EndCol {
		return a.EndCol < b.EndCol
	}
	if a.Resolution != b.Resolution {
		return a.Resolution < b.Resolution
	}
	if a.DeclaredType != b.DeclaredType {
		return a.DeclaredType < b.DeclaredType
	}
	if a.MethodName != b.MethodName {
		return a.MethodName < b.MethodName
	}
	return a.Arity < b.Arity
}

// FragmentEdgeSameKey reports whether two edges are the same call site of the same caller and callee.
func FragmentEdgeSameKey(a, b graphfrag.GraphFragmentEdge) bool {
	return a.CallerKey == b.CallerKey &&
		a.CalleeKey == b.CalleeKey &&
		a.Line == b.Line &&
		a.StartCol == b.StartCol &&
		a.EndCol == b.EndCol &&
		a.Resolution == b.Resolution &&
		a.DeclaredType == b.DeclaredType &&
		a.MethodName == b.MethodName &&
		a.Arity == b.Arity
}

func fragmentExternalLess(a, b *graphfrag.GraphFragmentExternal) bool {
	if a.CallerKey != b.CallerKey {
		return a.CallerKey < b.CallerKey
	}
	if a.TargetKey != b.TargetKey {
		return a.TargetKey < b.TargetKey
	}
	if a.Line != b.Line {
		return a.Line < b.Line
	}
	if a.StartCol != b.StartCol {
		return a.StartCol < b.StartCol
	}
	if a.EndCol != b.EndCol {
		return a.EndCol < b.EndCol
	}
	if a.Resolution != b.Resolution {
		return a.Resolution < b.Resolution
	}
	if a.DeclaredType != b.DeclaredType {
		return a.DeclaredType < b.DeclaredType
	}
	if a.MethodName != b.MethodName {
		return a.MethodName < b.MethodName
	}
	return a.Arity < b.Arity
}

func fragmentExternalSameKey(a, b *graphfrag.GraphFragmentExternal) bool {
	return a.CallerKey == b.CallerKey &&
		a.TargetKey == b.TargetKey &&
		a.Line == b.Line &&
		a.StartCol == b.StartCol &&
		a.EndCol == b.EndCol &&
		a.Resolution == b.Resolution &&
		a.DeclaredType == b.DeclaredType &&
		a.MethodName == b.MethodName &&
		a.Arity == b.Arity
}

// resolveFragmentEdges returns the resolution metadata for a caller->callee edge.
// An edge with no recorded resolution is an exact, directly-resolved source
// call (e.g. a typed re-resolution from the bytecode/type resolver), so it
// defaults to exact rather than the fail-closed "unknown" — the producer is the
// authority on resolution quality. Such an edge gets one exact resolution per
// call site of the caller that names the callee (defaultFragmentEdgeResolutions),
// so every call is exported with its line, columns, method name and arity.
func resolveFragmentEdges(ctx *Context, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string) []EdgeResolution {
	if ctx != nil {
		if out := ctx.FragmentEdgeResolutions[FragmentEdgePairKey(callerKey, calleeKey)]; len(out) > 0 {
			return out
		}
	}
	return defaultFragmentEdgeResolutions(ctx, callerKey, callerDecl, calleeKey)
}

// defaultFragmentEdgeResolutions gives an edge without a recorded resolution
// one exact resolution per call of callerDecl that names calleeKey: the calls
// spelled as calleeKey, else the calls of its base method with its arity. With
// none of either it keeps one site without a position, which fragmentEdgeLine
// places at the first call of the method (an alias the graph added for a call
// written as another overload). Method name and arity come from calleeKey, as
// recordEdgeResolution derives them for a recorded edge.
func defaultFragmentEdgeResolutions(ctx *Context, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string) []EdgeResolution {
	base := callgraph.EdgeResolution{Kind: callgraph.EdgeKindExact}
	if calleeID, err := callgraph.ParseFunctionID(calleeKey); err == nil {
		base.MethodName = callgraph.BaseFunctionName(calleeID.Name)
		base.Arity = callgraph.FunctionArity(calleeID.Name)
	}
	candidates := matchingCallsForCallee(ctx, callerKey, callerDecl, calleeKey)
	var calls []*callgraph.FunctionCall
	for _, call := range candidates {
		if call.Callee.String() == calleeKey {
			calls = append(calls, call)
		}
	}
	if len(calls) == 0 {
		for _, call := range candidates {
			if len(call.Arguments) == base.Arity {
				calls = append(calls, call)
			}
		}
	}
	if len(calls) == 0 {
		return []EdgeResolution{NewFragmentEdgeResolution(base)}
	}
	out := make([]EdgeResolution, 0, len(calls))
	for _, call := range calls {
		res := base
		res.CallSite, res.StartCol, res.EndCol = call.Line, call.StartCol, call.EndCol
		out = append(out, NewFragmentEdgeResolution(res))
	}
	return out
}

// FragmentEdgePairKey is the index key of a caller and callee pair.
func FragmentEdgePairKey(callerKey, calleeKey string) string {
	return callerKey + "\x00" + calleeKey
}

// NewFragmentEdgeResolution carries an edge's resolution into the fragment.
// A Python subclass-dispatch edge (a base method's call reaching an override)
// is the fragment's interface_dispatch: the stitch has no other kind for an
// expansion to implementations, and decodes an unknown kind as untrusted and
// drops the edge.
func NewFragmentEdgeResolution(res callgraph.EdgeResolution) EdgeResolution {
	kind := res.Kind
	if kind == callgraph.EdgeKindPythonSubclassDispatch {
		kind = callgraph.EdgeKindInterfaceDispatch
	}
	return EdgeResolution{
		EdgeResolution: res,
		Resolution:     string(kind),
	}
}

func fragmentEdgeLine(ctx *Context, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string, res EdgeResolution) int {
	if res.CallSite != 0 {
		return res.CallSite
	}
	return findFragmentCallLine(ctx, callerKey, callerDecl, calleeKey)
}

func findFragmentCallLine(ctx *Context, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string) int {
	if callerDecl == nil {
		return 0
	}
	if call := findCallForCallee(ctx, callerKey, callerDecl, calleeKey); call != nil {
		return call.Line
	}
	return callerDecl.StartLine
}

// ChainIDForLine recovers the fluent-chain id for an edge whose exact callee
// lookup failed. The links of a fluent chain (e.g. Request.builder(u)
// .header(h).build()) all share the same line AND the same ChainID,
// but the intermediate links are often left unresolved in a standalone scan, so
// the resolved edge key diverges from the underlying FunctionCall.Callee and the
// key-based lookup misses. Recovering by line is safe precisely because every
// chained call on that line carries the SAME ChainID — picking any of them
// yields the correct group id. Returns "" when no chained call sits on the line.
func ChainIDForLine(fn *callgraph.FunctionDecl, line int) string {
	if fn == nil || line <= 0 {
		return ""
	}
	for i := range fn.Calls {
		if fn.Calls[i].Line == line && fn.Calls[i].ChainID != "" {
			return fn.Calls[i].ChainID
		}
	}
	return ""
}

// ChainIDForCallerLine returns the chain id of the chained call on line of the caller, memoized per caller.
func ChainIDForCallerLine(ctx *Context, callerKey string, fn *callgraph.FunctionDecl, line int) string {
	if ctx == nil {
		return ChainIDForLine(fn, line)
	}
	lineIndex, ok := ctx.ChainIDsByCallerLine.Lookup(callerKey)
	if !ok {
		lineIndex = make(map[int]string)
		if fn != nil {
			for i := range fn.Calls {
				call := &fn.Calls[i]
				if call.Line > 0 && call.ChainID != "" {
					lineIndex[call.Line] = call.ChainID
				}
			}
		}
		lineIndex = ctx.ChainIDsByCallerLine.Store(callerKey, lineIndex)
	}
	return lineIndex[line]
}

// findCallForCalleeAtLine finds callerKey's FunctionCall matching calleeKey,
// preferring the specific call at line when more than one call in the body
// matches (overload/dispatch fan-out can put several resolved edges on the
// same caller function). ctx may be nil (falls back to an unindexed scan of
// callerDecl.Calls, used by tests that construct a FunctionDecl directly
// without a full Context).
func findCallForCalleeAtLine(ctx *Context, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string, line int) *callgraph.FunctionCall {
	candidates := matchingCallsForCallee(ctx, callerKey, callerDecl, calleeKey)
	var fallback *callgraph.FunctionCall
	for _, call := range candidates {
		if line > 0 && call.Line == line {
			return call
		}
		if fallback == nil {
			fallback = call
		}
	}
	return fallback
}

// findCallForCalleeAtSite is findCallForCalleeAtLine for a site with known
// columns: among the matching calls on line it takes the one at startCol and
// endCol, so two calls of one callee on one line keep their own call.
//
// A Python callee keyed by a receiver's source text can hold `).` itself
// (`<module>.(load(x).decode("utf-8")).replace`), which the key parser
// splits at the wrong place, so the parsed index misses the call; for Python
// the call at the site is also looked up by its key as written.
func findCallForCalleeAtSite(ctx *Context, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string, line, startCol, endCol int) *callgraph.FunctionCall {
	if line > 0 && startCol > 0 {
		for _, call := range matchingCallsForCallee(ctx, callerKey, callerDecl, calleeKey) {
			if call.Line == line && call.StartCol == startCol && call.EndCol == endCol {
				return call
			}
		}
		if ctx != nil && ctx.Ecosystem == EcosystemPython {
			for i := range callerDecl.Calls {
				call := &callerDecl.Calls[i]
				if call.Line == line && call.StartCol == startCol && call.EndCol == endCol && call.Callee.String() == calleeKey {
					return call
				}
			}
		}
	}
	return findCallForCalleeAtLine(ctx, callerKey, callerDecl, calleeKey, line)
}

func findCallForCallee(ctx *Context, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string) *callgraph.FunctionCall {
	candidates := matchingCallsForCallee(ctx, callerKey, callerDecl, calleeKey)
	if len(candidates) == 0 {
		return nil
	}
	return candidates[0]
}

// matchingCallsForCallee returns every FunctionCall in callerDecl whose
// Callee has calleeKey's (Package, Type, BaseFunctionName) tuple (an exact
// FunctionID.String() match, or an overload/dispatch-expanded alias of the
// same source call site). An unparseable calleeKey falls back to an exact
// FunctionID.String() match, which cannot use the tuple index. Order is
// callerDecl.Calls order.
//
// When ctx is non-nil, this is backed by CallSignatureIndexForCaller's cached
// per-caller index instead of a fresh linear scan: on graphs with heavy
// dispatch fan-out (large interface hierarchies), the same caller is looked
// up once per resolved edge, so its calls are indexed once instead of scanned
// (and calleeKey reparsed) for every edge.
func matchingCallsForCallee(ctx *Context, callerKey string, callerDecl *callgraph.FunctionDecl, calleeKey string) []*callgraph.FunctionCall {
	if callerDecl == nil {
		return nil
	}
	sigKey, ok := CalleeSignatureKey(ctx, calleeKey)
	if !ok {
		// CalleeKey isn't parseable (should not happen for real graph keys,
		// which are always produced by FunctionID.String()), so fall back to an
		// exact string match rather than silently returning nothing.
		var matches []*callgraph.FunctionCall
		for i := range callerDecl.Calls {
			call := &callerDecl.Calls[i]
			if call.Callee.String() == calleeKey {
				matches = append(matches, call)
			}
		}
		return matches
	}
	if ctx != nil {
		index := CallSignatureIndexForCaller(ctx, callerKey, callerDecl)
		return index[sigKey]
	}

	var matches []*callgraph.FunctionCall
	for i := range callerDecl.Calls {
		call := &callerDecl.Calls[i]
		if callSignatureKey(call.Callee.Package, call.Callee.Type, callgraph.BaseFunctionName(call.Callee.Name)) == sigKey {
			matches = append(matches, call)
		}
	}
	return matches
}

// CalleeSignatureKey returns the (package, type, method) key calls to calleeKey are grouped under.
func CalleeSignatureKey(ctx *Context, calleeKey string) (string, bool) {
	if ctx != nil {
		sigKey, ok := ctx.CalleeSignatureKeys.Lookup(calleeKey)
		if !ok {
			if calleeID, err := callgraph.ParseFunctionID(calleeKey); err == nil {
				sigKey = callSignatureKey(calleeID.Package, calleeID.Type, callgraph.BaseFunctionName(calleeID.Name))
			}
			sigKey = ctx.CalleeSignatureKeys.Store(calleeKey, sigKey)
		}
		return sigKey, sigKey != ""
	}
	calleeID, err := callgraph.ParseFunctionID(calleeKey)
	if err != nil {
		return "", false
	}
	return callSignatureKey(calleeID.Package, calleeID.Type, callgraph.BaseFunctionName(calleeID.Name)), true
}

// callSignatureKey builds the (Package, Type, BaseFunctionName) grouping key
// CallSignatureIndexForCaller and matchingCallsForCallee's unindexed fallback
// both use. This is a coarser key than a full FunctionID: it deliberately
// ignores arity/overload decoration
// (a dispatch-expanded calleeKey targeting a different overload/arity of the
// same base method still resolves back to the ONE source call site).
func callSignatureKey(pkg, typ, baseName string) string {
	return pkg + "\x00" + typ + "\x00" + baseName
}

// CallSignatureIndexForCaller returns callerKey's Calls grouped by
// callSignatureKey, building and caching the index on first use. See
// Context.CallsBySignature.
func CallSignatureIndexForCaller(ctx *Context, callerKey string, callerDecl *callgraph.FunctionDecl) map[string][]*callgraph.FunctionCall {
	if index, ok := ctx.CallsBySignature.Lookup(callerKey); ok {
		return index
	}
	index := make(map[string][]*callgraph.FunctionCall, len(callerDecl.Calls))
	for i := range callerDecl.Calls {
		call := &callerDecl.Calls[i]
		key := callSignatureKey(call.Callee.Package, call.Callee.Type, callgraph.BaseFunctionName(call.Callee.Name))
		index[key] = append(index[key], call)
	}
	return ctx.CallsBySignature.Store(callerKey, index)
}

// BuildGraphFragmentFunction projects one call-graph function onto its
// graph-fragment representation. FilePath is relativized to the project root
// with NormalizeExportPath, as chain-frame paths are; a path outside every
// root is exported as given. The synthetic <clinit> function is relativized
// too.
func BuildGraphFragmentFunction(ctx *Context, id callgraph.FunctionID, decl *callgraph.FunctionDecl) graphfrag.GraphFragmentFunction {
	meta := BuildExportFunctionMetadata(ctx.Graph, id, decl)
	fn := graphfrag.GraphFragmentFunction{
		Key:                           id.String(),
		FunctionName:                  meta.FunctionName,
		CanonicalSignature:            meta.CanonicalSignature,
		ErasedSignature:               meta.ErasedSignature,
		CompatibleCanonicalSignatures: compatibleCanonicalSignatures(ctx, id, decl),
		Package:                       id.Package,
		Type:                          id.Type,
		Name:                          id.Name,
		ReturnType:                    meta.ReturnType,
		ParameterTypes:                meta.ParameterTypes,
		Visibility:                    meta.Visibility,
		OwnerVisibility:               meta.OwnerVisibility,
		DisplaySymbol:                 meta.DisplaySymbol,
		Aliases:                       CloneStringSlice(meta.Aliases),
	}
	if decl != nil {
		fn.FilePath = NormalizeExportPath(ctx, decl.FilePath).FilePath
		fn.StartLine = decl.StartLine
		fn.EndLine = decl.EndLine
		if ctx.Ecosystem == EcosystemNode {
			// graph-algo-node-9: a callback written on its caller's line is
			// told from the caller by these columns.
			fn.StartCol, fn.EndCol = decl.StartCol, decl.EndCol
		}
		fn.ReturnsCalls = returnedCallees(decl)
		fn.Abstract = decl.Abstract
		fn.Constructs = fragmentConstructs(ctx, decl)
		if FragmentCarriesCalls(ctx) {
			fn.ReturnSources = fragmentRawSources(ctx, decl.ReturnSources)
			fn.ParameterNames = fragmentParameterNames(decl.Parameters)
		}
		if ctx.Ecosystem == EcosystemCPP {
			// A C++ function context reads the parameters as written.
			for _, p := range decl.WrittenParameters {
				fn.WrittenParameters = append(fn.WrittenParameters, graphfrag.GraphFragmentWrittenParameter{
					Type: p.Type, Name: p.Name, Line: p.Line, StartCol: p.StartCol, EndCol: p.EndCol, EndLine: p.EndLine,
				})
			}
		}
		if mark, ok := SharedTracer(ctx).EntryPoint(decl, ctx.UserPackages); ok {
			fn.EntryKind = string(mark.Kind)
		}
	}
	return fn
}

// fragmentConstructs is the class every return of a Java function builds
// with a plain `new` (graph-fragment-1.39, graph-algo-40), as a stitch reads
// it to narrow a call on the function's result to that class's method. Empty
// for any other ecosystem and when a return yields anything else.
func fragmentConstructs(ctx *Context, decl *callgraph.FunctionDecl) string {
	if ctx.Ecosystem != EcosystemJava {
		return ""
	}
	class, ok := decl.ConstructedClass()
	if !ok {
		return ""
	}
	return graphfrag.ClassKey(class.Package, class.Type)
}

// compatibleCanonicalSignatures emits only source-hierarchy-proven parent
// callable signatures. The concrete declaration keeps its own canonical
// signature; these are additional join keys for interface/override clients.
func compatibleCanonicalSignatures(ctx *Context, id callgraph.FunctionID, decl *callgraph.FunctionDecl) []string {
	if ctx == nil || ctx.Graph == nil || decl == nil || id.Package == "" || id.Type == "" {
		return nil
	}
	method := callgraph.BaseFunctionName(id.Name)
	if method == "" || method == ConstructorMethodName || method == "<clinit>" {
		return nil
	}
	owner := id.Package + "." + id.Type
	return compatibleParentSignatures(ctx, hierarchyAncestors(combinedTypeHierarchy(ctx), owner), method, decl)
}

// combinedTypeHierarchy returns the bytecode hierarchy merged with edges
// recovered from source-declared extends/implements clauses (OwnerBases).
// Bytecode edges win on conflict; source edges only add what bytecode
// indexing never saw — in a source-only scan (no jars)
// that is the entire hierarchy.
func combinedTypeHierarchy(ctx *Context) map[string][]string { //nolint:gocognit,gocyclo // merges two hierarchies with their precedence rules
	if ctx.CombinedHierarchy != nil {
		return ctx.CombinedHierarchy
	}
	merged := make(map[string][]string, len(ctx.Graph.TypeHierarchy))
	for owner, bases := range ctx.Graph.TypeHierarchy {
		merged[owner] = bases
	}
	for owner, bases := range sourceTypeHierarchy(ctx.Graph) {
		existing := make(map[string]bool, len(merged[owner]))
		for _, base := range merged[owner] {
			existing[base] = true
		}
		for _, base := range bases {
			if !existing[base] {
				merged[owner] = append(merged[owner], base)
			}
		}
	}
	// A type that declares no method of its own (an interface that only
	// extends others: ConfigurableProcessor extends Processor)
	// never reaches sourceTypeHierarchy, which reads bases off declarations;
	// without its edge an implementation's ancestry stops at it. The parser's
	// supertypes record it; take each clause's single candidate this scan or
	// the bytecode knows.
	known := func(t string) bool {
		if _, ok := merged[t]; ok {
			return true
		}
		_, ok := ctx.Graph.SourceSupertypes[t]
		return ok
	}
	for owner, clauses := range ctx.Graph.SourceSupertypes {
		existing := make(map[string]bool, len(merged[owner]))
		for _, base := range merged[owner] {
			existing[base] = true
		}
		for _, clause := range clauses {
			chosen := ""
			for _, candidate := range strings.Split(clause, "|") {
				if candidate = strings.TrimSpace(candidate); candidate == "" || !known(candidate) {
					continue
				}
				if chosen != "" && chosen != candidate {
					chosen = ""
					break
				}
				chosen = candidate
			}
			if chosen != "" && chosen != owner && !existing[chosen] {
				existing[chosen] = true
				merged[owner] = append(merged[owner], chosen)
			}
		}
	}
	ctx.CombinedHierarchy = merged
	return merged
}

// sourceTypeHierarchy derives owner → base FQN edges from the extends/
// implements clauses the parser stamps on every declaration (OwnerBases).
// Bases are recorded as erased simple names, so each is resolved against the
// types declared in this scan: a same-package declaration wins, otherwise a
// name that is unique across the scan; an ambiguous or unknown name resolves
// to nothing rather than guessing.
func sourceTypeHierarchy(graph *callgraph.CallGraph) map[string][]string {
	if graph == nil {
		return nil
	}
	decls := collectSourceTypeDecls(graph)
	hierarchy := make(map[string][]string, len(decls.basesByOwner))
	for owner, bases := range decls.basesByOwner {
		hierarchy[owner] = decls.resolveBases(owner, bases)
	}
	return hierarchy
}

// sourceTypeDecls indexes the types declared in this scan: simple name →
// sorted owner FQNs, owner FQN → package, and owner FQN → declared base
// simple names.
type sourceTypeDecls struct {
	typesBySimple map[string][]string
	pkgByOwner    map[string]string
	basesByOwner  map[string]map[string]bool
}

func collectSourceTypeDecls(graph *callgraph.CallGraph) sourceTypeDecls {
	decls := sourceTypeDecls{
		typesBySimple: make(map[string][]string),
		pkgByOwner:    make(map[string]string),
		basesByOwner:  make(map[string]map[string]bool),
	}
	seenOwner := make(map[string]bool)
	for _, decl := range graph.Functions {
		if decl == nil || decl.ID.Package == "" || decl.ID.Type == "" {
			continue
		}
		owner := decl.ID.Package + "." + decl.ID.Type
		if !seenOwner[owner] {
			seenOwner[owner] = true
			simple := decl.ID.Type
			if dot := strings.LastIndex(simple, "."); dot >= 0 {
				simple = simple[dot+1:]
			}
			decls.typesBySimple[simple] = append(decls.typesBySimple[simple], owner)
			decls.pkgByOwner[owner] = decl.ID.Package
		}
		decls.recordBases(owner, decl.OwnerBases)
	}
	for simple := range decls.typesBySimple {
		sort.Strings(decls.typesBySimple[simple])
	}
	return decls
}

func (d sourceTypeDecls) recordBases(owner string, bases []string) {
	for _, base := range bases {
		if base == "" {
			continue
		}
		if d.basesByOwner[owner] == nil {
			d.basesByOwner[owner] = make(map[string]bool)
		}
		d.basesByOwner[owner][base] = true
	}
}

// resolveBases maps one owner's declared base simple names onto FQNs: a
// same-package declaration wins, otherwise a name unique across the scan; an
// ambiguous or unknown name resolves to nothing rather than guessing.
func (d sourceTypeDecls) resolveBases(owner string, bases map[string]bool) []string {
	resolvedSet := make(map[string]bool, len(bases))
	var out []string
	for base := range bases {
		resolved := d.resolveBase(owner, base)
		if resolved == "" || resolved == owner || resolvedSet[resolved] {
			continue
		}
		resolvedSet[resolved] = true
		out = append(out, resolved)
	}
	sort.Strings(out)
	return out
}

func (d sourceTypeDecls) resolveBase(owner, base string) string {
	candidates := d.typesBySimple[base]
	if len(candidates) == 1 {
		return candidates[0]
	}
	for _, candidate := range candidates {
		if d.pkgByOwner[candidate] == d.pkgByOwner[owner] {
			return candidate
		}
	}
	return ""
}

func hierarchyAncestors(hierarchy map[string][]string, owner string) []string {
	seen := map[string]bool{owner: true}
	pending := append([]string(nil), hierarchy[owner]...)
	var ancestors []string
	for len(pending) > 0 {
		parent := pending[0]
		pending = pending[1:]
		if parent == "" || seen[parent] {
			continue
		}
		seen[parent] = true
		ancestors = append(ancestors, parent)
		pending = append(pending, hierarchy[parent]...)
	}
	return ancestors
}

func compatibleParentSignatures(ctx *Context, parents []string, method string, decl *callgraph.FunctionDecl) []string {
	arity := len(decl.Parameters)
	compatible := make(map[string]bool)
	for _, parent := range parents {
		var sameArity, sameParams []*callgraph.FunctionDecl
		for _, candidate := range ctx.DeclsByMethod[method] {
			candidateID := candidate.Decl.ID
			if candidateID.Package+"."+candidateID.Type != parent || len(candidate.Decl.Parameters) != arity {
				continue
			}
			sameArity = append(sameArity, candidate.Decl)
			if sameErasedParameters(decl.Parameters, candidate.Decl.Parameters) {
				sameParams = append(sameParams, candidate.Decl)
			}
		}
		// An override has the parent's parameter types: when a parent overload
		// has them, the other overloads of that arity are not this method's parents.
		if len(sameParams) > 0 {
			sameArity = sameParams
		}
		for _, parentDecl := range sameArity {
			signature := BuildExportFunctionMetadata(ctx.Graph, parentDecl.ID, parentDecl).CanonicalSignature
			if signature != "" {
				compatible[signature] = true
			}
		}
	}
	if len(compatible) == 0 {
		return nil
	}
	out := make([]string, 0, len(compatible))
	for signature := range compatible {
		out = append(out, signature)
	}
	sort.Strings(out)
	return out
}

// sameErasedParameters reports whether two parameter lists have the same types
// by erased simple name (generics stripped, package dropped).
func sameErasedParameters(a, b []callgraph.FunctionParameter) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if erasedSimpleParam(a[i].Type) != erasedSimpleParam(b[i].Type) {
			return false
		}
	}
	return true
}

func erasedSimpleParam(t string) string {
	t = strings.TrimSpace(t)
	if i := strings.Index(t, "<"); i >= 0 {
		if j := strings.LastIndex(t, ">"); j > i {
			t = t[:i] + t[j+1:]
		}
	}
	t = strings.ReplaceAll(t, "...", "[]")
	if i := strings.LastIndex(t, "."); i >= 0 {
		t = t[i+1:]
	}
	return t
}

// FragmentExports is the graph's `exports` field: the public names a caller
// spells mapped to the function keys the graph declares them under -- Python's
// module exports, Node's package specifiers, the constant paths a Ruby
// component publishes, or the public paths of a Rust crate's `pub use` items,
// aliases and modules. A graph is one ecosystem, so one of them is filled.
func FragmentExports(graph *callgraph.CallGraph) map[string]string {
	switch {
	case len(graph.PythonExports) > 0:
		return graph.PythonExports
	case len(graph.NodePackageExports) > 0:
		return graph.NodePackageExports
	case len(graph.RustExports) > 0:
		return graph.RustExports
	}
	return graph.RubyExports
}

// IndexFragmentEdgeResolutions indexes the graph's edge resolutions by caller and callee, in a stable order.
func IndexFragmentEdgeResolutions(graph *callgraph.CallGraph) map[string][]EdgeResolution {
	if graph == nil || len(graph.EdgeResolutions) == 0 {
		return nil
	}
	index := make(map[string][]EdgeResolution)
	for key := range graph.EdgeResolutions {
		res := graph.EdgeResolutions[key]
		callerKey, calleeKey, ok := callgraph.EdgeResolutionEndpoints(key, res)
		if !ok {
			continue
		}
		pairKey := FragmentEdgePairKey(callerKey, calleeKey)
		index[pairKey] = append(index[pairKey], NewFragmentEdgeResolution(res))
	}
	// Deterministic per-pair variant order: EdgeResolutions is a map, so
	// insertion order above is random. Downstream emission sorts its final
	// edge lists, but a stable index keeps intermediate behavior (e.g. which
	// variant a line-match picks first) reproducible run to run.
	for pairKey := range index {
		values := index[pairKey]
		sort.Slice(values, func(i, j int) bool { return fragmentEdgeResolutionLess(values[i], values[j]) })
	}
	return index
}

func fragmentEdgeResolutionLess(a, b EdgeResolution) bool {
	if a.CallSite != b.CallSite {
		return a.CallSite < b.CallSite
	}
	if a.StartCol != b.StartCol {
		return a.StartCol < b.StartCol
	}
	if a.EndCol != b.EndCol {
		return a.EndCol < b.EndCol
	}
	if a.DeclaredType != b.DeclaredType {
		return a.DeclaredType < b.DeclaredType
	}
	if a.MethodName != b.MethodName {
		return a.MethodName < b.MethodName
	}
	if a.Arity != b.Arity {
		return a.Arity < b.Arity
	}
	return a.Kind < b.Kind
}
