// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/callgraph/contracts"
	"github.com/scanoss/reach/graphfrag"
	"github.com/scanoss/reach/purl"
)

// SourceNodeTypeParameter is a source node bound to a parameter of the containing function.
const SourceNodeTypeParameter = "PARAMETER"

// SourceNodeTypeValue is a source node holding a literal or constant value.
const SourceNodeTypeValue = "VALUE"

// SourceNodeTypeCallResult is a source node produced by a call.
const SourceNodeTypeCallResult = "CALL_RESULT"

// SourceNodeTypeField is a source node read from a field.
const SourceNodeTypeField = "FIELD"

// SourceNodeTypeVariable is a source node read from a local variable.
const SourceNodeTypeVariable = "VARIABLE"

// MaxExportSourceResolutionDepth bounds how far a value is traced back through its sources.
const MaxExportSourceResolutionDepth = 8

// ConstructorMethodName is the method name of a constructor in a function key.
const ConstructorMethodName = "<init>"

// ExportTypeRef is a structured Java type reference, optionally carrying
// nested generic parameters, beside the flat erased type name.
type ExportTypeRef struct {
	Name              string          `json:"name"`
	GenericParameters []ExportTypeRef `json:"generic_parameters,omitempty"`
}

// CallGraphParameter is one argument of a call site: its position, keyword, type, expression and where its value comes from.
type CallGraphParameter struct {
	ParameterIndex     int                `json:"parameter_index"`
	Keyword            string             `json:"keyword,omitempty"`
	Type               string             `json:"type,omitempty"`
	VariableName       string             `json:"variable_name,omitempty"`
	ArgumentExpression string             `json:"argument_expression,omitempty"`
	ResolvedValue      string             `json:"resolved_value,omitempty"`
	SourceNodes        []ExportSourceNode `json:"source_nodes,omitempty"`
}

// ExportSourceNode is one source of an argument's value: a parameter, a value, a call result, a field or a variable.
type ExportSourceNode struct {
	Type                     string                `json:"type"`
	Name                     string                `json:"name,omitempty"`
	DeclaredType             string                `json:"declared_type,omitempty"`
	Value                    string                `json:"value,omitempty"`
	ParameterIndex           *int                  `json:"parameter_index,omitempty"`
	CallTarget               string                `json:"call_target,omitempty"`
	CallTargetDisplaySymbol  string                `json:"call_target_display_symbol,omitempty"`
	CallTargetInferredReturn *ExportInferredReturn `json:"call_target_inferred_return,omitempty"`
	Location                 *ExportSourceLocation `json:"location,omitempty"`
	SourceNodes              []ExportSourceNode    `json:"source_nodes,omitempty"`
	returnValue              bool
	guard                    *callgraph.SourceGuard
	callArgument             bool
	// mayValues goes to the graph fragment only (GraphFragmentSourceNode.MayValues).
	mayValues            []string
	mayValuesExhaustive  bool
	sourceParameterIndex int
	// Runtime is the runtime input the node's value is read from. Its
	// children are the input's key or default, never its value.
	Runtime *callgraph.RuntimeSource `json:"-"`
}

// ExportSourceLocation is the file and line of a source node.
type ExportSourceLocation struct {
	FilePath string `json:"file_path,omitempty"`
	Line     int    `json:"line,omitempty"`
}

// SplitFunctionName extracts class and method from a fully qualified function name.
// e.g., "org.apache.http.client.HttpClientBuilder.build" → ("org.apache.http.client.HttpClientBuilder", "build").
func SplitFunctionName(fn string) (class, method string) {
	idx := strings.LastIndex(fn, ".")
	if idx < 0 {
		return "", fn
	}
	return fn[:idx], fn[idx+1:]
}

// ContractMatchesForCall returns the knowledge base contracts that name call's callee with arity arguments.
func ContractMatchesForCall(ctx *Context, call *callgraph.FunctionCall, arity int) []contracts.Contract {
	if ctx.KB == nil || call == nil {
		return nil
	}
	fqn := FullFunctionName(call.Callee)
	if ctx.KB.Ecosystem == "go" {
		// Go KBs key a method by the parser's own identity, pkg.(Type).Method
		// or pkg.(*Type).Method; FullFunctionName drops the receiver brackets.
		fqn = call.Callee.String()
	}
	if ctx.KB.Ecosystem != "c" {
		matches := ctx.KB.ContractsForTolerant(fqn, arity)
		if len(matches) == 0 && ctx.KB.Ecosystem == "cpp" && call.Callee.Type != "" && call.Callee.Linkage != callgraph.LinkageInternal && !hasCallDeclaration(ctx.Graph, call.Callee) {
			matches = ctx.KB.ContractsForTolerant(call.Callee.Type+"."+callgraph.BaseFunctionName(call.Callee.Name), arity)
		}
		if len(matches) == 0 && ctx.KB.Ecosystem == EcosystemJava {
			matches = inheritedContracts(ctx, fqn, arity)
		}
		return exactConditionalContracts(matches, call)
	}
	if exact := ctx.KB.ContractsFor(fqn, arity); len(exact) > 0 {
		return exactConditionalContracts(exact, call)
	}
	if ctx.Graph == nil {
		return nil
	}
	externalGlobal := call.Callee.Linkage == callgraph.LinkageExternal && ctx.Graph.Functions[call.Callee.String()] == nil
	return exactConditionalContracts(ctx.KB.ContractsForCFunction(fqn, arity, externalGlobal), call)
}

// inheritedContracts finds the contracts a Java method inherits when the KB
// declares it on a supertype of the called class rather than on the class
// itself. It walks the contract hierarchy breadth first and returns the
// nearest level that declares the method, so the most specific declaration
// wins. Constructors are not inherited.
func inheritedContracts(ctx *Context, fqn string, arity int) []contracts.Contract {
	class, method := SplitFunctionName(fqn)
	if class == "" || method == ConstructorMethodName || method == "<clinit>" {
		return nil
	}
	seen := map[string]bool{class: true}
	level := ctx.KB.Hierarchy[class]
	for len(level) > 0 {
		var matches []contracts.Contract
		var next []string
		for _, parent := range level {
			if seen[parent] {
				continue
			}
			seen[parent] = true
			matches = append(matches, ctx.KB.ContractsFor(parent+"."+method, arity)...)
			next = append(next, ctx.KB.Hierarchy[parent]...)
		}
		if len(matches) > 0 {
			return matches
		}
		level = next
	}
	return nil
}

func exactConditionalContracts(matches []contracts.Contract, call *callgraph.FunctionCall) []contracts.Contract {
	exact := MatchingConditionalContracts(matches, call)
	if len(exact) > 0 {
		return exact
	}
	return matches
}

func canonicalContractsForCall(matches []contracts.Contract, call *callgraph.FunctionCall) []contracts.Contract {
	if exact := MatchingConditionalContracts(matches, call); len(exact) > 0 {
		return exact
	}
	unconditional := make([]contracts.Contract, 0, len(matches))
	for i := range matches {
		if matches[i].When == nil {
			unconditional = append(unconditional, matches[i])
		}
	}
	return unconditional
}

// compatibleCanonicalContracts drops contracts whose declared primitive
// parameter is passed an object. A contract names one signature per arity, but
// a library may overload f(int) and f(Spec) on one arity, so stamping the
// contract's int onto f(new Spec(..)) would type the object as an int. Left
// unfilled, the argument is typed by its own source instead.
func compatibleCanonicalContracts(matches []contracts.Contract, call *callgraph.FunctionCall) []contracts.Contract {
	out := make([]contracts.Contract, 0, len(matches))
	for i := range matches {
		if !contractPrimitiveParametersContradicted(&matches[i], call) {
			out = append(out, matches[i])
		}
	}
	return out
}

func contractPrimitiveParametersContradicted(contract *contracts.Contract, call *callgraph.FunctionCall) bool {
	for index, expected := range contract.ParameterTypes {
		if index >= len(call.ArgumentSources) || !isPrimitiveTypeName(expected) {
			continue
		}
		if sourcesAreObjectReferences(call.ArgumentSources[index], 0) {
			return true
		}
	}
	return false
}

// sourcesAreObjectReferences reports whether any source of an argument is an
// object: a constructor result or a value declared with a reference type. A
// call's own arguments are not followed, since they say nothing about its
// result type.
func sourcesAreObjectReferences(nodes []callgraph.SourceNode, depth int) bool {
	if depth >= MaxSourceDepth {
		return false
	}
	for i := range nodes {
		node := &nodes[i]
		if node.Type == SourceNodeTypeCallResult {
			if node.CallTarget != nil && strings.HasSuffix(FullFunctionName(*node.CallTarget), ".<init>") {
				return true
			}
			continue
		}
		if declared := strings.TrimSpace(node.DeclaredType); declared != "" && !isPrimitiveTypeName(declared) && !isBoxedPrimitiveTypeName(declared) {
			return true
		}
		if sourcesAreObjectReferences(node.SourceNodes, depth+1) {
			return true
		}
	}
	return false
}

var primitiveTypeNames = map[string]struct{}{
	"int": {}, "long": {}, "short": {}, "byte": {}, "char": {}, "boolean": {}, "float": {}, "double": {},
}

func isPrimitiveTypeName(name string) bool {
	_, ok := primitiveTypeNames[name]
	return ok
}

func isBoxedPrimitiveTypeName(name string) bool {
	switch strings.TrimPrefix(name, "java.lang.") {
	case "Integer", "Long", "Short", "Byte", "Character", "Boolean", "Float", "Double":
		return true
	}
	return false
}

// MatchingConditionalContracts keeps the contracts of matches whose When condition holds for call: the argument at its index is one of its values.
func MatchingConditionalContracts(matches []contracts.Contract, call *callgraph.FunctionCall) []contracts.Contract {
	exact := make([]contracts.Contract, 0, len(matches))
	for i := range matches {
		condition := matches[i].When
		if condition == nil || condition.ArgIndex < 0 || condition.ArgIndex >= len(call.Arguments) {
			continue
		}
		argument := strings.TrimSpace(call.Arguments[condition.ArgIndex])
		if slices.ContainsFunc(condition.ArgValueIn, func(want string) bool {
			return argument == strings.TrimSpace(want)
		}) {
			exact = append(exact, matches[i])
		}
	}
	return exact
}

func hasCallDeclaration(graph *callgraph.CallGraph, id callgraph.FunctionID) bool {
	if graph == nil {
		return false
	}
	if graph.Functions[id.String()] != nil {
		return true
	}
	id.Name = callgraph.BaseFunctionName(id.Name)
	return graph.Functions[id.String()] != nil
}

// MergeCallParameters combines declared parameter types, argument expressions,
// and argument source traces into a unified parameters array.
func MergeCallParameters( //nolint:gocognit // one pass merging call arguments with their declared parameters
	ctx *Context,
	callerID *callgraph.FunctionID,
	calleeID *callgraph.FunctionID,
	callee *callgraph.FunctionDecl,
	args []string,
	argSources [][]callgraph.SourceNode,
	sourceFilePath string,
	sourceLine int,
) []CallGraphParameter {
	typeCount := 0
	if callee != nil {
		typeCount = len(callee.Parameters)
	}
	size := typeCount
	if len(args) > size {
		size = len(args)
	}
	if size == 0 {
		return nil
	}

	params := make([]CallGraphParameter, 0, size)
	for i := range size {
		p := CallGraphParameter{ParameterIndex: i}
		var expr string
		if i < len(args) {
			expr = strings.TrimSpace(args[i])
		}
		if keyword, value := SplitKeywordArgument(expr, ctx.Ecosystem); keyword != "" {
			p.Keyword, expr = keyword, value
			p.Type = PythonKeywordParameterType(callee, keyword)
		} else {
			p.Type = resolveExportParameterType(ctx.Graph, calleeID, callee, i)
		}
		if i < len(args) {
			p.ArgumentExpression = expr
			if IsSimpleIdentifier(expr) {
				p.VariableName = expr
			}
		}
		if i < len(argSources) && len(argSources[i]) > 0 {
			p.SourceNodes = convertSourceNodes(ctx, resolveExportSourceNodes(ctx, callerID, argSources[i], 0), filepath.ToSlash(sourceFilePath), sourceLine)
		}
		if p.Type == "" {
			p.Type = uniqueSourceDeclaredType(p.SourceNodes)
		}
		p.ResolvedValue = ResolveSimpleExportParameterValue(p.ArgumentExpression, p.SourceNodes)
		if p.Type != "" || p.VariableName != "" || p.ArgumentExpression != "" {
			params = append(params, p)
		}
	}
	return params
}

// resolveExportSourceNodes follows simple parameter pass-through and return
// paths before serializing provenance. It keeps every candidate so a dynamic
// selector remains unresolved instead of choosing an arbitrary caller value.
func resolveExportSourceNodes(ctx *Context, ownerID *callgraph.FunctionID, nodes []callgraph.SourceNode, depth int) []callgraph.SourceNode {
	if ctx == nil || ctx.Graph == nil || depth >= MaxExportSourceResolutionDepth || len(nodes) == 0 {
		return cloneCallgraphSourceNodes(nodes)
	}

	resolved := cloneCallgraphSourceNodes(nodes)
	for i := range resolved {
		node := &resolved[i]
		switch node.Type {
		case SourceNodeTypeParameter:
			node.SourceNodes = append(node.SourceNodes, resolveIncomingParameterSources(ctx, ownerID, node.Name, node.ParameterIndex, depth+1)...)
		case SourceNodeTypeCallResult:
			node.SourceNodes = resolveExportSourceNodes(ctx, ownerID, node.SourceNodes, depth+1)
			node.SourceNodes = append(node.SourceNodes, ResolveCalleeReturnSources(ctx, node, depth+1)...)
		case SourceNodeTypeField:
			// A field's nested PARAMETER provenance may describe constructor
			// initialization, not the current method's argument list.
			node.SourceNodes = resolveExportSourceNodes(ctx, nil, node.SourceNodes, depth+1)
		default:
			node.SourceNodes = resolveExportSourceNodes(ctx, ownerID, node.SourceNodes, depth+1)
		}
	}
	return resolved
}

// ResolveCalleeReturnSources inlines the return provenance of a call result's
// target. A target already being inlined on the current path is skipped, so a
// recursive method contributes its returns once instead of once per level.
func ResolveCalleeReturnSources(ctx *Context, node *callgraph.SourceNode, depth int) []callgraph.SourceNode {
	if node.CallTarget == nil {
		return nil
	}
	targetKey := node.CallTarget.String()
	callee := ctx.Graph.Functions[targetKey]
	if callee == nil || ctx.ReturnInlining[targetKey] {
		return nil
	}
	if ctx.ReturnInlining == nil {
		ctx.ReturnInlining = make(map[string]bool)
	}
	ctx.ReturnInlining[targetKey] = true
	defer delete(ctx.ReturnInlining, targetKey)

	returns := selectGuardedReturnSources(callee.ReturnSources, node.SourceNodes)
	for i := range returns {
		// The selected nodes share their Flow with the callee's own return
		// sources: mark a copy. Writing through the shared one would change
		// the graph for later exports and race with the parallel edge build.
		flow := callgraph.SourceFlow{}
		if returns[i].Flow != nil {
			flow = *returns[i].Flow
		}
		flow.ReturnValue = true
		returns[i].Flow = &flow
	}
	return resolveExportSourceNodes(ctx, node.CallTarget, returns, depth)
}

func resolveIncomingParameterSources(ctx *Context, calleeID *callgraph.FunctionID, parameterName string, parameterIndex, depth int) []callgraph.SourceNode {
	if calleeID == nil || parameterIndex < 0 || depth >= MaxExportSourceResolutionDepth {
		return nil
	}
	if callee := ctx.Graph.Functions[calleeID.String()]; callee != nil && parameterIndex < len(callee.Parameters) &&
		callee.Parameters[parameterIndex].Name != "" && callee.Parameters[parameterIndex].Name != parameterName {
		return nil
	}

	// Prefer a once-built reverse index over scanning every function per hop.
	// A graph may omit graph.Callers, so the index also reads Functions[].Calls.
	calleeKey := calleeID.String()
	var agreed IncomingAgreement
	for _, callerKey := range ReverseCallersOf(ctx, calleeKey) {
		caller := ctx.Graph.Functions[callerKey]
		if caller == nil {
			continue
		}
		if !agreeAtCaller(ctx, caller, calleeKey, parameterName, parameterIndex, depth, &agreed) {
			return nil
		}
	}
	return agreed.First
}

// agreeAtCaller feeds agreed the provenance each of caller's calls to
// calleeKey passes for the parameter. It reports false once no agreed
// provenance can exist: a call site whose value is unknown, or values that
// disagree.
func agreeAtCaller(ctx *Context, caller *callgraph.FunctionDecl, calleeKey, parameterName string, parameterIndex, depth int, agreed *IncomingAgreement) bool {
	for i := range caller.Calls {
		call := &caller.Calls[i]
		if call.Callee.String() != calleeKey {
			continue
		}
		slot, ok := ArgumentSlot(len(call.Arguments), func(i int) string { return call.Arguments[i] }, parameterIndex, parameterName)
		if !ok {
			// This call site's value is unknown, so no agreed value exists.
			return false
		}
		if slot >= len(call.ArgumentSources) {
			continue
		}
		if !agreed.Add(func() []callgraph.SourceNode {
			return resolveExportSourceNodes(ctx, &caller.ID, call.ArgumentSources[slot], depth+1)
		}) {
			return false
		}
	}
	return true
}

// IncomingAgreement picks the provenance of a parameter from its call sites,
// fed in caller order. One call site is its provenance. Several call sites
// count only when every one of them passes the same constant (a literal, or a
// constant the graph folded to one), and then the first site stands for them
// all. Call sites that pass different values, or any value the graph cannot
// fold, give no provenance: picking one would invent the value of the others.
//
// Add stops the walk at the first call site that rules agreement out, and
// resolves a site only when its value can still decide the outcome, so a
// callee with many call sites does not resolve every one for each edge that
// reads it.
type IncomingAgreement struct {
	First []callgraph.SourceNode
	value string
	sites int
}

// Add records one more call site whose provenance resolve computes. It
// reports false once no agreed provenance can exist, whatever sites follow.
func (a *IncomingAgreement) Add(resolve func() []callgraph.SourceNode) bool {
	a.sites++
	switch a.sites {
	case 1:
		a.First = resolve()
		return true
	case 2:
		value, ok := resolveSimpleCallgraphSourceValue(a.First)
		if !ok {
			return false
		}
		a.value = value
	}
	value, ok := resolveSimpleCallgraphSourceValue(resolve())
	return ok && value == a.value
}

// ReverseCallersOf returns the sorted caller function keys of a callee. The
// slice is the shared index's own: callers must not modify it.
func ReverseCallersOf(ctx *Context, calleeKey string) []string {
	if ctx == nil || ctx.Graph == nil || calleeKey == "" {
		return nil
	}
	if ctx.CallsReverseIndex == nil {
		ctx.CallsReverseIndex = buildCallsReverseIndex(ctx.Graph)
	}
	return ctx.CallsReverseIndex[calleeKey]
}

func buildCallsReverseIndex(graph *callgraph.CallGraph) map[string][]string {
	index := make(map[string][]string)
	seen := make(map[string]map[string]bool)
	add := func(calleeKey, callerKey string) {
		if calleeKey == "" || callerKey == "" {
			return
		}
		if seen[calleeKey] == nil {
			seen[calleeKey] = make(map[string]bool)
		}
		if seen[calleeKey][callerKey] {
			return
		}
		seen[calleeKey][callerKey] = true
		index[calleeKey] = append(index[calleeKey], callerKey)
	}
	for callerKey, fn := range graph.Functions {
		if fn == nil {
			continue
		}
		idKey := fn.ID.String()
		if idKey == "" {
			idKey = callerKey
		}
		for i := range fn.Calls {
			add(fn.Calls[i].Callee.String(), idKey)
		}
	}
	for calleeKey, callers := range graph.Callers {
		for _, callerKey := range callers {
			add(calleeKey, callerKey)
		}
	}
	for _, callers := range index {
		sort.Strings(callers)
	}
	return index
}

//nolint:gocognit // Guard matching must distinguish exact, default, and unresolved branches without guessing.
func selectGuardedReturnSources(returns, arguments []callgraph.SourceNode) []callgraph.SourceNode {
	if len(returns) == 0 {
		return nil
	}
	values := make(map[int]string)
	for i := range arguments {
		if value, ok := resolveSimpleCallgraphSourceValue([]callgraph.SourceNode{arguments[i]}); ok {
			values[arguments[i].ParameterIndex] = NormalizeSelectorValue(value)
		}
	}

	matched := make(map[int]bool)
	for i := range returns {
		guard := sourceNodeGuard(&returns[i])
		if guard == nil || guard.Default {
			continue
		}
		if value, ok := values[guard.ParameterIndex]; ok && value == NormalizeSelectorValue(guard.Value) {
			matched[guard.ParameterIndex] = true
		}
	}

	selected := make([]callgraph.SourceNode, 0, len(returns))
	for i := range returns {
		source := &returns[i]
		guard := sourceNodeGuard(source)
		if guard == nil {
			selected = append(selected, *source)
			continue
		}
		value, known := values[guard.ParameterIndex]
		if !known {
			selected = append(selected, *source)
			continue
		}
		if guard.Default {
			if !matched[guard.ParameterIndex] {
				selected = append(selected, *source)
			}
			continue
		}
		if value == NormalizeSelectorValue(guard.Value) {
			selected = append(selected, *source)
		}
	}
	return selected
}

func sourceNodeGuard(node *callgraph.SourceNode) *callgraph.SourceGuard {
	if node == nil || node.Flow == nil {
		return nil
	}
	return node.Flow.Guard
}

func resolveSimpleCallgraphSourceValue(nodes []callgraph.SourceNode) (string, bool) {
	if len(nodes) == 0 {
		return "", false
	}
	var resolved string
	for i := range nodes {
		node := &nodes[i]
		if _, runtime := node.RuntimeSource(); runtime {
			return "", false
		}
		value := strings.TrimSpace(node.Value)
		ok := node.Type == SourceNodeTypeValue && value != ""
		if !ok && len(node.SourceNodes) > 0 {
			value, ok = resolveSimpleCallgraphSourceValue(node.SourceNodes)
		}
		if !ok {
			return "", false
		}
		if resolved == "" {
			resolved = value
		} else if resolved != value {
			return "", false
		}
	}
	return resolved, resolved != ""
}

// NormalizeSelectorValue strips the quotes around a string literal; see
// NormalizeValue.
func NormalizeSelectorValue(value string) string {
	return NormalizeValue(value)
}

// NormalizeValue strips the quotes around a string literal: double quotes
// (Java, Go, C), single quotes (Python, JavaScript, Ruby) and a backtick
// template without interpolation. A template with ${...} is not a constant and
// stays as written.
func NormalizeValue(value string) string {
	value = strings.TrimSpace(value)
	if len(value) < 2 || value[0] != value[len(value)-1] {
		return value
	}
	switch value[0] {
	case '"', '\'':
		return value[1 : len(value)-1]
	case '`':
		if !strings.Contains(value, "${") {
			return value[1 : len(value)-1]
		}
	}
	return value
}

func cloneCallgraphSourceNodes(nodes []callgraph.SourceNode) []callgraph.SourceNode {
	if len(nodes) == 0 {
		return nil
	}
	cloned := make([]callgraph.SourceNode, len(nodes))
	for i := range nodes {
		cloned[i] = nodes[i]
		cloned[i].SourceNodes = cloneCallgraphSourceNodes(nodes[i].SourceNodes)
		if nodes[i].CallTarget != nil {
			target := *nodes[i].CallTarget
			cloned[i].CallTarget = &target
		}
		if nodes[i].Location != nil {
			location := *nodes[i].Location
			cloned[i].Location = &location
		}
		if nodes[i].Flow != nil {
			flow := *nodes[i].Flow
			cloned[i].Flow = &flow
			if nodes[i].Flow.Guard != nil {
				guard := *nodes[i].Flow.Guard
				cloned[i].Flow.Guard = &guard
			}
		}
	}
	return cloned
}

// convertSourceNodes converts internal SourceNode to export format.
func convertSourceNodes(ctx *Context, nodes []callgraph.SourceNode, defaultFilePath string, defaultLine int) []ExportSourceNode {
	if len(nodes) == 0 {
		return nil
	}
	result := make([]ExportSourceNode, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		result[i] = ExportSourceNode{
			Type:                 n.Type,
			Name:                 n.Name,
			DeclaredType:         n.DeclaredType,
			Value:                n.Value,
			SourceNodes:          convertSourceNodes(ctx, n.SourceNodes, defaultFilePath, defaultLine),
			returnValue:          n.Flow != nil && n.Flow.ReturnValue,
			guard:                sourceNodeGuard(n),
			callArgument:         n.Flow != nil && n.Flow.CallArgument,
			sourceParameterIndex: n.ParameterIndex,
			Runtime:              exportRuntimeSource(n),
			mayValues:            n.MayValues,
			mayValuesExhaustive:  n.MayValuesExhaustive,
		}
		if n.Type == SourceNodeTypeParameter {
			idx := n.ParameterIndex
			result[i].ParameterIndex = &idx
		}
		if n.CallTarget != nil {
			result[i].CallTarget = FullFunctionName(*n.CallTarget)
			result[i].CallTargetDisplaySymbol = graphfrag.ConstructorDisplayFromSymbol(result[i].CallTarget)
			// Decorate CALL_RESULT nodes with the call target's inferred return
			// type when it differs from its declared one, so argument provenance
			// carries it even when the target is not itself exported.
			// resolveCallTargetInferredReturn checks the node type internally.
			result[i].CallTargetInferredReturn = resolveCallTargetInferredReturn(ctx, n.CallTarget, n.Type)
		}
		loc := &ExportSourceLocation{
			FilePath: defaultFilePath,
			Line:     defaultLine,
		}
		if n.Location != nil {
			if n.Location.FilePath != "" {
				loc.FilePath = NormalizeExportPath(ctx, n.Location.FilePath).FilePath
			}
			if n.Location.Line > 0 {
				loc.Line = n.Location.Line
			}
		}
		if loc.FilePath != "" || loc.Line > 0 {
			result[i].Location = loc
		}
	}
	return result
}

// resolveCallTargetInferredReturn looks up the target function's InferredReturn
// in the call graph and returns an ExportInferredReturn for it, or nil when:
//   - the nodeType is not "CALL_RESULT",
//   - the target function is not in the graph,
//   - no inference result exists,
//   - the origin is join-failed, or
//   - the inferred type equals the function's declared return type.
func resolveCallTargetInferredReturn(ctx *Context, target *callgraph.FunctionID, nodeType string) *ExportInferredReturn {
	if nodeType != SourceNodeTypeCallResult {
		return nil
	}
	if ctx == nil || ctx.Graph == nil || target == nil {
		return nil
	}
	fn := ctx.Graph.Functions[target.String()]
	if fn == nil || fn.InferredReturn == nil {
		return nil
	}
	ir := fn.InferredReturn
	if ir.Origin == "join-failed" {
		return nil
	}
	// An inferred type equal to the declared return type adds nothing.
	if strings.TrimSpace(ir.Type) == strings.TrimSpace(fn.ReturnType) {
		return nil
	}
	return &ExportInferredReturn{
		Type:       ir.Type,
		TypeRef:    exportTypeRefFromCallgraph(ir.TypeRef),
		Confidence: ir.Confidence,
		Origin:     ir.Origin,
		Provenance: convertInferredReturnProvenance(ir.Provenance),
	}
}

// ResolveSimpleExportParameterValue returns the constant value of an argument, from its source nodes or its expression, or "" when it has none.
func ResolveSimpleExportParameterValue(expr string, sourceNodes []ExportSourceNode) string {
	if value, ok := resolveSimpleExportSourceValue(sourceNodes); ok {
		return value
	}
	if len(ExportRuntimeSources(sourceNodes)) > 0 {
		// process.env.MODE reads like an enum constant, but its value is the
		// environment's.
		return ""
	}

	expr = strings.TrimSpace(expr)
	switch {
	case expr == "":
		return ""
	case strings.HasPrefix(expr, "\"") && strings.HasSuffix(expr, "\""):
		return expr
	case expr == "true" || expr == "false":
		return expr
	case LooksLikeIntegerLiteralExpr(expr):
		return expr
	case looksLikeEnumConstantExpr(expr):
		return expr
	default:
		return ""
	}
}

func resolveExportParameterType(
	graph *callgraph.CallGraph,
	calleeID *callgraph.FunctionID,
	callee *callgraph.FunctionDecl,
	index int,
) string {
	if callee != nil && index < len(callee.Parameters) {
		if typeName := strings.TrimSpace(callee.Parameters[index].Type); typeName != "" {
			return typeName
		}
	}
	if graph == nil || calleeID == nil || graph.ExternalMethodSignatures == nil {
		return ""
	}

	signatures := graph.ExternalMethodSignatures[callgraph.ExternalMethodSignatureKey(*calleeID)]
	for _, sig := range signatures {
		if index >= len(sig.ParameterTypes) {
			continue
		}
		if typeName := strings.TrimSpace(sig.ParameterTypes[index]); typeName != "" {
			return typeName
		}
	}
	return ""
}

func resolveSimpleExportSourceValue(nodes []ExportSourceNode) (string, bool) {
	if len(nodes) == 0 {
		return "", false
	}

	var resolved string
	for i := range nodes {
		value, ok := ResolveSimpleExportSourceValueNode(nodes[i])
		if !ok {
			return "", false
		}
		if resolved == "" {
			resolved = value
			continue
		}
		if resolved != value {
			return "", false
		}
	}

	if resolved == "" {
		return "", false
	}
	return resolved, true
}

// ResolveSimpleExportSourceValueNode returns the constant value of one source node, if it has one.
func ResolveSimpleExportSourceValueNode(node ExportSourceNode) (string, bool) {
	if node.Runtime != nil {
		return "", false
	}
	switch node.Type {
	case SourceNodeTypeValue:
		value := strings.TrimSpace(node.Value)
		if value == "" {
			value = strings.TrimSpace(node.Name)
		}
		if value == "" {
			return "", false
		}
		return value, true
	case SourceNodeTypeVariable, SourceNodeTypeField, SourceNodeTypeParameter:
		return resolveSimpleExportSourceValue(node.SourceNodes)
	case SourceNodeTypeCallResult:
		return resolveDirectExportReturnValue(node.SourceNodes)
	default:
		return "", false
	}
}

func resolveDirectExportReturnValue(nodes []ExportSourceNode) (string, bool) {
	if value, handled := resolveGuardedDirectReturnValue(nodes); handled {
		return value, value != ""
	}
	hasMarkedReturn := false
	for i := range nodes {
		if nodes[i].returnValue {
			hasMarkedReturn = true
			break
		}
	}
	var value string
	for i := range nodes {
		if hasMarkedReturn && !nodes[i].returnValue {
			continue
		}
		if nodes[i].Type != SourceNodeTypeValue {
			continue
		}
		candidate := strings.TrimSpace(nodes[i].Value)
		if candidate == "" || (value != "" && value != candidate) {
			return "", false
		}
		value = candidate
	}
	return value, value != ""
}

//nolint:gocognit,gocyclo // Mirrors guarded-source selection after path enrichment, retaining all ambiguous candidates.
func resolveGuardedDirectReturnValue(nodes []ExportSourceNode) (string, bool) {
	hasGuard := false
	arguments := make(map[int]string)
	for i := range nodes {
		if nodes[i].guard != nil {
			hasGuard = true
		}
		if nodes[i].callArgument {
			if value, ok := ResolveSimpleExportSourceValueNode(nodes[i]); ok {
				arguments[nodes[i].sourceParameterIndex] = NormalizeSelectorValue(value)
			}
		}
	}
	if !hasGuard {
		return "", false
	}

	matched := make(map[int]bool)
	for i := range nodes {
		guard := nodes[i].guard
		if guard == nil || guard.Default {
			continue
		}
		if value, ok := arguments[guard.ParameterIndex]; ok && value == NormalizeSelectorValue(guard.Value) {
			matched[guard.ParameterIndex] = true
		}
	}
	var selected []ExportSourceNode
	for i := range nodes {
		guard := nodes[i].guard
		if guard == nil {
			continue
		}
		value, known := arguments[guard.ParameterIndex]
		if !known {
			selected = append(selected, nodes[i])
			continue
		}
		if guard.Default {
			if !matched[guard.ParameterIndex] {
				selected = append(selected, nodes[i])
			}
			continue
		}
		if value == NormalizeSelectorValue(guard.Value) {
			selected = append(selected, nodes[i])
		}
	}
	returnValue := ""
	for i := range selected {
		value, ok := ResolveSimpleExportSourceValueNode(selected[i])
		if !ok || (returnValue != "" && returnValue != value) {
			return "", true
		}
		returnValue = value
	}
	return returnValue, true
}

// LooksLikeIntegerLiteralExpr reports whether expr is a decimal integer literal, optionally signed or with a trailing L.
func LooksLikeIntegerLiteralExpr(expr string) bool {
	expr = strings.TrimSpace(strings.TrimSuffix(expr, "L"))
	if expr == "" {
		return false
	}
	for i, r := range expr {
		if i == 0 && (r == '+' || r == '-') {
			continue
		}
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func looksLikeEnumConstantExpr(expr string) bool {
	expr = strings.TrimSpace(expr)
	dot := strings.LastIndex(expr, ".")
	if dot <= 0 || dot >= len(expr)-1 {
		return false
	}
	suffix := expr[dot+1:]
	for i, r := range suffix {
		if (r >= 'A' && r <= 'Z') || r == '_' || (i > 0 && r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

// SharedTracer returns the export's tracer, creating it on first use.
func SharedTracer(ctx *Context) *callgraph.Tracer {
	if ctx.Tracer == nil {
		ctx.Tracer = callgraph.NewTracer(ctx.Graph, ctx.PackageSeparator)
		ctx.Tracer.SetModuleFunc(func(key string) string { return TraceModule(ctx, key) })
		ctx.Tracer.SetProjectRoot(ctx.ProjectRoot)
	}
	return ctx.Tracer
}

// TraceModule classifies routes by the module each frame shows as
// dependency_info.
func TraceModule(ctx *Context, key string) string {
	decl := ctx.Graph.Functions[key]
	if decl == nil {
		return ""
	}
	if info := NormalizeExportPath(ctx, decl.FilePath).DependencyInfo; info != nil {
		return info.Module
	}
	return ""
}

// ArgumentSlot is the position, among a call's n arguments, of the argument
// that fills the callee parameter declared at index with name: the keyword
// argument naming it (Python `mode="fast"`), else the argument at index when
// every argument up to it is positional. ok is false when no argument provably
// fills the parameter: a keyword argument, a Python `*args` or a JavaScript
// `...args` spread sits in the way. A JavaScript `f(a = v)` reads as a keyword
// argument; the Node parser gives an assignment argument no sources, so the
// misreading loses that call's value and never borrows another's.
func ArgumentSlot(n int, expression func(int) string, index int, name string) (slot int, ok bool) {
	if name != "" {
		for i := range n {
			if keyword := slotKeyword(expression(i)); keyword == name {
				return i, true
			}
		}
	}
	if index < 0 || index >= n {
		return 0, false
	}
	for i := 0; i <= index; i++ {
		expr := strings.TrimSpace(expression(i))
		if slotKeyword(expr) != "" || strings.HasPrefix(expr, "*") || strings.HasPrefix(expr, "...") {
			return 0, false
		}
	}
	return index, true
}

// slotKeyword is the Python keyword an argument names. A JavaScript arrow
// function such as `x => x.trim()` also matches `name = value`, but no Python
// keyword value starts with `>`.
func slotKeyword(expr string) string {
	keyword, value := SplitKeywordArgument(expr, EcosystemPython)
	if strings.HasPrefix(value, ">") {
		return ""
	}
	return keyword
}

// ExportInferredReturn is a function's inferred return type as the export
// metadata carries it. It is nil when no inference fires or when the internal
// origin is "join-failed".
//
// "join-failed" is an internal origin and MUST NOT appear in exported
// output. When a join fails, InferredReturn is nil
// or its Origin is "join-failed"; the export layer treats both as absent.
type ExportInferredReturn struct {
	Type       string             `json:"type"`
	TypeRef    *ExportTypeRef     `json:"type_ref,omitempty"`
	Confidence string             `json:"confidence"`
	Origin     string             `json:"origin"`
	Provenance []ExportSourceNode `json:"provenance,omitempty"`
}

// ExportFunctionMetadata is a function's display name, signatures, return type and parameter types as exported.
type ExportFunctionMetadata struct {
	FunctionName       string
	CanonicalSignature string
	ErasedSignature    string
	ReturnType         string
	ReturnTypeRef      *ExportTypeRef
	ParameterTypes     []string
	ParameterTypeRefs  []ExportTypeRef
	Visibility         string
	OwnerVisibility    string
	DisplaySymbol      string
	Aliases            []string
	InferredReturn     *ExportInferredReturn
}

// BuildExportFunctionMetadata returns the exported metadata of the function id declares.
func BuildExportFunctionMetadata(
	graph *callgraph.CallGraph,
	id callgraph.FunctionID,
	decl *callgraph.FunctionDecl,
) ExportFunctionMetadata {
	meta := ExportFunctionMetadata{
		FunctionName: FullFunctionName(id),
	}

	if decl != nil {
		meta.ParameterTypes = exportParameterTypesFromDecl(decl.Parameters)
		meta.ParameterTypeRefs = exportParameterTypeRefsFromDecl(decl.Parameters)
		meta.ReturnType = strings.TrimSpace(decl.ReturnType)
		meta.ReturnTypeRef = exportTypeRefFromCallgraph(decl.ReturnTypeRef)
		meta.Visibility = strings.TrimSpace(decl.Visibility)
		meta.OwnerVisibility = strings.TrimSpace(decl.OwnerVisibility)
	}

	if sig, ok := exportExternalSignature(graph, id, len(meta.ParameterTypes)); ok {
		meta.ParameterTypes = MergeExportParameterTypes(meta.ParameterTypes, sig.ParameterTypes)
		meta.ParameterTypeRefs = mergeExportParameterTypeRefs(meta.ParameterTypeRefs, sig.ParameterTypeRefs)
		if meta.ReturnType == "" {
			meta.ReturnType = strings.TrimSpace(sig.ReturnType)
		}
		if meta.ReturnTypeRef == nil {
			meta.ReturnTypeRef = exportTypeRefFromCallgraph(sig.ReturnTypeRef)
		}
	}

	meta.ReturnType = normalizeExportReturnType(id, meta.ReturnType)
	meta.CanonicalSignature = CanonicalSignature(meta.FunctionName, meta.ParameterTypes, meta.ReturnType)
	meta.ErasedSignature = erasedSignature(meta.FunctionName, meta.ParameterTypes, meta.ReturnType, typeParamBoundsOf(decl))
	meta.DisplaySymbol, meta.Aliases = exportDisplaySymbolAndAliases(id, meta.FunctionName)

	// Populate inferred_return when the inference pass produced a result.
	// Two suppression rules apply:
	//   1. join-failed origin is suppressed (it is internal only).
	//   2. When inferred type == declared type the field carries zero information
	//      and is omitted.
	if decl != nil && decl.InferredReturn != nil &&
		decl.InferredReturn.Origin != "join-failed" &&
		strings.TrimSpace(decl.InferredReturn.Type) != strings.TrimSpace(meta.ReturnType) {
		ir := decl.InferredReturn
		meta.InferredReturn = &ExportInferredReturn{
			Type:       ir.Type,
			TypeRef:    exportTypeRefFromCallgraph(ir.TypeRef),
			Confidence: ir.Confidence,
			Origin:     ir.Origin,
			Provenance: convertInferredReturnProvenance(ir.Provenance),
		}
	}

	return meta
}

// BuildCallExportFunctionMetadata enriches an external call with canonical
// signature details that the contract KB can state unambiguously. Source or
// scanned declarations remain authoritative; contracts only fill gaps.
func BuildCallExportFunctionMetadata(
	ctx *Context,
	call *callgraph.FunctionCall,
	decl *callgraph.FunctionDecl,
) (ExportFunctionMetadata, []contracts.Contract) {
	if call == nil {
		return ExportFunctionMetadata{}, nil
	}
	meta := BuildExportFunctionMetadata(ctx.Graph, call.Callee, decl)
	matches := ContractMatchesForCall(ctx, call, len(call.Arguments))
	if len(matches) == 0 {
		return meta, nil
	}
	canonicalMatches := compatibleCanonicalContracts(canonicalContractsForCall(matches, call), call)
	if len(canonicalMatches) == 0 {
		return meta, matches
	}

	parameterTypes := canonicalMatches[0].ParameterTypes
	returnType := canonicalMatches[0].CanonicalReturnType
	for i := 1; i < len(canonicalMatches); i++ {
		if !slices.Equal(parameterTypes, canonicalMatches[i].ParameterTypes) {
			parameterTypes = nil
		}
		if returnType != canonicalMatches[i].CanonicalReturnType {
			returnType = ""
		}
	}
	meta.ParameterTypes = MergeExportParameterTypes(meta.ParameterTypes, parameterTypes)
	if meta.ReturnType == "" {
		meta.ReturnType = returnType
	}
	meta.CanonicalSignature = CanonicalSignature(meta.FunctionName, meta.ParameterTypes, meta.ReturnType)
	return meta, matches
}

// convertInferredReturnProvenance converts a []callgraph.SourceNode (inference
// provenance) into the export shape without path normalization. This is used
// only for the inferred_return.provenance field — the paths are not available
// at metadata-build time, since no Context is available here.
func convertInferredReturnProvenance(nodes []callgraph.SourceNode) []ExportSourceNode {
	if len(nodes) == 0 {
		return nil
	}
	result := make([]ExportSourceNode, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		result[i] = ExportSourceNode{
			Type:         n.Type,
			Name:         n.Name,
			DeclaredType: n.DeclaredType,
			Value:        n.Value,
			SourceNodes:  convertInferredReturnProvenance(n.SourceNodes),
		}
		if n.Type == SourceNodeTypeParameter {
			idx := n.ParameterIndex
			result[i].ParameterIndex = &idx
		}
		if n.CallTarget != nil {
			result[i].CallTarget = FullFunctionName(*n.CallTarget)
			result[i].CallTargetDisplaySymbol = graphfrag.ConstructorDisplayFromSymbol(result[i].CallTarget)
		}
	}
	return result
}

// exportTypeRefFromCallgraph converts a callgraph.TypeRef into the exported
// shape, returning nil when the source carries no useful structured data.
// The flat name alone is not surfaced through *_ref fields; consumers can
// read it from the existing return_type / parameter_types strings.
func exportTypeRefFromCallgraph(ref callgraph.TypeRef) *ExportTypeRef {
	if ref.Name == "" && len(ref.GenericParameters) == 0 {
		return nil
	}
	if !ref.HasGenerics() {
		return nil
	}
	out := convertCallgraphTypeRef(ref)
	return &out
}

func convertCallgraphTypeRef(ref callgraph.TypeRef) ExportTypeRef {
	out := ExportTypeRef{Name: ref.Name}
	if len(ref.GenericParameters) > 0 {
		out.GenericParameters = make([]ExportTypeRef, len(ref.GenericParameters))
		for i, child := range ref.GenericParameters {
			out.GenericParameters[i] = convertCallgraphTypeRef(child)
		}
	}
	return out
}

func exportParameterTypeRefsFromDecl(params []callgraph.FunctionParameter) []ExportTypeRef {
	if len(params) == 0 {
		return nil
	}
	hasGenerics := false
	refs := make([]ExportTypeRef, len(params))
	for i, param := range params {
		refs[i] = convertCallgraphTypeRef(param.TypeRef)
		if refs[i].Name == "" {
			refs[i].Name = strings.TrimSpace(param.Type)
		}
		if param.TypeRef.HasGenerics() {
			hasGenerics = true
		}
	}
	if !hasGenerics {
		return nil
	}
	return refs
}

func mergeExportParameterTypeRefs(existing []ExportTypeRef, fallback []callgraph.TypeRef) []ExportTypeRef {
	if len(fallback) == 0 {
		return existing
	}
	merged := append([]ExportTypeRef(nil), existing...)
	hasGenerics := false
	for _, r := range merged {
		if len(r.GenericParameters) > 0 {
			hasGenerics = true
			break
		}
	}
	if len(merged) == 0 {
		merged = make([]ExportTypeRef, len(fallback))
	}
	limit := len(merged)
	if len(fallback) < limit {
		limit = len(fallback)
	}
	for i := 0; i < limit; i++ {
		converted := convertCallgraphTypeRef(fallback[i])
		if merged[i].Name == "" {
			merged[i].Name = converted.Name
		}
		if len(merged[i].GenericParameters) == 0 {
			merged[i].GenericParameters = converted.GenericParameters
		}
		if len(converted.GenericParameters) > 0 {
			hasGenerics = true
		}
	}
	if !hasGenerics {
		return existing
	}
	return merged
}

func normalizeExportReturnType(id callgraph.FunctionID, returnType string) string {
	trimmed := strings.TrimSpace(returnType)
	if callgraph.BaseFunctionName(id.Name) != ConstructorMethodName {
		return trimmed
	}
	if trimmed != "" && trimmed != "void" {
		return trimmed
	}
	return strings.TrimSpace(id.Type)
}

func exportParameterTypesFromDecl(params []callgraph.FunctionParameter) []string {
	if len(params) == 0 {
		return nil
	}
	types := make([]string, len(params))
	for i := range params {
		types[i] = strings.TrimSpace(params[i].Type)
	}
	if allEmptyStrings(types) {
		return nil
	}
	return types
}

// MergeExportParameterTypes fills the empty entries of existing with the types fallback has at the same position.
func MergeExportParameterTypes(existing, fallback []string) []string {
	if len(existing) == 0 {
		if len(fallback) == 0 {
			return nil
		}
		return append([]string(nil), fallback...)
	}
	if len(fallback) == 0 {
		return existing
	}

	merged := append([]string(nil), existing...)
	limit := len(merged)
	if len(fallback) < limit {
		limit = len(fallback)
	}
	for i := 0; i < limit; i++ {
		if strings.TrimSpace(merged[i]) == "" {
			merged[i] = strings.TrimSpace(fallback[i])
		}
	}
	return merged
}

func uniqueSourceDeclaredType(nodes []ExportSourceNode) string {
	current := nodes
	for len(current) > 0 {
		types := make(map[string]struct{})
		nextCapacity := 0
		for i := range current {
			nextCapacity += len(current[i].SourceNodes)
		}
		next := make([]ExportSourceNode, 0, nextCapacity)
		for i := range current {
			if declared := strings.TrimSpace(current[i].DeclaredType); declared != "" {
				types[declared] = struct{}{}
			}
			next = append(next, current[i].SourceNodes...)
		}
		if len(types) == 1 {
			for declared := range types {
				return declared
			}
		}
		if len(types) > 1 {
			return ""
		}
		current = next
	}
	return ""
}

func exportExternalSignature(
	graph *callgraph.CallGraph,
	id callgraph.FunctionID,
	paramCount int,
) (callgraph.ExternalMethodSignature, bool) {
	if graph == nil || graph.ExternalMethodSignatures == nil {
		return callgraph.ExternalMethodSignature{}, false
	}

	signatures := graph.ExternalMethodSignatures[callgraph.ExternalMethodSignatureKey(id)]
	if len(signatures) == 0 {
		return callgraph.ExternalMethodSignature{}, false
	}
	for _, sig := range signatures {
		if paramCount == 0 || len(sig.ParameterTypes) == paramCount {
			return sig, true
		}
	}
	return signatures[0], true
}

// CanonicalSignature renders "name(type, ...): return", with "?" for an unknown parameter type.
func CanonicalSignature(functionName string, parameterTypes []string, returnType string) string {
	if functionName == "" {
		return ""
	}

	params := make([]string, len(parameterTypes))
	for i := range parameterTypes {
		paramType := strings.TrimSpace(parameterTypes[i])
		if paramType == "" {
			paramType = "?"
		}
		params[i] = paramType
	}

	signature := functionName + "(" + strings.Join(params, ", ") + ")"
	if trimmedReturnType := strings.TrimSpace(returnType); trimmedReturnType != "" {
		signature += ": " + trimmedReturnType
	}
	return signature
}

// erasedSignature builds the generics-erased join form of a canonical
// signature: every generic argument list is stripped, and type variables
// (per the declaring class's recorded bounds) are replaced by their erased
// bound. This is the normal form a bytecode-level consumer reproduces.
func erasedSignature(functionName string, parameterTypes []string, returnType string, bounds map[string]string) string {
	if functionName == "" {
		return ""
	}
	params := make([]string, len(parameterTypes))
	for i := range parameterTypes {
		params[i] = eraseJavaType(parameterTypes[i], bounds)
	}
	signature := functionName + "(" + strings.Join(params, ", ") + ")"
	if erased := eraseJavaType(returnType, bounds); erased != "" && erased != "?" {
		signature += ": " + erased
	}
	return signature
}

// eraseJavaType strips generic arguments, preserves array suffixes, and
// substitutes a type variable with its erased bound ("Object" by default).
func eraseJavaType(typeText string, bounds map[string]string) string {
	typeText = strings.TrimSpace(typeText)
	if typeText == "" {
		return "?"
	}
	if angle := strings.Index(typeText, "<"); angle >= 0 {
		suffix := ""
		if closeIdx := strings.LastIndex(typeText, ">"); closeIdx >= 0 && closeIdx+1 < len(typeText) {
			suffix = typeText[closeIdx+1:]
		}
		typeText = typeText[:angle] + suffix
	}
	arraySuffix := ""
	for strings.HasSuffix(typeText, "[]") {
		typeText = typeText[:len(typeText)-2]
		arraySuffix += "[]"
	}
	if bound, ok := bounds[typeText]; ok && bound != "" {
		typeText = bound
	}
	return typeText + arraySuffix
}

func typeParamBoundsOf(decl *callgraph.FunctionDecl) map[string]string {
	if decl == nil {
		return nil
	}
	return decl.TypeParamBounds
}

func exportDisplaySymbolAndAliases(id callgraph.FunctionID, functionName string) (string, []string) {
	display := constructorDisplaySymbol(id, functionName)
	if display == "" || display == functionName {
		return display, nil
	}
	return display, []string{display}
}

func constructorDisplaySymbol(id callgraph.FunctionID, fallback string) string {
	if callgraph.BaseFunctionName(id.Name) != ConstructorMethodName {
		return fallback
	}
	typeName := SanitizeSymbol(id.Type)
	if typeName == "" || strings.Contains(typeName, "(") {
		return fallback
	}
	simpleName := typeName
	if dot := strings.LastIndex(simpleName, "."); dot >= 0 {
		simpleName = simpleName[dot+1:]
	}
	if id.Package == "" {
		return typeName + "." + simpleName
	}
	return id.Package + "." + typeName + "." + simpleName
}

// CloneStringSlice returns a copy of values, nil when it is empty.
func CloneStringSlice(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	return append([]string(nil), values...)
}

func allEmptyStrings(values []string) bool {
	if len(values) == 0 {
		return true
	}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return false
		}
	}
	return true
}

// FullFunctionName returns the qualified package.Type.method name of id, without its arity suffix.
func FullFunctionName(id callgraph.FunctionID) string {
	base := callgraph.BaseFunctionName(id.Name)
	typeName := SanitizeSymbol(id.Type)
	// Package needs the same sanitization as Type: an unresolved static-rooted
	// fluent chain link falls back to the raw receiver expression as its
	// Package, which for a multi-line chain carries newlines and indentation
	// that must never leak into exported symbols or canonical signatures.
	pkg := SanitizeSymbol(id.Package)
	if typeName == "" || strings.Contains(typeName, "(") {
		if pkg == "" {
			return base
		}
		return pkg + "." + base
	}
	if pkg == "" {
		return typeName + "." + base
	}
	return pkg + "." + typeName + "." + base
}

// SanitizeSymbol collapses whitespace and newlines in symbol strings.
// Fluent chain calls in Java store the raw multiline expression as the Type,
// e.g. "Request.builder()\r\n            .setId(id)". This produces clean
// single-line symbols like "Request.builder().setId(id)".
func SanitizeSymbol(s string) string {
	if !strings.ContainsAny(s, "\r\n\t") {
		return s
	}
	s = strings.ReplaceAll(s, "\r\n", "")
	s = strings.ReplaceAll(s, "\n", "")
	var b strings.Builder
	for _, r := range s {
		if r != ' ' && r != '\t' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// NormalizeExportPath names actualPath by its artifact and its path inside it.
// An export asks once per function and call site, for few distinct files, so
// each file is located once; every caller still gets its own DependencyInfo.
func NormalizeExportPath(ctx *Context, actualPath string) ExportLocation {
	location, ok := ctx.ExportLocations.Lookup(actualPath)
	if !ok {
		location = ctx.ExportLocations.Store(actualPath, locateExportPath(ctx, actualPath))
	}
	if location.DependencyInfo != nil {
		dep := *location.DependencyInfo
		location.DependencyInfo = &dep
	}
	return location
}

func locateExportPath(ctx *Context, actualPath string) ExportLocation {
	if actualPath == "" {
		return ExportLocation{}
	}

	cleanPath := filepath.Clean(actualPath)
	if dep := ctx.DependencyForPath(cleanPath); dep != nil {
		if rel, ok := RelativeToRoot(dep.Dir, cleanPath); ok {
			return ExportLocation{
				FilePath: filepath.ToSlash(rel),
				DependencyInfo: &DependencyContext{
					Module:  dep.Module,
					Version: dep.Version,
					PURL:    purl.Dependency(ctx.Ecosystem, dep.Module, dep.Version),
				},
			}
		}
		if !filepath.IsAbs(cleanPath) {
			return ExportLocation{
				FilePath: filepath.ToSlash(cleanPath),
				DependencyInfo: &DependencyContext{
					Module:  dep.Module,
					Version: dep.Version,
					PURL:    purl.Dependency(ctx.Ecosystem, dep.Module, dep.Version),
				},
			}
		}
	}

	if rel, ok := RelativeToRoot(ctx.ProjectRoot, cleanPath); ok {
		return ExportLocation{FilePath: filepath.ToSlash(rel)}
	}
	if !filepath.IsAbs(cleanPath) {
		return ExportLocation{FilePath: filepath.ToSlash(cleanPath)}
	}
	return ExportLocation{FilePath: filepath.ToSlash(cleanPath)}
}

// IsSimpleIdentifier reports whether expr is a single identifier.
func IsSimpleIdentifier(expr string) bool {
	if expr == "" {
		return false
	}
	for i, r := range expr {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r == '_' || r == '$' {
			continue
		}
		if i > 0 && r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

// exportFunctionFQN renders a FunctionID as its undecorated package.Type.method
// symbol (no arity/overload suffix), matching contract method keys.
func exportFunctionFQN(id callgraph.FunctionID) string {
	var fqn string
	switch {
	case id.Type != "" && id.Package != "":
		fqn = id.Package + "." + id.Type + "." + id.Name
	case id.Type != "":
		fqn = id.Type + "." + id.Name
	case id.Package != "":
		fqn = id.Package + "." + id.Name
	default:
		fqn = id.Name
	}
	if i := strings.IndexByte(fqn, '#'); i >= 0 {
		return fqn[:i]
	}
	return fqn
}

// ContractDeclKeys returns the keys a declaration is indexed under for contract
// lookups. The Rust call graph joins a declaration's module, type and name with
// "." ("serde_json::de.Deserializer.new") while the Rust KBs key contracts as
// "serde_json::de::Deserializer.new", so Rust declarations take the KB spelling,
// once under the declaring path and once under each public re-export of it.
func ContractDeclKeys(ctx *Context, id callgraph.FunctionID) []string {
	fqn := exportFunctionFQN(id)
	if fqn == "" {
		return nil
	}
	if ctx.Ecosystem != EcosystemRust {
		return []string{fqn}
	}
	keys := []string{RustContractMethodKey(fqn)}
	// A Rust contract names the path a consumer imports: a type declared in a
	// private module and re-exported is reachable only through its public
	// re-export paths, not the declaring one.
	if id.Package != "" && id.Type != "" && ctx.Graph != nil {
		_, method := SplitFunctionName(keys[0])
		for _, public := range ctx.Graph.PublicTypePaths[id.Package+"::"+id.Type] {
			keys = append(keys, public+"."+method)
		}
	}
	return keys
}

// RustContractMethodKey spells a Rust api the way the Rust KBs key contracts:
// "::" between path segments and "." before the method only.
func RustContractMethodKey(api string) string {
	path := strings.ReplaceAll(api, "::", ".")
	i := strings.LastIndex(path, ".")
	if i < 0 {
		return api
	}
	return strings.ReplaceAll(path[:i], ".", "::") + path[i:]
}

// ExportPackageSeparator returns the separator between package and name in ecosystem's function names.
func ExportPackageSeparator(ecosystem string) string {
	switch ecosystem {
	case "go":
		return "/"
	case EcosystemRust:
		return "::"
	default:
		return "."
	}
}
