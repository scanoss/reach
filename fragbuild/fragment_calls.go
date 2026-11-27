// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/graphfrag"
)

// FragmentCarriesCalls reports a fragment that holds them: a Java, Python,
// Go, Node, C, C++, Rust, Ruby or C# one, the languages the cards matcher
// reads. Another language's fragment leaves them out (graph-fragment-1.22),
// and a reader rebuilds its calls from the edges, which miss calls the graph
// records no edge for and the call's text as written.
func FragmentCarriesCalls(ctx *Context) bool {
	return ctx != nil && (ctx.Ecosystem == EcosystemJava || ctx.Ecosystem == EcosystemPython || ctx.Ecosystem == EcosystemGo || ctx.Ecosystem == EcosystemNode || ctx.Ecosystem == EcosystemC ||
		ctx.Ecosystem == EcosystemCPP || ctx.Ecosystem == EcosystemRust || ctx.Ecosystem == ecosystemRuby || ctx.Ecosystem == EcosystemCSharp)
}

// fragmentRawSources projects provenance as the parser traced it, with file
// paths relative to the component root.
func fragmentRawSources(ctx *Context, nodes []callgraph.SourceNode) []graphfrag.GraphFragmentRawSource {
	if nodes == nil {
		return nil
	}
	out := make([]graphfrag.GraphFragmentRawSource, len(nodes))
	for i := range nodes {
		node := &nodes[i]
		raw := graphfrag.GraphFragmentRawSource{
			Type: node.Type, Name: node.Name, DeclaredType: node.DeclaredType, Value: node.Value,
			ParameterIndex: node.ParameterIndex, SourceNodes: fragmentRawSources(ctx, node.SourceNodes),
			MayValues: node.MayValues, MayValuesExhaustive: node.MayValuesExhaustive,
		}
		if node.CallTarget != nil {
			raw.CallTarget = node.CallTarget.String()
		}
		if node.Location != nil {
			raw.Location = &graphfrag.GraphFragmentSourceLoc{Line: node.Location.Line}
			if node.Location.FilePath != "" {
				raw.Location.FilePath = NormalizeExportPath(ctx, node.Location.FilePath).FilePath
			}
		}
		if flow := node.Flow; flow != nil {
			raw.ReturnValue, raw.CallArgument = flow.ReturnValue, flow.CallArgument
			if flow.Guard != nil {
				raw.Guard = &graphfrag.GraphFragmentRawGuard{ParameterIndex: flow.Guard.ParameterIndex, Value: flow.Guard.Value, Default: flow.Guard.Default}
			}
		}
		out[i] = raw
	}
	return out
}

// fragmentArgumentSources projects a call's argument provenance, one slot
// per argument.
func fragmentArgumentSources(ctx *Context, sources [][]callgraph.SourceNode) [][]graphfrag.GraphFragmentRawSource {
	if sources == nil {
		return nil
	}
	out := make([][]graphfrag.GraphFragmentRawSource, len(sources))
	for i := range sources {
		out[i] = fragmentRawSources(ctx, sources[i])
	}
	return out
}

// BuildGraphFragmentExternalSignatures lists the external signatures the
// graph holds for the targets of its calls and for its own functions, the
// ones an export of the graph reads.
func BuildGraphFragmentExternalSignatures(ctx *Context) map[string][]graphfrag.GraphFragmentExternalSignature {
	if !FragmentCarriesCalls(ctx) || ctx.Graph == nil || len(ctx.Graph.ExternalMethodSignatures) == 0 {
		return nil
	}
	out := make(map[string][]graphfrag.GraphFragmentExternalSignature)
	add := func(id callgraph.FunctionID) {
		key := callgraph.ExternalMethodSignatureKey(id)
		if _, done := out[key]; done {
			return
		}
		signatures := ctx.Graph.ExternalMethodSignatures[key]
		if len(signatures) == 0 {
			return
		}
		list := make([]graphfrag.GraphFragmentExternalSignature, len(signatures))
		for i := range signatures {
			list[i] = graphfrag.GraphFragmentExternalSignature{
				ParameterTypes: append([]string{}, signatures[i].ParameterTypes...),
				ReturnType:     signatures[i].ReturnType,
			}
		}
		out[key] = list
	}
	for _, decl := range ctx.Graph.Functions {
		add(decl.ID)
		for i := range decl.Calls {
			add(decl.Calls[i].Callee)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// fragmentParameterNames lists a function's parameter names, none when it
// has no named parameter.
func fragmentParameterNames(parameters []callgraph.FunctionParameter) []string {
	names := make([]string, len(parameters))
	named := false
	for i := range parameters {
		names[i] = parameters[i].Name
		named = named || names[i] != ""
	}
	if !named {
		return nil
	}
	return names
}
