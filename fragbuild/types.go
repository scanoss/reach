// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import "github.com/scanoss/reach/callgraph"

// DependencyContext names the dependency a file or function belongs to.
type DependencyContext struct {
	Module  string `json:"module"`
	Version string `json:"version"`
	PURL    string `json:"purl,omitempty"`
}

// ContractDeclaration links a contract method to a concrete function
// declaration in the call graph.
type ContractDeclaration struct {
	DeclFQN string
	Decl    *callgraph.FunctionDecl
}

// ExportLocation is a file path as exported, and the dependency it belongs to.
type ExportLocation struct {
	FilePath       string
	DependencyInfo *DependencyContext
}

// EdgeResolution is a call-graph edge resolution with its exported resolution kind.
type EdgeResolution struct {
	callgraph.EdgeResolution
	Resolution string
}
