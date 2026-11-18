// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "github.com/scanoss/reach/javaruntime"

const (
	ecosystemCPP         = "cpp"
	ecosystemGo          = "go"
	ecosystemJava        = "java"
	lambdaExpressionNode = "lambda_expression"
)

// NewParserForEcosystem returns the call graph parser for the given ecosystem.
// Returns nil if no parser is available for the ecosystem.
func NewParserForEcosystem(ecosystem string, opts ...ParserOption) Parser {
	switch ecosystem {
	case "c":
		return NewCParser(opts...)
	case ecosystemCPP, "c++":
		return NewCPPParser(opts...)
	case "go":
		return NewGoParser(opts...)
	case "java":
		return NewJavaParser(opts...)
	case "node", "javascript", "typescript":
		return NewNodeParser(opts...)
	case "python":
		return NewPythonParser(opts...)
	case "ruby":
		return NewRubyParser(opts...)
	case "rust":
		return NewRustParser(opts...)
	default:
		return nil
	}
}

// NewTypeResolverForEcosystem returns the type resolver for the given ecosystem.
// Returns nil if no type resolver is available (tree-sitter-only resolution).
func NewTypeResolverForEcosystem(ecosystem string, javaRuntime javaruntime.Config) TypeResolver {
	switch ecosystem {
	case "c":
		return NewCContractTypeResolverFromSource()
	case ecosystemCPP, "c++":
		return NewCPPContractTypeResolverFromSource()
	case "go":
		return NewGoContractTypeResolverFromSource()
	case "java":
		return NewJavaBytecodeTypeResolver(javaRuntime)
	case "node", "javascript", "typescript":
		return NewNodeContractTypeResolverFromSource()
	case "python":
		return NewPythonTypeResolverChain()
	case "rust":
		return NewRustContractTypeResolverFromSource()
	default:
		return nil
	}
}
