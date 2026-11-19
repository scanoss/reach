// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// rust_implicit_calls.go records the calls a Rust call expression makes
// without a call expression of their own (FunctionDecl.ImplicitCalls):
//
//   - A function handed to another as a value runs when the receiver calls
//     it: age's `alt((rsa_privkey, openssh_privkey)).parse(input)` runs both
//     parsers, and nom's combinators are generic, so the compiler calls them
//     directly.
//   - `s.parse::<T>()` runs `<T as FromStr>::from_str`: age's
//     `s.parse::<tag::Recipient>()` runs `tag::Recipient::from_str`.

// rustFromStrMethod is the method `str::parse::<T>()` runs on T.
const rustFromStrMethod = "from_str"

// rustImplicitCalls returns the implicit calls one call expression makes.
func (p *RustParser) rustImplicitCalls(node *sitter.Node, ctx *rustTypeCtx, filePath string, call *FunctionCall) []FunctionCall {
	var out []FunctionCall
	if parsed, ok := rustParsedType(node, ctx); ok {
		out = append(out, FunctionCall{
			Callee:   FunctionID{Package: parsed.pkg, Type: parsed.typ, Name: rustFromStrMethod},
			Raw:      call.Raw,
			FilePath: filePath,
			Line:     call.Line,
			StartCol: call.StartCol,
			EndCol:   call.EndCol,
			EndLine:  call.EndLine,
		})
	}
	args := rustCallArgumentsNode(node)
	if args == nil {
		return out
	}
	crate := rustCrateRoot(ctx.analysis.PackagePath)
	for _, value := range rustFunctionValueArguments(args, ctx.src) {
		text := value.Content(ctx.src)
		id, ok := p.rustHandlerID(value, ctx, filePath)
		if !ok || id.Name == "" || id.Name == rustUnnamedCallee {
			continue
		}
		ref := callbackReference(call, id, text)
		// A function of another crate is not declared in this graph, so a
		// reference to it would be dropped: it is an ordinary call to the
		// dependency, which the stitch joins like any other.
		ref.Reference = rustCrateRoot(id.Package) == crate
		out = appendCallbackReference(out, ref)
	}
	return out
}

// rustParsedTypeName is a type a `parse` call parses into.
type rustParsedTypeName struct{ pkg, typ string }

// rustParsedType returns the type T of a `recv.parse::<T>()` call, with its
// path resolved through the file's imports.
func rustParsedType(node *sitter.Node, ctx *rustTypeCtx) (rustParsedTypeName, bool) {
	fn := node.ChildByFieldName("function")
	if fn == nil || fn.Symbol() != rustSyms.genericFunction {
		return rustParsedTypeName{}, false
	}
	method := fn.ChildByFieldName("function")
	if method == nil || method.Symbol() != rustSyms.fieldExpression || nodeFieldText(method, "field", ctx.src) != "parse" {
		return rustParsedTypeName{}, false
	}
	typeArgs := fn.ChildByFieldName("type_arguments")
	if typeArgs == nil || typeArgs.NamedChildCount() != 1 {
		return rustParsedTypeName{}, false
	}
	text := rustScopedTypeText(typeArgs.NamedChild(0), ctx.src)
	pkg, typ := rustQualifyType(ctx.analysis, ctx.analysis.rustFacts, text)
	if pkg == "" || typ == "" {
		return rustParsedTypeName{}, false
	}
	return rustParsedTypeName{pkg: pkg, typ: typ}, true
}

// rustFunctionValueArguments returns the arguments of a call that name a
// function as a value: a path whose last segment is a function name
// (snake_case), passed bare, by reference, or inside a tuple or an array.
// A call's own arguments, a closure and any other expression are left to the
// walk that reads them.
func rustFunctionValueArguments(args *sitter.Node, src []byte) []*sitter.Node {
	var out []*sitter.Node
	var visit func(n *sitter.Node)
	visit = func(n *sitter.Node) {
		switch n.Symbol() {
		case rustSyms.identifier, rustSyms.scopedIdentifier:
			if rustLooksLikeFunctionName(n, src) {
				out = append(out, n)
			}
		case rustSyms.tupleExpression, rustSyms.referenceExpression, rustSyms.parenthesized:
			for i := 0; i < int(n.NamedChildCount()); i++ {
				visit(n.NamedChild(i))
			}
		default:
			if n.Type() == "array_expression" {
				for i := 0; i < int(n.NamedChildCount()); i++ {
					visit(n.NamedChild(i))
				}
			}
		}
	}
	for i := 0; i < int(args.NamedChildCount()); i++ {
		visit(args.NamedChild(i))
	}
	return out
}

// rustLooksLikeFunctionName reports whether a path's last segment is spelled
// like a function: lower case, not `self`. A type, a variant or a constant
// (`Error::Io`, `None`, `MAX`) is not a function value.
func rustLooksLikeFunctionName(n *sitter.Node, src []byte) bool {
	leaf := n
	if n.Symbol() == rustSyms.scopedIdentifier {
		leaf = n.ChildByFieldName("name")
	}
	if leaf == nil || leaf.Symbol() != rustSyms.identifier {
		return false
	}
	name := leaf.Content(src)
	if name == "" || name == "self" || name == "_" {
		return false
	}
	c := name[0]
	return c == '_' || (c >= 'a' && c <= 'z')
}
