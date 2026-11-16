// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// collectJavaMemberTypes records the static type of every field and enum
// constant of every named type declared among nodes, nested types included,
// under the fully qualified name a use spells (pkg.Owner.member, the
// NamedValues keys). The type is qualified through the declaring file's
// imports, possibly as alternatives (qualifyJavaType) the reader settles.
// The overload selector reads it to type an argument written as
// `Type.CONSTANT` or `variable.field`.
func collectJavaMemberTypes(nodes []*sitter.Node, src []byte, analysis *FileAnalysis, outerType string) {
	for _, child := range nodes {
		switch child.Type() {
		case javaNodeClassDeclaration, javaNodeInterfaceDeclaration, javaNodeEnumDeclaration,
			javaNodeRecordDeclaration, javaNodeAnnotationTypeDecl:
		default:
			continue
		}
		name, body := javaTypeNameAndBody(child, src)
		if name == "" || body == nil {
			continue
		}
		owner := javaNestedTypeName(outerType, name)
		ownerFQN := javaQualifiedName(javaAnalysisPackagePath(analysis), owner)
		members := javaTypeBodyMembers(body)
		for _, member := range members {
			switch member.Type() {
			case javaNodeEnumConstant:
				if child.Type() != javaNodeEnumDeclaration {
					continue
				}
				if nameNode := member.ChildByFieldName(javaFieldName); nameNode != nil {
					recordJavaMemberType(analysis, ownerFQN+"."+nameNode.Content(src), ownerFQN)
				}
			case javaNodeFieldDeclaration, javaNodeConstantDeclaration:
				typeNode := member.ChildByFieldName(javaFieldType)
				if typeNode == nil {
					continue
				}
				qualified := qualifyJavaType(strings.TrimSpace(typeNode.Content(src)), analysis)
				if qualified == "" {
					continue
				}
				for i := 0; i < int(member.ChildCount()); i++ {
					declarator := member.Child(i)
					if declarator.Type() != javaNodeVariableDeclarator {
						continue
					}
					if nameNode := declarator.ChildByFieldName(javaFieldName); nameNode != nil {
						recordJavaMemberType(analysis, ownerFQN+"."+nameNode.Content(src), qualified)
					}
				}
			}
		}
		collectJavaMemberTypes(members, src, analysis, owner)
	}
}

func recordJavaMemberType(analysis *FileAnalysis, key, qualified string) {
	if analysis.JavaMemberTypes == nil {
		analysis.JavaMemberTypes = make(map[string]string)
	}
	analysis.JavaMemberTypes[key] = qualified
}

// mergeJavaMemberTypes merges a file's member types into the graph. Two files
// that record different types under one key (the same type declared twice)
// leave the key unknown.
func mergeJavaMemberTypes(graph *CallGraph, analysis *FileAnalysis) {
	if len(analysis.JavaMemberTypes) == 0 {
		return
	}
	if graph.javaMemberTypes == nil {
		graph.javaMemberTypes = make(map[string]string, len(analysis.JavaMemberTypes))
	}
	for key, qualified := range analysis.JavaMemberTypes {
		if existing, ok := graph.javaMemberTypes[key]; ok && existing != qualified {
			graph.javaMemberTypes[key] = ""
			continue
		}
		graph.javaMemberTypes[key] = qualified
	}
}

// javaMemberRefUse builds the reference to the member an argument written as
// `Qualifier.member` reads: through a type (newJavaNameRef's candidates) or,
// when the qualifier is a local, parameter or field, through that variable's
// declared type.
func javaMemberRefUse(expr string, analysis *FileAnalysis, currentClass string, varTypes map[string]string, origins map[string]varOrigin) *nameRef {
	first, member, dotted := strings.Cut(expr, ".")
	if !dotted || analysis == nil {
		return nil
	}
	_, isVar := varTypes[first]
	if !isVar {
		_, isVar = origins[first]
	}
	if !isVar {
		return newJavaNameRef(expr, analysis, currentClass)
	}
	if strings.Contains(member, ".") || !isSimpleJavaIdentifier(member) {
		return nil
	}
	typeName, ok := varTypes[first]
	if !ok {
		typeName = origins[first].typeName
	}
	if typeName == "" {
		return nil
	}
	owner, ok := resolveJavaVariableTypeCallee(first, "", analysis, map[string]string{first: typeName})
	if !ok || owner.Type == "" {
		return nil
	}
	return newNameRef(expr, [][]string{{javaQualifiedName(owner.Package, owner.Type+"."+member)}})
}

// javaMemberType resolves ref against the graph's member types: the first tier
// with a recorded member decides, and its members must agree on one type.
func javaMemberType(graph *CallGraph, ref *nameRef) string {
	if graph == nil || ref == nil || len(graph.javaMemberTypes) == 0 {
		return ""
	}
	for _, tier := range ref.tiers {
		found := ""
		for _, key := range tier {
			qualified, ok := graph.javaMemberTypes[key]
			if !ok {
				continue
			}
			if qualified == "" || (found != "" && found != qualified) {
				return ""
			}
			found = qualified
		}
		if found != "" {
			return found
		}
	}
	return ""
}
