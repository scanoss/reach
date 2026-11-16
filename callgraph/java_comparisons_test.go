// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// describeSources renders source nodes as Type(Name=Value){children}.
func describeSources(nodes []SourceNode) string {
	parts := make([]string, 0, len(nodes))
	for _, n := range nodes {
		s := n.Type
		if n.Name != "" {
			s += " " + n.Name
		}
		if n.Value != "" && n.Value != n.Name {
			s += "=" + n.Value
		}
		if n.Type == javaSourceTypeParameter {
			s += fmt.Sprintf("#%d", n.ParameterIndex)
		}
		if len(n.SourceNodes) > 0 {
			s += "{" + describeSources(n.SourceNodes) + "}"
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ",")
}

// A constant compared with `==`, `!=` or `equals` (as receiver or argument)
// and a `case` label get the other operand, or the switch subject, traced
// with the scope's origins; other positions get none.
func TestJavaParser_ComparedOperands(t *testing.T) {
	t.Parallel()

	src := `package com.example;
public class Cmp {
    Object pick(Object alg, int kind) {
        Object fixed = Alg.HS512;
        if (alg == Alg.RS256 || Alg.PS256.equals(alg) || fixed.equals(Alg.EdDSA)) {
            return Alg.RS384;
        }
        if ((Alg.ES256) != alg) { }
        if ((alg == Alg.A9) == (kind > 0)) { }
        switch (kind) {
            case Kinds.ONE: return null;
        }
        return null;
    }
}
`
	graph := parseInlineJava(t, "Cmp", src)
	var got []string
	for _, fn := range graph.Functions {
		for _, r := range fn.ConstantRefs {
			operand := "-"
			if r.Operand != nil {
				operand = r.Operand.Text + " " + describeSources(r.Operand.Sources)
			}
			got = append(got, fmt.Sprintf("%s %s: %s", r.Context, r.Text, operand))
		}
	}
	sort.Strings(got)
	want := []string{
		"case Kinds.ONE: kind PARAMETER kind#1",
		"compare Alg.A9: alg PARAMETER alg#0",
		"compare Alg.ES256: alg PARAMETER alg#0",
		"compare Alg.RS256: alg PARAMETER alg#0",
		"equals Alg.EdDSA: fixed VARIABLE fixed{VALUE Alg.HS512}",
		"equals Alg.PS256: alg PARAMETER alg#0",
		"init Alg.HS512: -",
		"return Alg.RS384: -",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("compared operands =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A compared field gets the literals and constants its class writes to it:
// in an initializer, as this.f or as f in a member with no local f. A write
// in a member that declares a local f, a nested class's field of the same
// name, and a non-constant write add nothing.
func TestJavaParser_ComparedFieldWrites(t *testing.T) {
	t.Parallel()

	src := `package com.example;
public class Params {
    private int polyType = Kinds.NONE;
    Params(int n) { this.polyType = Kinds.SIMPLE; }
    Params(int n, int m) { polyType = Kinds.PRODUCT; }
    Params(String s) { polyType = read(); }
    void shadow(int polyType) { polyType = Kinds.SHADOWED; }
    static class Inner { int polyType; Inner() { polyType = Kinds.INNER; } }
    boolean simple() { return polyType == Kinds.SIMPLE; }
    int read() { return 0; }
}
`
	graph := parseInlineJava(t, "Params", src)
	var got string
	for _, fn := range graph.Functions {
		for _, r := range fn.ConstantRefs {
			if r.Context == ConstantRefCompare && r.Operand != nil {
				got = describeSources(r.Operand.Sources)
			}
		}
	}
	want := "FIELD polyType{VALUE Kinds.NONE,VALUE Kinds.SIMPLE,VALUE Kinds.PRODUCT}"
	if got != want {
		t.Errorf("compared field sources = %s, want %s", got, want)
	}
}
