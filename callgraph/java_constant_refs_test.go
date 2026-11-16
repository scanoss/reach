// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func constantRefsOf(graph *CallGraph) map[string][]string {
	out := map[string][]string{}
	for _, fn := range graph.Functions {
		for _, r := range fn.ConstantRefs {
			span := fmt.Sprintf("%d:%d-%d", r.Line, r.StartCol, r.EndCol)
			if r.EndLine != 0 {
				span = fmt.Sprintf("%d:%d-%d:%d", r.Line, r.StartCol, r.EndLine, r.EndCol)
			}
			out[fn.ID.Name] = append(out[fn.ID.Name], r.Context+" "+r.Text+" "+span)
		}
	}
	for _, refs := range out {
		sort.Strings(refs)
	}
	return out
}

// A qualified constant is recorded wherever it is written, with its position
// kind, in the function that contains it; a name imported with import static
// is recorded qualified. Variables, this-fields and type receivers of calls
// are not constants.
func TestJavaParser_ConstantRefsAtEveryPosition(t *testing.T) {
	t.Parallel()

	src := `package com.example;
import static javax.xml.crypto.dsig.SignatureMethod.RSA_SHA256;
public class Refs {
    static final Object[] ALL = { Alg.ES256, Alg.ES384 };
    private Object field = Alg.HS256;
    private int n;
    Object pick(Object alg, int kind) {
        if (alg == Alg.RS256 || Alg.PS256.equals(alg) || alg.equals(Alg.EdDSA)) {
            return Alg.RS384;
        }
        switch (kind) {
            case Kinds.ONE: return com.example.Alg.RS512;
        }
        Object a = (kind > 0 ? Alg.A1 : Alg.A2);
        a = Alg.A3;
        this.n = params.size;
        use(Alg.A4, RSA_SHA256);
        System.out.println(Alg
            .A5);
        return a;
    }
    void use(Object a, Object b) {}
}
`
	graph := parseInlineJava(t, "Refs", src)
	got := constantRefsOf(graph)
	want := map[string][]string{
		"<clinit>#0": {
			"array Alg.ES256 4:35-44",
			"array Alg.ES384 4:46-55",
			"init Alg.HS256 5:28-37",
		},
		"pick#2": {
			"arg Alg.A4 17:13-19",
			"arg Alg.A5 18:28-19:16",
			"arg javax.xml.crypto.dsig.SignatureMethod.RSA_SHA256 17:21-31",
			"assign Alg.A3 15:13-19",
			"case Kinds.ONE 12:18-27",
			"compare Alg.RS256 8:20-29",
			"equals Alg.EdDSA 8:69-78",
			"equals Alg.PS256 8:33-42",
			"init Alg.A1 14:32-38",
			"init Alg.A2 14:41-47",
			"other System.out 18:9-19",
			"return Alg.RS384 9:20-29",
			"return com.example.Alg.RS512 12:36-57",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("constant refs =\n%v\nwant\n%v", got, want)
	}
}

// A constant of a nested type is one reference, not one per segment.
func TestJavaParser_ConstantRefOfNestedTypeIsOneRef(t *testing.T) {
	t.Parallel()

	src := `package com.example;
public class Nested {
    Object get() { return Outer.Inner.NAME; }
}
`
	got := constantRefsOf(parseInlineJava(t, "Nested", src))
	want := map[string][]string{"get#0": {"return Outer.Inner.NAME 3:27-43"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("constant refs = %v, want %v", got, want)
	}
}
