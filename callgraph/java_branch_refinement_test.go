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

// Inside a branch guarded by `v == X`, `X.equals(v)`, `v.equals(X)` (also as
// an && conjunct), `case X:` or `case X ->`, a call's argument v traces to X.
// No refinement: the else branch, equalsIgnoreCase, a group entered by
// falling through, a group with two labels, default, a branch that writes v,
// a field, and outside the branch (alg is written on line 16, so it has no
// single source there).
func TestJavaParser_BranchRefinement(t *testing.T) {
	t.Parallel()

	src := `package com.example;
import javax.crypto.Mac;
public class Branch {
    private String field;
    void run(String alg, int n) throws Exception {
        switch (alg) {
            case "HmacSHA256": Mac.getInstance(alg); break;
            case "HmacSHA384": Mac.getInstance(alg);
            case "HmacSHA512": Mac.getInstance(alg); break;
            case "A": case "B": Mac.getInstance(alg); break;
            default: Mac.getInstance(alg);
        }
        if (alg.equals("HmacMD5")) { Mac.getInstance(alg); } else { Mac.getInstance(alg); }
        if (n > 0 && Algs.SHA1.equals(alg)) Mac.getInstance(alg);
        if (alg.equalsIgnoreCase("hmacsha1")) Mac.getInstance(alg);
        if (alg == "X") { alg = other(); Mac.getInstance(alg); }
        switch (alg) { case "R" -> Mac.getInstance(alg); default -> { } }
        if (field.equals("F")) Mac.getInstance(field);
        switch (alg) { case "C", "D": Mac.getInstance(alg); break; }
        Mac.getInstance(alg);
    }
    String other() { return null; }
}
`
	graph := parseInlineJava(t, "Branch", src)
	var got []string
	for _, fn := range graph.Functions {
		for _, c := range fn.Calls {
			if c.Raw != "Mac.getInstance" {
				continue
			}
			got = append(got, fmt.Sprintf("%02d %s", c.Line, describeSources(c.ArgumentSources[0])))
		}
	}
	sort.Strings(got)
	want := []string{
		`07 VARIABLE alg{VALUE="HmacSHA256"}`,
		`08 VARIABLE alg{VALUE="HmacSHA384"}`,
		`09 VARIABLE alg`,
		`10 VARIABLE alg`,
		`11 VARIABLE alg`,
		`13 VARIABLE alg`,
		`13 VARIABLE alg{VALUE="HmacMD5"}`,
		`14 VARIABLE alg{VALUE Algs.SHA1}`,
		`15 VARIABLE alg`,
		`16 VARIABLE alg`,
		`17 VARIABLE alg{VALUE="R"}`,
		`18 FIELD field`,
		`19 VARIABLE alg`,
		`20 VARIABLE alg`,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Mac.getInstance arguments =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
