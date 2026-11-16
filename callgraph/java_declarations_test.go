// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"reflect"
	"sort"
	"testing"
)

func declarationsOf(graph *CallGraph) map[string][]string {
	out := map[string][]string{}
	span := func(line, startCol, endLine, endCol int) string {
		if endLine != 0 {
			return fmt.Sprintf("%d:%d-%d:%d", line, startCol, endLine, endCol)
		}
		return fmt.Sprintf("%d:%d-%d", line, startCol, endCol)
	}
	for _, fn := range graph.Functions {
		for _, d := range fn.Declarations {
			out[fn.ID.Name] = append(out[fn.ID.Name], fmt.Sprintf("decl %s %s init=%s %s", d.Type, d.Name, d.Init, span(d.Line, d.StartCol, d.EndLine, d.EndCol)))
		}
		for _, c := range fn.Casts {
			out[fn.ID.Name] = append(out[fn.ID.Name], fmt.Sprintf("cast %s %s inner=%d:%d", c.Type, span(c.Line, c.StartCol, c.EndLine, c.EndCol), c.InnerLine, c.InnerCol))
		}
	}
	for _, facts := range out {
		sort.Strings(facts)
	}
	return out
}

// Local and field declarations are recorded with their whole span (modifiers
// to semicolon), declared type, name and initializer kind, in the function
// that contains them (a field initializer in <clinit>); casts of a call with
// where the call starts. Primitive, String and Object declarations and casts
// of anything but a call are not recorded.
func TestJavaParser_DeclarationsAndCasts(t *testing.T) {
	t.Parallel()

	src := `package com.example;
import java.security.cert.*;
public class Decls {
    private X509Certificate field = null;
    private X509Certificate bare;
    Object pick(Object o, CertificateFactory f, java.util.List<Object> certs) throws Exception {
        X509Certificate a = (X509Certificate) o;
        final X509Certificate b = (X509Certificate) f.generateCertificate(null);
        X509Certificate c;
        c = (X509Certificate) certs.get(0);
        X509Certificate d = a, e = null;
        X509Certificate arr[] = { a };
        java.security.cert.X509Certificate q = ((X509Certificate)
            (certs.get(1)));
        int n = 0;
        String s = "x";
        Object x = new Object();
        Certificate lit = (Certificate) null;
        use((Certificate) new Decls().toString());
        return a;
    }
    void use(Object o) {}
}
`
	got := declarationsOf(parseInlineJava(t, "Decls", src))
	want := map[string][]string{
		"<clinit>#0": {
			"decl X509Certificate bare init= 5:5-34",
			"decl X509Certificate field init=null 4:5-42",
		},
		"pick#3": {
			"cast Certificate 19:13-49 inner=19:27",
			"cast X509Certificate 10:13-43 inner=10:31",
			"cast X509Certificate 13:49-14:27 inner=14:14",
			"cast X509Certificate 8:35-80 inner=8:53",
			"decl Certificate lit init=cast 18:9-46",
			"decl X509Certificate a init=cast 7:9-49",
			"decl X509Certificate b init=cast 8:9-81",
			"decl X509Certificate c init= 9:9-27",
			"decl X509Certificate d init=other 11:9-41",
			"decl X509Certificate e init=null 11:9-41",
			"decl X509Certificate[] arr init=other 12:9-39",
			"decl java.security.cert.X509Certificate q init=cast 13:9-14:29",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("declarations =\n%v\nwant\n%v", got, want)
	}
}
