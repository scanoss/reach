// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// A local or parameter written more than once keeps no single source, but the
// string literals it is assigned are recorded as the values it may hold at a
// use, initializer first; a variable assigned something else adds nothing.
func TestJavaArgumentMayValues(t *testing.T) {
	src := `package app;
import java.security.Signature;
class Y {
    Signature branches(int alg) throws Exception {
        String jcaAlg;
        if (alg == 1) {
            jcaAlg = "SHA256withECDSA";
        } else {
            jcaAlg = "SHA384withECDSA";
        }
        return Signature.getInstance(jcaAlg);
    }
    Signature initialized(boolean b, String other) throws Exception {
        String name = "SHA256withRSA";
        if (b) {
            name = other;
        }
        return Signature.getInstance(name);
    }
    Signature parameter(String name) throws Exception {
        if (name == null) {
            name = "SHA1withDSA";
        }
        return Signature.getInstance(name);
    }
    Signature single() throws Exception {
        String name = "SHA512withECDSA";
        return Signature.getInstance(name);
    }
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "Y.java"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string][]string{}
	exhaustive := map[string]bool{}
	sources := map[string]int{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			for j := range fn.Calls {
				call := &fn.Calls[j]
				if BaseFunctionName(call.Callee.Name) != "getInstance" || len(call.ArgumentSources) == 0 || len(call.ArgumentSources[0]) != 1 {
					continue
				}
				node := call.ArgumentSources[0][0]
				got[BaseFunctionName(fn.ID.Name)] = node.MayValues
				exhaustive[BaseFunctionName(fn.ID.Name)] = node.MayValuesExhaustive
				sources[BaseFunctionName(fn.ID.Name)] = len(node.SourceNodes)
			}
		}
	}
	want := map[string][]string{
		"branches":    {`"SHA256withECDSA"`, `"SHA384withECDSA"`},
		"initialized": {`"SHA256withRSA"`},
		"parameter":   {`"SHA1withDSA"`},
		"single":      nil,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("may values = %#v, want %#v", got, want)
	}
	// Only the local every write of which is a literal always holds a string
	// constant; a parameter holds its caller's value too.
	if want := map[string]bool{"branches": true, "initialized": false, "parameter": false, "single": false}; !reflect.DeepEqual(exhaustive, want) {
		t.Errorf("exhaustive = %v, want %v", exhaustive, want)
	}
	// The reassigned names still claim no single source; the one-assignment
	// local keeps its initializer as its source.
	if sources["initialized"] != 0 || sources["parameter"] != 0 || sources["single"] != 1 {
		t.Errorf("source node counts = %v", sources)
	}
}
