// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// A Java method declared without a body is abstract: the stitch reads every
// other method, an empty one included, as a body a call on its type may run.
func TestJavaParser_MarksMethodsWithoutBodyAbstract(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	src := `package p;
interface Sink {
	void write();
	default void flush() {}
	static Sink none() { return null; }
}
abstract class Base implements Sink {
	protected abstract void close();
	protected void flushFields() {}
	native int handle();
}
`
	if err := os.WriteFile(filepath.Join(dir, "P.java"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	analyses, err := NewJavaParser().ParseDirectory(dir, "p")
	if err != nil {
		t.Fatalf("ParseDirectory: %v", err)
	}
	got := map[string]bool{}
	for _, analysis := range analyses {
		for i := range analysis.Functions {
			fn := &analysis.Functions[i]
			got[fn.ID.Type+"."+fn.ID.Name] = fn.Abstract
		}
	}
	want := map[string]bool{
		"Sink.write#0":       true,
		"Sink.flush#0":       false,
		"Sink.none#0":        false,
		"Base.close#0":       true,
		"Base.flushFields#0": false,
		"Base.handle#0":      false,
	}
	for name, abstract := range want {
		if a, ok := got[name]; !ok || a != abstract {
			t.Errorf("%s: abstract = %v (found %v), want %v; all: %v", name, a, ok, abstract, got)
		}
	}
}
