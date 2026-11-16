// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/scanoss/reach/skip"
)

func writeTestFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A Java build records the ServiceLoader registrations of its sources, from
// a sources JAR's root and from a Maven resources directory alike, as
// ServiceLoader reads them; a test resource directory is skipped when the
// scan's matcher skips test sources.
func TestBuildRecordsJavaServiceProviders(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, "org", "plug", "PdfParser.java"), "package org.plug;\npublic class PdfParser {\n  public void parse() {}\n}\n")
	writeTestFile(t, filepath.Join(root, "META-INF", "services", "org.core.Parser"),
		"# parsers\n\uFEFForg.plug.PdfParser\n\norg.plug.Formats$Zip # nested\nnot a class name\norg.plug.PdfParser\n")
	writeTestFile(t, filepath.Join(root, "module", "src", "main", "resources", "META-INF", "services", "org.core.Detector"), "org.plug.MagicDetector\n")
	writeTestFile(t, filepath.Join(root, "module", "src", "test", "resources", "META-INF", "services", "org.core.Parser"), "org.plug.TestParser\n")
	writeTestFile(t, filepath.Join(root, "META-INF", "services", "README"), "org.plug.Ignored\n")

	builder := NewBuilderForEcosystem(ecosystemJava, NewJavaParser())
	builder.SetSkipMatcher(skip.NewMatcher(skip.DefaultSkippedTestPatterns, true))
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: root, ImportPath: ""}}, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	want := map[string][]string{
		"org.core.Parser":   {"org.plug.PdfParser", "org.plug.Formats$Zip"},
		"org.core.Detector": {"org.plug.MagicDetector"},
	}
	if !reflect.DeepEqual(graph.ServiceProviders, want) {
		t.Errorf("ServiceProviders = %v, want %v", graph.ServiceProviders, want)
	}
}

func TestIsJavaBinaryName(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{
		"org.apache.tika.parser.Parser": true,
		"a.Outer$Inner":                 true,
		"a.b1._C":                       true,
		"Parser":                        false,
		"a..b":                          false,
		"a.1b":                          false,
		"a.b c":                         false,
		"README":                        false,
	} {
		if got := isJavaBinaryName(name); got != want {
			t.Errorf("isJavaBinaryName(%q) = %v, want %v", name, got, want)
		}
	}
}
