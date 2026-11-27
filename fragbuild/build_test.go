// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scanoss/reach/callgraph"
)

// Build needs no contracts: with a nil KB it still exports the functions,
// edges and external calls of the graph.
func TestBuildWithoutContracts(t *testing.T) {
	dir := t.TempDir()
	src := "import json\n\ndef load(path):\n    return parse(open(path).read())\n\ndef parse(text):\n    return json.loads(text)\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	parser := callgraph.NewParserForEcosystem(EcosystemPython)
	graph, err := callgraph.NewBuilderForEcosystem(EcosystemPython, parser).
		BuildFromDirectories([]callgraph.PackageDir{{Dir: dir}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out := Build(Input{Graph: graph, Ecosystem: EcosystemPython, ProjectRoot: dir})
	if len(out.Functions) < 2 || len(out.InternalEdges) == 0 || len(out.ExternalCalls) == 0 {
		t.Fatalf("got %d functions, %d internal edges, %d external calls; want a complete fragment",
			len(out.Functions), len(out.InternalEdges), len(out.ExternalCalls))
	}
	if out.ScanMetadata.Ecosystem != EcosystemPython || out.ScanMetadata.FunctionCount != len(out.Functions) {
		t.Fatalf("scan metadata %+v does not describe the fragment", out.ScanMetadata)
	}
}
