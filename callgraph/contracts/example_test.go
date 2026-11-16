// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package contracts_test

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing/fstest"

	"github.com/scanoss/reach/callgraph"
	"github.com/scanoss/reach/callgraph/contracts"
)

// A domain installs its knowledge once, before the first build: a contracts
// source (one directory per ecosystem of *.yaml files) and, optionally,
// language-level hints. Here a one-library Python KB says what
// werkzeug.security.generate_password_hash returns; the builder then parses
// a directory, and the graph's reverse index walks a library call back to
// the application code that reaches it.
func ExampleSetSource() {
	contracts.SetSource(fstest.MapFS{
		"python/werkzeug.yaml": &fstest.MapFile{Data: []byte(`schema_version: "2"
ecosystem: python
library:
  name: werkzeug
  coordinates: [Werkzeug]
  version_range: ">=2.3,<4.0"
contracts:
  - method: werkzeug.security.generate_password_hash
    arity: 1
    return: { type: builtins.str, confidence: high }
    role: output
hierarchy:
  builtins.str: [builtins.object]
  builtins.object: []
`)},
	})
	defer contracts.SetSource(nil)

	dir, err := os.MkdirTemp("", "reach-example")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	src := "from werkzeug.security import generate_password_hash\n\n\ndef store(password):\n    return generate_password_hash(password)\n\n\ndef signup(form):\n    return store(form['password'])\n"
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(src), 0o600); err != nil {
		panic(err)
	}

	builder := callgraph.NewBuilderForEcosystem("python", callgraph.NewParserForEcosystem("python"))
	graph, err := builder.BuildFromDirectories([]callgraph.PackageDir{{Dir: dir, ImportPath: ""}}, nil)
	if err != nil {
		panic(err)
	}
	// Walk back from the library call to the code that reaches it.
	for fn := "werkzeug.security.generate_password_hash"; ; {
		fmt.Println(fn)
		callers := slices.Sorted(slices.Values(graph.Callers[fn]))
		if len(callers) == 0 {
			break
		}
		fn = callers[0]
	}
	// Output:
	// werkzeug.security.generate_password_hash
	// app.store
	// app.signup
}
