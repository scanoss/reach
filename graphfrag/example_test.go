// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag_test

import (
	"fmt"

	"github.com/scanoss/reach/graphfrag"
)

// A domain stores one fragment per component version and stitches the
// dependency closure of an application to learn which application code
// reaches a target. Here the target is a vulnerable function of a library,
// attached to the library's fragment as an annotation (the crypto_* names
// are the stored format's, whatever the domain). The application calls the
// library's parse, which calls the vulnerable decode; the stitch returns the
// chain from the application's entry to it.
func ExampleStitch() {
	app := graphfrag.ComponentKey{Purl: "pkg:maven/com.acme/app", Version: "1.0.0"}
	lib := graphfrag.ComponentKey{Purl: "pkg:maven/org.example/lib", Version: "2.3.1"}

	appFragment, err := graphfrag.DecodeFragment(app, []byte(`{
	  "schema_version": "graph-fragment-1.25",
	  "scan_metadata": {"ecosystem": "java", "root_module": "com.acme:app"},
	  "functions": [{"key": "com.acme.(App).main#1", "function_name": "com.acme.App.main", "file_path": "App.java", "start_line": 3}],
	  "external_calls": [{
	    "caller_key": "com.acme.(App).main#1",
	    "target_key": "org.example.(Parser).parse#1",
	    "line": 4,
	    "resolution": "exact"
	  }]
	}`))
	if err != nil {
		panic(err)
	}
	libFragment, err := graphfrag.DecodeFragment(lib, []byte(`{
	  "schema_version": "graph-fragment-1.25",
	  "scan_metadata": {"ecosystem": "java", "root_module": "org.example:lib"},
	  "functions": [
	    {"key": "org.example.(Parser).parse#1", "function_name": "org.example.Parser.parse", "file_path": "Parser.java", "start_line": 10},
	    {"key": "org.example.(Codec).decode#1", "function_name": "org.example.Codec.decode", "file_path": "Codec.java", "start_line": 20}
	  ],
	  "internal_edges": [{
	    "caller_key": "org.example.(Parser).parse#1",
	    "callee_key": "org.example.(Codec).decode#1",
	    "line": 11,
	    "resolution": "exact"
	  }],
	  "crypto_annotations": [{
	    "function_key": "org.example.(Codec).decode#1",
	    "finding_id": "vuln-1",
	    "rule_id": "example.vulnerable-decode",
	    "symbol": "org.example.Codec.decode"
	  }]
	}`))
	if err != nil {
		panic(err)
	}

	result, err := graphfrag.Stitch(app,
		graphfrag.DependencyGraph{app: {lib}, lib: nil},
		map[graphfrag.ComponentKey]graphfrag.Fragment{app: appFragment, lib: libFragment})
	if err != nil {
		panic(err)
	}
	for _, chain := range result.Chains {
		fmt.Println(chain.FindingID)
		for _, frame := range chain.Frames {
			fmt.Println(" ", frame.Component, frame.Signature)
		}
	}
	// Output:
	// vuln-1
	//   pkg:maven/com.acme/app@1.0.0 com.acme.(App).main#1
	//   pkg:maven/org.example/lib@2.3.1 org.example.(Parser).parse#1
	//   pkg:maven/org.example/lib@2.3.1 org.example.(Codec).decode#1
}
