// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package contracts_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/scanoss/reach/callgraph/contracts"
)

// mustLoad is a test helper that loads a KnowledgeBase from a YAML string.
// It calls t.Fatal if Load returns an error, so callers don't need to check.
// T4.1: Helper for all Merge() scenario tests.
func mustLoad(t *testing.T, yaml string) *contracts.KnowledgeBase {
	t.Helper()
	kb, err := contracts.Load([]byte(yaml))
	if err != nil {
		t.Fatalf("mustLoad: unexpected Load error: %v", err)
	}
	return kb
}

// TestLoadKnowledgeBase_RejectsMalformedYAML verifies that Load returns an error for malformed YAML input.
func TestLoadKnowledgeBase_RejectsMalformedYAML(t *testing.T) {
	t.Parallel()

	_, err := contracts.Load([]byte("not yaml: ["))
	if err == nil {
		t.Fatal("expected error for malformed YAML, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsMissingSchemaVersion verifies that Load returns an error when schema_version is absent.
func TestLoadKnowledgeBase_RejectsMissingSchemaVersion(t *testing.T) {
	t.Parallel()

	yamlNoVersion := `
ecosystem: java
contracts: []
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlNoVersion))
	if err == nil {
		t.Fatal("expected error for missing schema_version, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsUnsupportedSchemaVersion verifies that Load returns an error for schema_version values other than "2".
// T1.3: Updated from "2" to "99" so this test remains correct when validateHeader is flipped to accept "2" in T1.5.
func TestLoadKnowledgeBase_RejectsUnsupportedSchemaVersion(t *testing.T) {
	t.Parallel()

	yamlBadVersion := `
schema_version: "99"
ecosystem: java
contracts: []
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlBadVersion))
	if err == nil {
		t.Fatal("expected error for unsupported schema_version, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsMissingEcosystem verifies that Load returns an error when the ecosystem field is absent.
func TestLoadKnowledgeBase_RejectsMissingEcosystem(t *testing.T) {
	t.Parallel()

	yamlNoEco := `
schema_version: "2"
library:
  name: test
contracts: []
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlNoEco))
	if err == nil {
		t.Fatal("expected error for missing ecosystem, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsNegativeArity verifies that Load returns an error for contracts with arity < 0.
func TestLoadKnowledgeBase_RejectsNegativeArity(t *testing.T) {
	t.Parallel()

	yamlNegArity := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: -1
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlNegArity))
	if err == nil {
		t.Fatal("expected error for arity -1, got nil")
	}
}

func TestLoadKnowledgeBase_ParsesVarargsFlag(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: io.netty.handler.ssl.SslContextBuilder.protocols
    arity: 1
    varargs: true
    return:
      type: io.netty.handler.ssl.SslContextBuilder
      confidence: high
  - method: io.netty.handler.ssl.SslContextBuilder.ciphers
    arity: 1
    return:
      type: io.netty.handler.ssl.SslContextBuilder
      confidence: high
hierarchy: {}
`)
	varargs := kb.ContractsFor("io.netty.handler.ssl.SslContextBuilder.protocols", 1)
	if len(varargs) != 1 || !varargs[0].Varargs {
		t.Fatalf("protocols#1 varargs flag not loaded: %+v", varargs)
	}
	positional := kb.ContractsFor("io.netty.handler.ssl.SslContextBuilder.ciphers", 1)
	if len(positional) != 1 || positional[0].Varargs {
		t.Fatalf("ciphers#1 must default to varargs=false: %+v", positional)
	}
}

func TestLoadKnowledgeBase_RejectsVarargsAtArityZero(t *testing.T) {
	t.Parallel()

	yamlVarargsZero := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: io.netty.handler.ssl.SslContextBuilder.build
    arity: 0
    varargs: true
    return:
      type: io.netty.handler.ssl.SslContext
      confidence: high
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlVarargsZero))
	if err == nil {
		t.Fatal("expected error for varargs at arity 0 (the variadic parameter occupies one slot), got nil")
	}
}

func TestLoadKnowledgeBase_ParsesCanonicalSignatureTypes(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: example.Cipher.init
    arity: 2
    parameter_types: [int, java.security.Key]
    canonical_return_type: void
    return: {type: void, confidence: high}
hierarchy: {}
`)

	got := kb.ContractsFor("example.Cipher.init", 2)
	if len(got) != 1 || !slices.Equal(got[0].ParameterTypes, []string{"int", "java.security.Key"}) {
		t.Fatalf("parameter types = %#v", got)
	}
	if got[0].CanonicalReturnType != "void" {
		t.Fatalf("canonical return type = %q, want void", got[0].CanonicalReturnType)
	}
}

func TestMerge_CanonicalParameterTypesEnrichUnknownContract(t *testing.T) {
	withoutTypes := mustLoad(t, `
schema_version: "2"
ecosystem: java
library: {name: without-types}
contracts:
  - method: example.Cipher.init
    arity: 2
    return: {type: void, confidence: high}
hierarchy: {}
`)
	withTypes := mustLoad(t, `
schema_version: "2"
ecosystem: java
library: {name: with-types}
contracts:
  - method: example.Cipher.init
    arity: 2
    parameter_types: [int, java.security.Key]
    return: {type: void, confidence: high}
hierarchy: {}
`)

	merged, err := contracts.Merge(withoutTypes, withTypes)
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	matches := merged.ContractsFor("example.Cipher.init", 2)
	if len(matches) != 1 || !slices.Equal(matches[0].ParameterTypes, []string{"int", "java.security.Key"}) {
		t.Fatalf("merged parameter types = %#v, want canonical types", matches)
	}
}

func TestLoadKnowledgeBase_RejectsParameterTypesArityMismatch(t *testing.T) {
	t.Parallel()

	_, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: example.Cipher.init
    arity: 2
    parameter_types: [int]
    return: {type: void, confidence: high}
hierarchy: {}
`))
	if err == nil || !strings.Contains(err.Error(), "parameter_types length 1 must equal arity 2") {
		t.Fatalf("error = %v", err)
	}
}

// TestLoadKnowledgeBase_RejectsInvalidConfidence verifies that Load returns an error for return.confidence values outside {high, medium, low}.
func TestLoadKnowledgeBase_RejectsInvalidConfidence(t *testing.T) {
	t.Parallel()

	yamlBadConf := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: veryhigh
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlBadConf))
	if err == nil {
		t.Fatal("expected error for invalid confidence, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsEmptyMethod verifies that Load returns an error when a contract has an empty method field.
func TestLoadKnowledgeBase_RejectsEmptyMethod(t *testing.T) {
	t.Parallel()

	yamlEmptyMethod := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: ""
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlEmptyMethod))
	if err == nil {
		t.Fatal("expected error for empty method, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsEmptyReturnType verifies that Load returns an error when return.type is an empty string.
func TestLoadKnowledgeBase_RejectsEmptyReturnType(t *testing.T) {
	t.Parallel()

	yamlEmptyType := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: ""
      confidence: high
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlEmptyType))
	if err == nil {
		t.Fatal("expected error for empty return.type, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsDuplicateUnconditionalContracts verifies that Load returns an error when two unconditional contracts share the same method#arity key.
func TestLoadKnowledgeBase_RejectsDuplicateUnconditionalContracts(t *testing.T) {
	t.Parallel()

	yamlDup := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: medium
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlDup))
	if err == nil {
		t.Fatal("expected error for duplicate unconditional contract at same method#arity, got nil")
	}
}

// TestLoadKnowledgeBase_ParsesConditionalContracts
// Cipher.unwrap with SECRET_KEY/PRIVATE_KEY/PUBLIC_KEY conditions should parse as 3 entries at the same key.
func TestLoadKnowledgeBase_ParsesConditionalContracts(t *testing.T) {
	t.Parallel()

	yamlConditional := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in:
        - "javax.crypto.Cipher.SECRET_KEY"
        - "Cipher.SECRET_KEY"
        - "3"
    return:
      type: javax.crypto.SecretKey
      confidence: high
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in:
        - "javax.crypto.Cipher.PRIVATE_KEY"
        - "Cipher.PRIVATE_KEY"
        - "2"
    return:
      type: java.security.PrivateKey
      confidence: high
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in:
        - "javax.crypto.Cipher.PUBLIC_KEY"
        - "Cipher.PUBLIC_KEY"
        - "1"
    return:
      type: java.security.PublicKey
      confidence: high
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
  java.security.PrivateKey: [java.security.Key]
  java.security.PublicKey: [java.security.Key]
  java.security.Key: [java.lang.Object]
`
	kb, err := contracts.Load([]byte(yamlConditional))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries := kb.ContractsFor("javax.crypto.Cipher.unwrap", 3)
	if len(entries) != 3 {
		t.Fatalf("expected 3 contracts for Cipher.unwrap#3, got %d", len(entries))
	}

	// All should be conditional
	for i, e := range entries {
		if e.When == nil {
			t.Errorf("entry[%d]: expected When != nil (conditional contract)", i)
		}
		if e.Arity != 3 {
			t.Errorf("entry[%d]: expected arity 3, got %d", i, e.Arity)
		}
	}

	// Collect return types — should be the three distinct types
	types := map[string]struct{}{}
	for _, e := range entries {
		types[e.Return.Type] = struct{}{}
	}
	for _, expected := range []string{"javax.crypto.SecretKey", "java.security.PrivateKey", "java.security.PublicKey"} {
		if _, ok := types[expected]; !ok {
			t.Errorf("expected return type %q to be present among conditional contracts", expected)
		}
	}
}

// TestSchemaV2_Accepted verifies that Load() accepts schema_version "2" with a valid library block.
// T1.1: RED until validateHeader is updated (T1.5). This test MUST fail before the implementation flip.
func TestSchemaV2_Accepted(t *testing.T) {
	t.Parallel()

	yamlV2 := `
schema_version: "2"
ecosystem: java
library:
  name: test
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`
	kb, err := contracts.Load([]byte(yamlV2))
	if err != nil {
		t.Fatalf("expected no error for schema_version \"2\" with library block, got: %v", err)
	}
	if kb == nil {
		t.Fatal("expected non-nil KnowledgeBase, got nil")
	}
	if kb.Library == nil {
		t.Fatal("expected kb.Library to be non-nil after loading v2 YAML")
	}
	if kb.Library.Name != "test" {
		t.Errorf("expected kb.Library.Name == \"test\", got %q", kb.Library.Name)
	}
}

// TestSchemaV1_HardRejected verifies that Load() rejects schema_version "1" with an error.
// T1.2: Currently this test PASSES (v1 is accepted). After T1.5 it will correctly FAIL during
// the migration window but end GREEN once validateHeader rejects v1.
func TestSchemaV1_HardRejected(t *testing.T) {
	t.Parallel()

	yamlV1 := `
schema_version: "1"
ecosystem: java
contracts: []
hierarchy: {}
`
	_, err := contracts.Load([]byte(yamlV1))
	if err == nil {
		t.Fatal("expected error for schema_version \"1\" (should be hard-rejected), got nil")
	}
}

// TestLoad_PopulatesSourceLibrary verifies that every Contract in a loaded KB has SourceLibrary set
// to the library.name value from the YAML.
// T2.1: RED until SourceLibrary field is added to Contract (T2.3).
func TestLoad_PopulatesSourceLibrary(t *testing.T) {
	t.Parallel()

	yamlData := `
schema_version: "2"
ecosystem: java
library:
  name: test-lib
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`
	kb, err := contracts.Load([]byte(yamlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	entries := kb.ContractsFor("javax.crypto.KeyGenerator.generateKey", 0)
	if len(entries) == 0 {
		t.Fatal("expected at least one contract entry")
	}
	for i, c := range entries {
		if c.SourceLibrary != "test-lib" {
			t.Errorf("entry[%d]: expected SourceLibrary == %q, got %q", i, "test-lib", c.SourceLibrary)
		}
	}
}

// TestLoad_PopulatesLibraryOnKB verifies that kb.Library is populated from the library block.
// T2.2: Confirms kb.Library.Name == library.name after Load().
func TestLoad_PopulatesLibraryOnKB(t *testing.T) {
	t.Parallel()

	yamlData := `
schema_version: "2"
ecosystem: java
library:
  name: my-lib
contracts: []
hierarchy: {}
`
	kb, err := contracts.Load([]byte(yamlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if kb.Library == nil {
		t.Fatal("expected kb.Library to be non-nil, got nil")
	}
	if kb.Library.Name != "my-lib" {
		t.Errorf("expected kb.Library.Name == %q, got %q", "my-lib", kb.Library.Name)
	}
}

// TestLoad_PopulatesSourceLibraryAcrossAllContracts verifies that ALL contracts in a KB with
// multiple entries (different methods, different conditions) have SourceLibrary == library.name.
// T2.3 (test side): RED until SourceLibrary field is added to Contract and population loop is complete.
func TestLoad_PopulatesSourceLibraryAcrossAllContracts(t *testing.T) {
	t.Parallel()

	yamlData := `
schema_version: "2"
ecosystem: java
library:
  name: multi-lib
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in:
        - "javax.crypto.Cipher.SECRET_KEY"
    return:
      type: javax.crypto.SecretKey
      confidence: high
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in:
        - "javax.crypto.Cipher.PRIVATE_KEY"
    return:
      type: java.security.PrivateKey
      confidence: high
hierarchy: {}
`
	kb, err := contracts.Load([]byte(yamlData))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for key, entries := range kb.Contracts {
		for i, c := range entries {
			if c.SourceLibrary != "multi-lib" {
				t.Errorf("key=%q entry[%d]: expected SourceLibrary == %q, got %q", key, i, "multi-lib", c.SourceLibrary)
			}
		}
	}
}

// ── TDD Pair 1: Basic Merge scenarios (T4.1 + T4.2 RED → T4.3 GREEN) ────────

// TestMerge_NoKBs_ReturnsEmpty verifies that Merge() with no arguments returns
// a non-nil empty KnowledgeBase with no error.
func TestMerge_NoKBs_ReturnsEmpty(t *testing.T) {
	t.Parallel()

	kb, err := contracts.Merge()
	if err != nil {
		t.Fatalf("Merge(): expected nil error, got %v", err)
	}
	if kb == nil {
		t.Fatal("Merge(): expected non-nil KnowledgeBase, got nil")
	}
	if len(kb.Contracts) != 0 {
		t.Errorf("Merge(): expected 0 contracts, got %d", len(kb.Contracts))
	}
	if len(kb.Hierarchy) != 0 {
		t.Errorf("Merge(): expected 0 hierarchy edges, got %d", len(kb.Hierarchy))
	}
}

// TestMerge_SingleKB_ReturnsClone verifies that Merge(kb) returns a clone of the
// single KB, and that mutating the result does not affect the original.
func TestMerge_SingleKB_ReturnsClone(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-a
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
`)

	result, err := contracts.Merge(kb)
	if err != nil {
		t.Fatalf("Merge(kb): expected nil error, got %v", err)
	}
	if result == nil {
		t.Fatal("Merge(kb): expected non-nil result, got nil")
	}

	// Count original contracts
	origTotal := 0
	for _, cs := range kb.Contracts {
		origTotal += len(cs)
	}
	resultTotal := 0
	for _, cs := range result.Contracts {
		resultTotal += len(cs)
	}
	if resultTotal != origTotal {
		t.Errorf("Merge(kb): expected %d contracts in clone, got %d", origTotal, resultTotal)
	}
	if len(result.Hierarchy) != len(kb.Hierarchy) {
		t.Errorf("Merge(kb): expected %d hierarchy edges in clone, got %d", len(kb.Hierarchy), len(result.Hierarchy))
	}

	// Mutate result — original must be unaffected
	result.Contracts["mutated-key"] = []contracts.Contract{{Method: "mutated"}}
	if _, ok := kb.Contracts["mutated-key"]; ok {
		t.Error("Merge(kb): mutating clone affected the original — not a deep clone")
	}
}

// TestMerge_TwoLibraries_NoConflicts_MergesCleanly verifies that two KBs with
// non-overlapping contracts and hierarchy are merged correctly.
func TestMerge_TwoLibraries_NoConflicts_MergesCleanly(t *testing.T) {
	t.Parallel()

	libA := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-a
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
`)

	libB := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-b
contracts:
  - method: java.security.KeyFactory.generatePrivate
    arity: 1
    return:
      type: java.security.PrivateKey
      confidence: high
hierarchy:
  java.security.PrivateKey: [java.security.Key]
`)

	merged, err := contracts.Merge(libA, libB)
	if err != nil {
		t.Fatalf("Merge(libA, libB): unexpected error: %v", err)
	}
	if merged == nil {
		t.Fatal("Merge(libA, libB): expected non-nil result")
	}

	// Expect both contracts present
	if _, ok := merged.Contracts["javax.crypto.KeyGenerator.generateKey#0"]; !ok {
		t.Error("merged KB missing libA contract: KeyGenerator.generateKey#0")
	}
	if _, ok := merged.Contracts["java.security.KeyFactory.generatePrivate#1"]; !ok {
		t.Error("merged KB missing libB contract: KeyFactory.generatePrivate#1")
	}

	// Expect both hierarchy edges
	if _, ok := merged.Hierarchy["javax.crypto.SecretKey"]; !ok {
		t.Error("merged KB missing libA hierarchy: SecretKey")
	}
	if _, ok := merged.Hierarchy["java.security.PrivateKey"]; !ok {
		t.Error("merged KB missing libB hierarchy: PrivateKey")
	}

	// Library should be nil (merged KB represents >1 library)
	if merged.Library != nil {
		t.Error("merged KB: expected Library == nil for multi-library merge")
	}
}

// ── TDD Pair 2: Conflict rules + ecosystem + uniqueness (T4.3 RED → T4.4 GREEN) ─

// TestMerge_IdempotentContract_C1 verifies rule 1: same key + identical contract
// from two libraries → merged once, no error.
func TestMerge_IdempotentContract_C1(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-1
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-2
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C1: unexpected error: %v", err)
	}
	entries := merged.Contracts["javax.crypto.Cipher.unwrap#3"]
	if len(entries) != 1 {
		t.Errorf("Merge C1: expected 1 deduplicated entry, got %d", len(entries))
	}
}

// TestMerge_ConflictingContract_C2_ErrorNamesBothLibraries verifies rule 2:
// same key + same condition + different return → HARD ERROR naming both libraries.
func TestMerge_ConflictingContract_C2_ErrorNamesBothLibraries(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-a
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-b
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: java.security.PrivateKey
      confidence: high
hierarchy: {}
`)

	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("Merge C2: expected HARD ERROR for conflicting contract, got nil")
	}
	if !strings.Contains(err.Error(), "lib-a") {
		t.Errorf("Merge C2: expected error to contain %q, got: %v", "lib-a", err)
	}
	if !strings.Contains(err.Error(), "lib-b") {
		t.Errorf("Merge C2: expected error to contain %q, got: %v", "lib-b", err)
	}
}

// TestMerge_SetBasedConditionEquality_C3 verifies that arg_value_in order is
// irrelevant: ["A","B"] and ["B","A"] are treated as the same condition (idempotent).
func TestMerge_SetBasedConditionEquality_C3(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c3-1
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["A", "B"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c3-2
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["B", "A"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C3: expected idempotent merge (no error), got: %v", err)
	}
	entries := merged.Contracts["javax.crypto.Cipher.unwrap#3"]
	if len(entries) != 1 {
		t.Errorf("Merge C3: expected 1 entry (set-based dedup), got %d", len(entries))
	}
}

// TestMerge_DifferentConditions_BothRetained_C4 verifies that two contracts with
// the same method+arity but different conditions are both retained.
func TestMerge_DifferentConditions_BothRetained_C4(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c4-1
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c4-2
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.PRIVATE_KEY"]
    return:
      type: java.security.PrivateKey
      confidence: high
hierarchy: {}
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C4: unexpected error: %v", err)
	}
	entries := merged.Contracts["javax.crypto.Cipher.unwrap#3"]
	if len(entries) != 2 {
		t.Errorf("Merge C4: expected 2 contracts (different conditions), got %d", len(entries))
	}
}

// TestMerge_IdempotentHierarchy_C5 verifies rule 3: same child→[A] in both
// libraries → merged KB contains it exactly once.
func TestMerge_IdempotentHierarchy_C5(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c5-1
contracts: []
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c5-2
contracts: []
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C5: unexpected error: %v", err)
	}
	parents := merged.Hierarchy["javax.crypto.SecretKey"]
	if len(parents) != 1 || parents[0] != "java.security.Key" {
		t.Errorf("Merge C5: expected [java.security.Key], got %v", parents)
	}
}

// TestMerge_ConflictingHierarchy_C6_ErrorNamesBothLibraries verifies rule 4:
// child→[A] vs child→[B] → HARD ERROR naming both source libraries.
func TestMerge_ConflictingHierarchy_C6_ErrorNamesBothLibraries(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c6-a
contracts: []
hierarchy:
  com.example.X: [com.example.A]
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c6-b
contracts: []
hierarchy:
  com.example.X: [com.example.B]
`)

	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("Merge C6: expected HARD ERROR for conflicting hierarchy, got nil")
	}
	if !strings.Contains(err.Error(), "lib-c6-a") {
		t.Errorf("Merge C6: expected error to contain %q, got: %v", "lib-c6-a", err)
	}
	if !strings.Contains(err.Error(), "lib-c6-b") {
		t.Errorf("Merge C6: expected error to contain %q, got: %v", "lib-c6-b", err)
	}
}

// TestMerge_HierarchySubsetUnion_C7 verifies rule 5: child→[A] vs child→[A,B]
// → union output is [A,B].
func TestMerge_HierarchySubsetUnion_C7(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c7-1
contracts: []
hierarchy:
  com.example.X: [com.example.A]
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c7-2
contracts: []
hierarchy:
  com.example.X: [com.example.A, com.example.B]
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C7: unexpected error: %v", err)
	}
	parents := merged.Hierarchy["com.example.X"]
	if len(parents) != 2 {
		t.Errorf("Merge C7: expected 2 parents in union, got %d: %v", len(parents), parents)
	}
	hasA, hasB := false, false
	for _, p := range parents {
		if p == "com.example.A" {
			hasA = true
		}
		if p == "com.example.B" {
			hasB = true
		}
	}
	if !hasA || !hasB {
		t.Errorf("Merge C7: expected both A and B in union, got %v", parents)
	}
}

// TestMerge_EmptyLibrary_C8_NoOp verifies that merging a KB with zero contracts
// and zero hierarchy is a no-op — the result matches the non-empty KB.
func TestMerge_EmptyLibrary_C8_NoOp(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c8-full
contracts:
  - method: javax.crypto.KeyGenerator.generateKey
    arity: 0
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy:
  javax.crypto.SecretKey: [java.security.Key]
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-c8-empty
contracts: []
hierarchy: {}
`)

	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("Merge C8: unexpected error: %v", err)
	}

	total := 0
	for _, cs := range merged.Contracts {
		total += len(cs)
	}
	if total != 1 {
		t.Errorf("Merge C8: expected 1 contract (lib2 is empty), got %d", total)
	}
	if len(merged.Hierarchy) != 1 {
		t.Errorf("Merge C8: expected 1 hierarchy edge, got %d", len(merged.Hierarchy))
	}
}

// TestMerge_DuplicateLibraryName_Errors verifies that two KBs with the same
// library.name cause Merge() to return a non-nil error.
func TestMerge_DuplicateLibraryName_Errors(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: same-lib
contracts: []
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: same-lib
contracts: []
hierarchy: {}
`)

	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("Merge duplicate library name: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "same-lib") {
		t.Errorf("Merge duplicate library name: expected error to contain %q, got: %v", "same-lib", err)
	}
}

// ── T-1.1: Python embed + loader tests (RED until T-1.3 adds the embed + YAML) ─

// TestMerge_EcosystemMismatch_Errors verifies that KBs with different ecosystem
// strings cause Merge() to return a non-nil error.
func TestMerge_EcosystemMismatch_Errors(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: eco-lib-1
contracts: []
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: python
library:
  name: eco-lib-2
contracts: []
hierarchy: {}
`)

	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("Merge ecosystem mismatch: expected error, got nil")
	}
}

// TestMerge_SourceLibrary_InConflictDiagnostic_D2 verifies that conflict error
// messages contain both library.name values (diagnostic completeness, spec D2).
func TestMerge_SourceLibrary_InConflictDiagnostic_D2(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-diag-a
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: javax.crypto.SecretKey
      confidence: high
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: lib-diag-b
contracts:
  - method: javax.crypto.Cipher.unwrap
    arity: 3
    when:
      arg_index: 2
      arg_value_in: ["javax.crypto.Cipher.SECRET_KEY"]
    return:
      type: java.security.PrivateKey
      confidence: high
hierarchy: {}
`)

	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("Merge D2: expected error for conflicting contract, got nil")
	}
	if !strings.Contains(err.Error(), "lib-diag-a") {
		t.Errorf("Merge D2: error missing %q: %v", "lib-diag-a", err)
	}
	if !strings.Contains(err.Error(), "lib-diag-b") {
		t.Errorf("Merge D2: error missing %q: %v", "lib-diag-b", err)
	}
}

// ── issue-103: role enum validation + Parameters sub-schema ──────────────────

// TestContract_RoleOperation_Accepted verifies that role: operation loads
// successfully now that the role taxonomy is enum-validated.
func TestContract_RoleOperation_Accepted(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: test-role-operation
contracts:
  - method: org.bouncycastle.crypto.BlockCipher.processBlock
    arity: 4
    return:
      type: int
      confidence: high
    role: operation
hierarchy: {}
`)
	entries := kb.ContractsFor("org.bouncycastle.crypto.BlockCipher.processBlock", 4)
	if len(entries) != 1 || entries[0].Role != "operation" {
		t.Fatalf("expected 1 contract with role=operation, got %#v", entries)
	}
}

// TestContract_RejectsInvalidRole_NamesMethod verifies that an unknown role
// value fails Load, naming the offending method.
func TestContract_RejectsInvalidRole_NamesMethod(t *testing.T) {
	t.Parallel()

	_, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: java
library:
  name: test-bad-role
contracts:
  - method: com.example.Foo.bar
    arity: 0
    return:
      type: com.example.Foo
      confidence: high
    role: bogus
hierarchy: {}
`))
	if err == nil {
		t.Fatal("expected error for invalid role, got nil")
	}
	if !strings.Contains(err.Error(), "com.example.Foo.bar") {
		t.Errorf("error should name the offending method, got: %v", err)
	}
}

// TestContract_ParsesParameters_IndexAligned verifies the Parameters
// sub-schema parses index-aligned parameter role/contribution entries.
func TestContract_ParsesParameters_IndexAligned(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: test-parameters
contracts:
  - method: org.bouncycastle.crypto.params.KeyParameter.<init>
    arity: 1
    return:
      type: org.bouncycastle.crypto.params.KeyParameter
      confidence: high
    parameters:
      - index: 0
        role: metadata-contributing
        contributes:
          property: key_length_bits
          derivation: argument_bit_length
hierarchy: {}
`)
	entries := kb.ContractsFor("org.bouncycastle.crypto.params.KeyParameter.<init>", 1)
	if len(entries) != 1 {
		t.Fatalf("expected 1 contract, got %d", len(entries))
	}
	params := entries[0].Parameters
	if len(params) != 1 {
		t.Fatalf("expected 1 parameter contract, got %d: %#v", len(params), params)
	}
	p := params[0]
	if p.Index == nil || *p.Index != 0 {
		t.Fatalf("expected parameter index 0, got %#v", p.Index)
	}
	if p.Role != "metadata-contributing" {
		t.Fatalf("expected role metadata-contributing, got %q", p.Role)
	}
	if p.Contributes == nil || p.Contributes.Property != "key_length_bits" || p.Contributes.Derivation != "argument_bit_length" {
		t.Fatalf("expected contributes {key_length_bits, argument_bit_length}, got %#v", p.Contributes)
	}
}

// TestContract_RejectsInvalidDerivation_NamesMethodAndField verifies that an
// unknown derivation value fails Load, naming the method and field.
func TestContract_RejectsInvalidDerivation_NamesMethodAndField(t *testing.T) {
	t.Parallel()

	_, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: java
library:
  name: test-bad-derivation
contracts:
  - method: com.example.Foo.bar
    arity: 1
    return:
      type: com.example.Foo
      confidence: high
    parameters:
      - index: 0
        role: metadata-contributing
        contributes:
          property: key_length_bits
          derivation: bogus_value
hierarchy: {}
`))
	if err == nil {
		t.Fatal("expected error for invalid derivation, got nil")
	}
	if !strings.Contains(err.Error(), "com.example.Foo.bar") {
		t.Errorf("error should name the offending method, got: %v", err)
	}
	if !strings.Contains(err.Error(), "derivation") {
		t.Errorf("error should name the offending field, got: %v", err)
	}
}

// TestContract_RejectsInvalidParameterRole_NamesMethodAndField verifies that
// an unknown parameter role value fails Load.
func TestContract_RejectsInvalidParameterRole_NamesMethodAndField(t *testing.T) {
	t.Parallel()

	_, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: java
library:
  name: test-bad-param-role
contracts:
  - method: com.example.Foo.bar
    arity: 1
    return:
      type: com.example.Foo
      confidence: high
    parameters:
      - index: 0
        role: bogus-role
hierarchy: {}
`))
	if err == nil {
		t.Fatal("expected error for invalid parameter role, got nil")
	}
	if !strings.Contains(err.Error(), "com.example.Foo.bar") {
		t.Errorf("error should name the offending method, got: %v", err)
	}
}

// TestMerge_IdenticalRole_MergesWithoutError verifies that two libraries
// declaring the same method with identical role merge idempotently.
func TestMerge_IdenticalRole_MergesWithoutError(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: role-lib-1
contracts:
  - method: com.example.Foo.configure
    arity: 0
    return:
      type: void
      confidence: high
    role: config
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: role-lib-2
contracts:
  - method: com.example.Foo.configure
    arity: 0
    return:
      type: void
      confidence: high
    role: config
hierarchy: {}
`)
	merged, err := contracts.Merge(lib1, lib2)
	if err != nil {
		t.Fatalf("expected identical-role merge to succeed, got: %v", err)
	}
	entries := merged.Contracts["com.example.Foo.configure#0"]
	if len(entries) != 1 {
		t.Fatalf("expected 1 deduplicated entry, got %d", len(entries))
	}
}

// TestMerge_DivergentRole_HardErrors verifies that two libraries declaring
// the same method+arity+condition with different role values hard-fail
// Merge, naming both libraries.
func TestMerge_DivergentRole_HardErrors(t *testing.T) {
	t.Parallel()

	lib1 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: role-conflict-a
contracts:
  - method: com.example.Foo.configure
    arity: 0
    return:
      type: void
      confidence: high
    role: config
hierarchy: {}
`)
	lib2 := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: role-conflict-b
contracts:
  - method: com.example.Foo.configure
    arity: 0
    return:
      type: void
      confidence: high
    role: output
hierarchy: {}
`)
	_, err := contracts.Merge(lib1, lib2)
	if err == nil {
		t.Fatal("expected HARD ERROR for divergent role, got nil")
	}
	if !strings.Contains(err.Error(), "role-conflict-a") || !strings.Contains(err.Error(), "role-conflict-b") {
		t.Errorf("error should name both libraries, got: %v", err)
	}
}

// TestBackwardCompat_LegacyContract_NoRoleOrParameters verifies that a
// contract with no role/parameters fields loads exactly as before: Role is
// empty and Parameters is nil.
func TestBackwardCompat_LegacyContract_NoRoleOrParameters(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, `
schema_version: "2"
ecosystem: java
library:
  name: legacy
contracts:
  - method: com.example.Legacy.call
    arity: 0
    return:
      type: com.example.Legacy
      confidence: high
hierarchy: {}
`)
	entries := kb.ContractsFor("com.example.Legacy.call", 0)
	if len(entries) != 1 {
		t.Fatalf("expected 1 contract, got %d", len(entries))
	}
	if entries[0].Role != "" {
		t.Fatalf("expected empty Role for legacy contract, got %q", entries[0].Role)
	}
	if entries[0].Parameters != nil {
		t.Fatalf("expected nil Parameters for legacy contract, got %#v", entries[0].Parameters)
	}
}

// TestLoadKnowledgeBase_ParsesTraitAssociatedTypes verifies trait_associated_types
// entries parse and resolve via KnowledgeBase.TraitAssociatedType.
func TestLoadKnowledgeBase_ParsesTraitAssociatedTypes(t *testing.T) {
	t.Parallel()

	kb := mustLoad(t, `
schema_version: "2"
ecosystem: rust
library: {name: crypto-common-test}
contracts: []
trait_associated_types:
  - trait: KeyInit
    name: KeySize
    type: generic_array::GenericArray
  - trait: SomeTrait
    name: NoDefault
hierarchy: {}
`)
	typ, ok := kb.TraitAssociatedType("KeyInit", "KeySize")
	if !ok || typ != "generic_array::GenericArray" {
		t.Fatalf("TraitAssociatedType(KeyInit, KeySize) = (%q, %v), want (%q, true)", typ, ok, "generic_array::GenericArray")
	}

	// A cataloged (trait, name) pair with no type is still "known" -- ok is
	// true -- but carries nothing a caller can resolve to.
	typ, ok = kb.TraitAssociatedType("SomeTrait", "NoDefault")
	if !ok || typ != "" {
		t.Fatalf("TraitAssociatedType(SomeTrait, NoDefault) = (%q, %v), want (\"\", true)", typ, ok)
	}

	if _, ok := kb.TraitAssociatedType("Uncataloged", "Anything"); ok {
		t.Fatal("expected ok=false for an uncataloged (trait, name) pair")
	}
}

// TestLoadKnowledgeBase_RejectsTraitAssociatedTypeMissingTrait verifies trait
// is required on every trait_associated_types entry.
func TestLoadKnowledgeBase_RejectsTraitAssociatedTypeMissingTrait(t *testing.T) {
	t.Parallel()

	_, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: rust
library: {name: test}
contracts: []
trait_associated_types:
  - name: KeySize
    type: generic_array::GenericArray
hierarchy: {}
`))
	if err == nil {
		t.Fatal("expected error for trait_associated_types entry missing trait, got nil")
	}
}

// TestLoadKnowledgeBase_RejectsTraitAssociatedTypeMissingName verifies name is
// required on every trait_associated_types entry.
func TestLoadKnowledgeBase_RejectsTraitAssociatedTypeMissingName(t *testing.T) {
	t.Parallel()

	_, err := contracts.Load([]byte(`
schema_version: "2"
ecosystem: rust
library: {name: test}
contracts: []
trait_associated_types:
  - trait: KeyInit
    type: generic_array::GenericArray
hierarchy: {}
`))
	if err == nil {
		t.Fatal("expected error for trait_associated_types entry missing name, got nil")
	}
}

// TestMerge_TraitAssociatedTypes_IdenticalIsIdempotent verifies two libraries
// declaring the same (trait, name) -> type merge without error, mirroring
// contract merge rule 1.
func TestMerge_TraitAssociatedTypes_IdenticalIsIdempotent(t *testing.T) {
	t.Parallel()

	a := mustLoad(t, `
schema_version: "2"
ecosystem: rust
library: {name: lib-a}
contracts: []
trait_associated_types:
  - trait: KeyInit
    name: KeySize
    type: generic_array::GenericArray
hierarchy: {}
`)
	b := mustLoad(t, `
schema_version: "2"
ecosystem: rust
library: {name: lib-b}
contracts: []
trait_associated_types:
  - trait: KeyInit
    name: KeySize
    type: generic_array::GenericArray
hierarchy: {}
`)
	merged, err := contracts.Merge(a, b)
	if err != nil {
		t.Fatalf("Merge() error = %v", err)
	}
	typ, ok := merged.TraitAssociatedType("KeyInit", "KeySize")
	if !ok || typ != "generic_array::GenericArray" {
		t.Fatalf("merged TraitAssociatedType = (%q, %v), want (%q, true)", typ, ok, "generic_array::GenericArray")
	}
}

// TestMerge_TraitAssociatedTypes_ConflictingTypeIsHardError verifies two
// libraries declaring the same (trait, name) with a DIFFERENT type is a hard
// error naming both libraries, mirroring contract merge rule 2.
func TestMerge_TraitAssociatedTypes_ConflictingTypeIsHardError(t *testing.T) {
	t.Parallel()

	a := mustLoad(t, `
schema_version: "2"
ecosystem: rust
library: {name: lib-a}
contracts: []
trait_associated_types:
  - trait: KeyInit
    name: KeySize
    type: generic_array::GenericArray
hierarchy: {}
`)
	b := mustLoad(t, `
schema_version: "2"
ecosystem: rust
library: {name: lib-b}
contracts: []
trait_associated_types:
  - trait: KeyInit
    name: KeySize
    type: some_other_crate::Size
hierarchy: {}
`)
	_, err := contracts.Merge(a, b)
	if err == nil {
		t.Fatal("expected conflict error for divergent trait_associated_types entries, got nil")
	}
	if !strings.Contains(err.Error(), "lib-a") || !strings.Contains(err.Error(), "lib-b") {
		t.Fatalf("expected error to name both libraries, got: %v", err)
	}
}
