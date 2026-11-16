// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"testing"
)

// TestNewBuilderForEcosystem_Python_DoesNotPanic guards REQ-1.5.
// NewBuilderForEcosystem("python", ...) must construct a Builder without panicking.
// Full KB-load assertion is deferred to once the YAML exists (T-1.3); this test
// confirms the constructor wires correctly and is RED until the constructor is added.
func TestNewBuilderForEcosystem_Python_DoesNotPanic(t *testing.T) {
	t.Parallel()

	// Must not panic. NewBuilderForEcosystem does not exist yet — this test is RED
	// until T-1.4 implements it.
	builder := NewBuilderForEcosystem("python", NewPythonParser())
	if builder == nil {
		t.Fatal("NewBuilderForEcosystem(\"python\", ...) returned nil, expected non-nil *Builder")
	}
}

// TestNewBuilderForEcosystem_Java_Backward_Compat verifies that after the
// NewBuilderForEcosystem constructor is added, the existing NewBuilder
// still behaves identically (backward-compatible). Java tests must not regress.
func TestNewBuilderForEcosystem_Java_Backward_Compat(t *testing.T) {
	t.Parallel()

	// NewBuilder is the backward-compatible constructor (ecosystem="").
	builder := NewBuilder(NewJavaParser())
	if builder == nil {
		t.Fatal("NewBuilder returned nil — backward compat broken")
	}
}
