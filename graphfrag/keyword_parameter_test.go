// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"strings"
	"testing"
)

// A Python keyword argument keeps its keyword from the fragment document to
// the stitch model, back to a document, and into the stitched export.
func TestParameterKeywordRoundTrip(t *testing.T) {
	t.Parallel()
	raw := GraphFragmentParameter{ParameterIndex: 2, Keyword: "algorithm", ArgumentExpression: `"HS256"`, ResolvedValue: `"HS256"`}
	param := toParameter(raw, make(internTable))
	if param.Keyword != "algorithm" {
		t.Fatalf("model keyword = %q", param.Keyword)
	}
	if back := fromParameter(param); back.Keyword != "algorithm" || back.ArgumentExpression != `"HS256"` {
		t.Fatalf("document parameter = %+v", back)
	}
	exported, err := json.Marshal(exportParameter(param))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(exported), `"keyword":"algorithm"`) {
		t.Fatalf("stitched parameter %s has no keyword", exported)
	}
	positional, err := json.Marshal(fromParameter(Parameter{ParameterIndex: 0, ArgumentExpression: "data"}))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(positional), "keyword") {
		t.Fatalf("positional parameter %s carries a keyword", positional)
	}
}
