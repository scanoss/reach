// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package contracts

import "testing"

func TestHintsDefaultToZeroAndAreReplaced(t *testing.T) {
	prev := *CurrentHints()
	t.Cleanup(func() { SetHints(prev) })

	SetHints(Hints{})
	if got := CurrentHints().JavaWildcardTypePackages["Cipher"]; got != "" {
		t.Fatalf("zero hints: Cipher -> %q, want none", got)
	}
	SetHints(Hints{JavaWildcardTypePackages: map[string]string{"Cipher": "javax.crypto"}})
	if got := CurrentHints().JavaWildcardTypePackages["Cipher"]; got != "javax.crypto" {
		t.Fatalf("installed hints: Cipher -> %q, want javax.crypto", got)
	}
}
