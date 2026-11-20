// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

// An ecosystem with no module name of its own (nuget) records the purl as the
// module. Composing a purl from it again would prefix and escape it twice.
func TestExportDependencyInfoPurlShapes(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		name, ecosystem, module, purl, version, want string
	}{
		{"nuget module is a purl", "csharp", "pkg:nuget/Acme.Crypto", "pkg:nuget/Acme.Crypto", "2.4.0", "pkg:nuget/Acme.Crypto@2.4.0"},
		{"purl already carries the version", "csharp", "pkg:nuget/Acme.Crypto", "pkg:nuget/Acme.Crypto@2.0.0", "2.0.0", "pkg:nuget/Acme.Crypto@2.0.0"},
		{"a version that needs escaping", "csharp", "pkg:nuget/Acme.Crypto", "pkg:nuget/Acme.Crypto", "1.0.0+build", "pkg:nuget/Acme.Crypto@1.0.0%2Bbuild"},
		{"a frame with no module is unchanged", "java", "", "pkg:maven/net.crypto/lib", "2.0.0", "pkg:maven/net.crypto/lib"},
		{"a named module is unchanged", "java", "net.crypto:lib", "pkg:maven/net.crypto/lib", "2.0.0", "pkg:maven/net.crypto/lib@2.0.0"},
	} {
		frame := &CallFrame{Module: c.module, Component: ComponentKey{Purl: c.purl, Version: c.version}}
		if got := exportDependencyInfo(frame, c.ecosystem).PURL; got != c.want {
			t.Errorf("%s: purl %q, want %q", c.name, got, c.want)
		}
	}
}
