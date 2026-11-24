// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// parseCSharpTree writes files under a temporary root and parses the
// directory dir of it.
func parseCSharpTree(t *testing.T, files map[string]string, dir string) []*FileAnalysis {
	t.Helper()
	root := t.TempDir()
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	analyses, err := NewCSharpParser().ParseDirectory(filepath.Join(root, dir), "Acme")
	if err != nil {
		t.Fatal(err)
	}
	return analyses
}

func TestCSharpImplicitUsings(t *testing.T) {
	const program = "namespace Shop;\nclass App { }\n"
	cases := []struct {
		name, project string
		want, absent  []string
	}{
		{
			name:    "web sdk",
			project: `<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>`,
			want:    []string{"System", "System.Linq", "Microsoft.AspNetCore.Builder", "Microsoft.AspNetCore.Http", "Microsoft.Extensions.Hosting"},
		},
		{
			name:    "worker sdk",
			project: `<Project Sdk="Microsoft.NET.Sdk.Worker"><PropertyGroup><ImplicitUsings>true</ImplicitUsings></PropertyGroup></Project>`,
			want:    []string{"System.Threading.Tasks", "Microsoft.Extensions.Hosting", "Microsoft.Extensions.DependencyInjection"},
			absent:  []string{"Microsoft.AspNetCore.Builder"},
		},
		{
			name:    "base sdk",
			project: `<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>`,
			want:    []string{"System.IO", "System.Net.Http"},
			absent:  []string{"Microsoft.Extensions.Hosting"},
		},
		{
			name:    "disabled",
			project: `<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><ImplicitUsings>disable</ImplicitUsings></PropertyGroup></Project>`,
			absent:  []string{"System", "Microsoft.AspNetCore.Builder"},
		},
		{
			name: "using items",
			project: `<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup>
  <ItemGroup>
    <Using Include="Shop.Crypto" />
    <Using Remove="System.Net.Http" />
    <Using Include="Shop.Aliased" Alias="Aliased" />
  </ItemGroup>
</Project>`,
			want:   []string{"Shop.Crypto", "Microsoft.AspNetCore.Builder"},
			absent: []string{"System.Net.Http", "Shop.Aliased"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analyses := parseCSharpTree(t, map[string]string{"Shop.csproj": tc.project, "src/Api/App.cs": program}, "src/Api")
			got := analyses[0].WildcardImports
			for _, ns := range tc.want {
				if !slices.Contains(got, ns) {
					t.Errorf("imports = %q, want %s", got, ns)
				}
			}
			for _, ns := range tc.absent {
				if slices.Contains(got, ns) {
					t.Errorf("imports = %q, want no %s", got, ns)
				}
			}
			if len(analyses[0].CSharpUsings) != 0 {
				t.Errorf("written usings = %+v, want none: the project's usings are not directives of the file", analyses[0].CSharpUsings)
			}
		})
	}
}

// A project's global using settles a call's owner the way a written one does.
func TestCSharpGlobalUsingSettlesTheOwner(t *testing.T) {
	graph := buildCSharpGraph(t, map[string]string{
		"Shop.csproj": `<Project Sdk="Microsoft.NET.Sdk"><ItemGroup><Using Include="Shop.Crypto" /></ItemGroup></Project>`,
		"lib.cs":      "namespace Shop.Crypto;\nclass Hasher { public static void Go() { } }\n",
		"app.cs":      "namespace Shop.App;\nclass App { void Run() { Hasher.Go(); } }\n",
	})
	if !hasCall(t, graph, "Shop.App.(App).Run#0", "Shop.Crypto.(Hasher).Go#0") {
		t.Errorf("calls = %q, want the call keyed by the namespace the project imports", callsOf(t, graph, "Shop.App.(App).Run#0"))
	}
}
