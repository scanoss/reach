// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"encoding/xml"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
)

// The namespaces a C# project brings into scope without a using directive in
// the source: the SDK's implicit global usings, which a project turns on with
// <ImplicitUsings>enable</ImplicitUsings>, and the <Using Include="N" /> items
// it lists. The compiler sees them as global usings of every file, so a file
// of an ASP.NET Core project names WebApplication or BackgroundService
// without writing a using.
// https://learn.microsoft.com/en-us/dotnet/core/project-sdk/overview#implicit-using-directives

var (
	csharpSDKUsings = []string{
		"System", "System.Collections.Generic", "System.IO", "System.Linq",
		"System.Net.Http", "System.Threading", "System.Threading.Tasks",
	}
	csharpHostingUsings = []string{
		"Microsoft.Extensions.Configuration", "Microsoft.Extensions.DependencyInjection",
		"Microsoft.Extensions.Hosting", "Microsoft.Extensions.Logging",
	}
	csharpWebUsings = slices.Concat([]string{
		"System.Net.Http.Json", "Microsoft.AspNetCore.Builder", "Microsoft.AspNetCore.Hosting",
		"Microsoft.AspNetCore.Http", "Microsoft.AspNetCore.Routing",
	}, csharpHostingUsings)
)

// csharpImplicitUsingsBySDK is the implicit global usings each project SDK
// adds on top of the base SDK's.
var csharpImplicitUsingsBySDK = map[string][]string{
	"Microsoft.NET.Sdk":        csharpSDKUsings,
	"Microsoft.NET.Sdk.Web":    slices.Concat(csharpSDKUsings, csharpWebUsings),
	"Microsoft.NET.Sdk.Worker": slices.Concat(csharpSDKUsings, csharpHostingUsings),
}

// csharpProjectFile is the part of a .csproj that names global usings.
type csharpProjectFile struct {
	SDK            string `xml:"Sdk,attr"`
	PropertyGroups []struct {
		ImplicitUsings string `xml:"ImplicitUsings"`
	} `xml:"PropertyGroup"`
	ItemGroups []struct {
		Usings []struct {
			Include string `xml:"Include,attr"`
			Remove  string `xml:"Remove,attr"`
			Alias   string `xml:"Alias,attr"`
			Static  string `xml:"Static,attr"`
		} `xml:"Using"`
	} `xml:"ItemGroup"`
}

// globalUsings is the namespaces the project imports into every file.
func (f *csharpProjectFile) globalUsings() []string {
	var out []string
	sdk, _, _ := strings.Cut(strings.TrimSpace(f.SDK), "/")
	for _, group := range f.PropertyGroups {
		switch strings.ToLower(strings.TrimSpace(group.ImplicitUsings)) {
		case "enable", "true":
			out = slices.Clone(csharpImplicitUsingsBySDK[sdk])
		case "disable", "false":
			out = nil
		}
	}
	for _, group := range f.ItemGroups {
		for _, using := range group.Usings {
			switch {
			case using.Remove != "":
				out = slices.DeleteFunc(out, func(ns string) bool { return ns == using.Remove })
			case using.Include != "" && using.Alias == "" && !strings.EqualFold(using.Static, "true") && !slices.Contains(out, using.Include):
				out = append(out, using.Include)
			}
		}
	}
	return out
}

// csharpProjects caches, per directory, the global usings of the nearest
// project file at or above it. Clones of one parser share it.
type csharpProjects struct {
	byDir sync.Map // directory -> []string
}

// globalUsings returns the global usings of the nearest .csproj at or above
// dir, or nil when there is none.
func (c *csharpProjects) globalUsings(dir string) []string {
	var visited []string
	var usings []string
	for current := filepath.Clean(dir); ; current = filepath.Dir(current) {
		if cached, ok := c.byDir.Load(current); ok {
			usings, _ = cached.([]string)
			break
		}
		visited = append(visited, current)
		if project, ok := csharpReadProject(current); ok {
			usings = project.globalUsings()
			break
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	for _, seen := range visited {
		c.byDir.Store(seen, usings)
	}
	return usings
}

// csharpReadProject reads the first .csproj of dir, by name.
func csharpReadProject(dir string) (*csharpProjectFile, bool) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.csproj"))
	if err != nil || len(matches) == 0 {
		return nil, false
	}
	slices.Sort(matches)
	data, err := os.ReadFile(matches[0])
	if err != nil {
		return nil, false
	}
	project := &csharpProjectFile{}
	if xml.Unmarshal(data, project) != nil {
		return &csharpProjectFile{}, true
	}
	return project, true
}

// addGlobalUsings appends the project's global usings the file does not
// already write to its on-demand imports.
func addGlobalUsings(analysis *FileAnalysis, usings []string) {
	for _, ns := range usings {
		if !slices.Contains(analysis.WildcardImports, ns) {
			analysis.WildcardImports = append(analysis.WildcardImports, ns)
		}
	}
}
