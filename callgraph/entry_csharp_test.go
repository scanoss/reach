// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

// csharpEntryRoots are the declarations of a graph and the catalog rule of
// each one the tracer roots ("" for a root no rule gave).
type csharpEntryRoots struct {
	declared map[string]bool
	rules    map[string]string
}

// csharpEntryRules builds a graph over the files and reads its roots.
func csharpEntryRules(t *testing.T, files map[string]string) csharpEntryRoots {
	t.Helper()
	return csharpRootsOf(t, buildCSharpGraph(t, files))
}

// csharpRootsOf reads a graph's roots, with the application's packages
// unknown and known.
func csharpRootsOf(t *testing.T, graph *CallGraph) csharpEntryRoots {
	t.Helper()
	tracer := NewTracer(graph, csharpSeparator)
	out := csharpEntryRoots{declared: map[string]bool{}}
	for _, userPackages := range []map[string]bool{nil, {"Shop": true}} {
		got := map[string]string{}
		for key, decl := range graph.Functions {
			out.declared[key] = true
			if mark, ok := tracer.EntryPoint(decl, userPackages); ok {
				got[key] = mark.Rule
			}
		}
		if out.rules != nil && len(out.rules) != len(got) {
			t.Fatalf("roots differ with the application's packages known: %v vs %v", out.rules, got)
		}
		out.rules = got
	}
	return out
}

func assertCSharpRoots(t *testing.T, got csharpEntryRoots, roots map[string]string, notRoots ...string) {
	t.Helper()
	for key, rule := range roots {
		if actual, ok := got.rules[key]; !ok || actual != rule {
			t.Errorf("%s: rule = %q (rooted %v), want %q; roots = %v", key, actual, ok, rule, got.rules)
		}
	}
	for _, key := range notRoots {
		if !got.declared[key] {
			t.Errorf("%s is not declared", key)
		}
		if rule, ok := got.rules[key]; ok {
			t.Errorf("%s is rooted by %q, want no root", key, rule)
		}
	}
}

const csharpControllerActions = `
    public UsersController(IUsers users) { }
    public byte[] Create(byte[] d) { return d; }
    private byte[] Hash(byte[] d) { return d; }
    [NonAction]
    public byte[] Sign(byte[] d) { return d; }
    public static byte[] Encode(byte[] d) { return d; }
    public string Name { get { return Hasher.Go(); } }
}`

func TestCSharpControllerActionsAreEntryPoints(t *testing.T) {
	const actionRule = "csharp/aspnetcore:supertype:*"
	notActions := []string{
		"Shop.Web.(UsersController).Hash#1", "Shop.Web.(UsersController).Sign#1",
		"Shop.Web.(UsersController).Encode#1", "Shop.Web.(UsersController).Name#0",
		"Shop.Web.(UsersController).<init>#1",
	}
	cases := map[string]map[string]string{
		"Controller": {
			"UsersController.cs": "using Microsoft.AspNetCore.Mvc;\nnamespace Shop.Web;\npublic class UsersController : Controller {" + csharpControllerActions,
		},
		"ControllerBase": {
			"UsersController.cs": "using Microsoft.AspNetCore.Mvc;\nnamespace Shop.Web;\npublic class UsersController : ControllerBase {" + csharpControllerActions,
		},
		"application base controller in another file": {
			"BaseApiController.cs": "using Microsoft.AspNetCore.Mvc;\nnamespace Shop.Web;\npublic abstract class BaseApiController : ControllerBase { }\n",
			"UsersController.cs":   "namespace Shop.Web;\npublic class UsersController : BaseApiController {" + csharpControllerActions,
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			rules := csharpEntryRules(t, files)
			assertCSharpRoots(t, rules, map[string]string{"Shop.Web.(UsersController).Create#1": actionRule}, notActions...)
		})
	}
}

// A class of the same shape that derives from no framework type has no
// actions.
func TestCSharpPlainClassHasNoActions(t *testing.T) {
	rules := csharpEntryRules(t, map[string]string{
		"UsersController.cs": "namespace Shop.Web;\npublic class UsersController {" + csharpControllerActions,
	})
	assertCSharpRoots(t, rules, nil, "Shop.Web.(UsersController).Create#1")
}

const csharpWorker = `namespace Shop.Workers;
public class Rotator : BackgroundService {
    protected override Task ExecuteAsync(CancellationToken token) { return Rotate(); }
    public Task Rotate() { return null; }
}
public class Warmup : IHostedService {
    public Task StartAsync(CancellationToken token) { return null; }
    public Task StopAsync(CancellationToken token) { return null; }
    public Task Preload() { return null; }
}`

func TestCSharpHostedServicesAreEntryPoints(t *testing.T) {
	cases := map[string]map[string]string{
		"written using": {"Workers.cs": "using Microsoft.Extensions.Hosting;\n" + csharpWorker},
		"implicit using": {
			"Shop.csproj": `<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>`,
			"Workers.cs":  csharpWorker,
		},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			rules := csharpEntryRules(t, files)
			assertCSharpRoots(t, rules, map[string]string{
				"Shop.Workers.(Rotator).ExecuteAsync#1": "csharp/hosting:supertype:ExecuteAsync",
				"Shop.Workers.(Warmup).StartAsync#1":    "csharp/hosting:supertype:StartAsync",
				"Shop.Workers.(Warmup).StopAsync#1":     "csharp/hosting:supertype:StartAsync",
			}, "Shop.Workers.(Rotator).Rotate#0", "Shop.Workers.(Warmup).Preload#0")
		})
	}
}

// A BackgroundService the application declares in its own namespace is not
// the framework's, with or without the framework's namespace in scope: the
// enclosing namespace wins C#'s lookup.
func TestCSharpOwnBackgroundServiceIsNotTheFrameworks(t *testing.T) {
	const own = "public abstract class BackgroundService { protected abstract Task ExecuteAsync(CancellationToken token); }\n"
	for name, using := range map[string]string{"no using": "", "using written": "using Microsoft.Extensions.Hosting;\n"} {
		t.Run(name, func(t *testing.T) {
			rules := csharpEntryRules(t, map[string]string{
				"Base.cs":    "namespace Shop.Workers;\n" + own,
				"Workers.cs": using + "namespace Shop.Workers;\npublic class Rotator : BackgroundService {\n    protected override Task ExecuteAsync(CancellationToken token) { return null; }\n}\n",
			})
			assertCSharpRoots(t, rules, nil, "Shop.Workers.(Rotator).ExecuteAsync#1")
		})
	}
}
