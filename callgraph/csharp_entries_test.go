// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

const csharpAttributeRule = "csharp/aspnetcore:decorator:ApiController"

// A class that derives from nothing is a controller when an attribute
// routes it: its actions are entry points, and a routing attribute marks
// its method.
func TestCSharpRoutedTypeActionsAreEntryPoints(t *testing.T) {
	rules := csharpEntryRules(t, map[string]string{"OrdersApi.cs": `using Microsoft.AspNetCore.Mvc;
namespace Shop.Web;
[Route("api/orders")]
public class OrdersApi {
    [HttpPost]
    public byte[] Create(byte[] d) { return d; }
    public byte[] List() { return null; }
    private byte[] Hash(byte[] d) { return d; }
    [NonAction]
    public void Audit() { }
}`})
	assertCSharpRoots(t, rules, map[string]string{
		"Shop.Web.(OrdersApi).Create#1": csharpAttributeRule,
		"Shop.Web.(OrdersApi).List#0":   csharpAttributeRule,
	}, "Shop.Web.(OrdersApi).Hash#1", "Shop.Web.(OrdersApi).Audit#0")
}

// A method attribute counts however the source names the attribute type.
func TestCSharpMethodAttributeSpellings(t *testing.T) {
	cases := map[string]string{
		"qualified": `namespace Shop.Web;
public class Endpoints {
    [Microsoft.AspNetCore.Mvc.HttpGet("keys")]
    public byte[] Get() { return null; }
    public byte[] Helper() { return null; }
}`,
		"Attribute suffix": `using Microsoft.AspNetCore.Mvc;
namespace Shop.Web;
public class Endpoints {
    [HttpGetAttribute("keys")]
    public byte[] Get() { return null; }
    public byte[] Helper() { return null; }
}`,
		"namespace alias": `using Mvc = Microsoft.AspNetCore.Mvc;
namespace Shop.Web;
public class Endpoints {
    [Mvc.HttpGet("keys")]
    public byte[] Get() { return null; }
    public byte[] Helper() { return null; }
}`,
		"among others": `using Microsoft.AspNetCore.Mvc;
namespace Shop.Web;
public class Endpoints {
    [Produces("application/json"), AcceptVerbs("GET", "HEAD")]
    public byte[] Get() { return null; }
    public byte[] Helper() { return null; }
}`,
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			rules := csharpEntryRules(t, map[string]string{"Endpoints.cs": source})
			assertCSharpRoots(t, rules, map[string]string{"Shop.Web.(Endpoints).Get#0": csharpAttributeRule}, "Shop.Web.(Endpoints).Helper#0")
		})
	}
}

// An attribute of a catalog name from another namespace is not the
// framework's.
func TestCSharpAttributeFromAnotherNamespaceIsNotAnEntry(t *testing.T) {
	rules := csharpEntryRules(t, map[string]string{
		"Fake.cs": `namespace Acme.Fake;
public class HttpGetAttribute : System.Attribute { }
public class RouteAttribute : System.Attribute { }`,
		"Endpoints.cs": `using Acme.Fake;
namespace Shop.Web;
[Route]
public class Endpoints {
    [HttpGet]
    public byte[] Get() { return null; }
    public byte[] List() { return null; }
}`,
	})
	assertCSharpRoots(t, rules, nil, "Shop.Web.(Endpoints).Get#0", "Shop.Web.(Endpoints).List#0")
}

const (
	csharpMapRule     = "csharp/aspnetcore:registration_call:MapGet"
	csharpWebProject  = `<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><ImplicitUsings>enable</ImplicitUsings></PropertyGroup></Project>`
	csharpHashHelpers = `namespace Shop.Crypto;
public static class Hasher { public static byte[] Hash() { return null; } }
`
)

// A method group a minimal-API Map call registers in top-level statements
// is an entry point: a local function by its name, a static method as
// Type.Name. The Builder namespace comes from the project's implicit usings.
func TestCSharpMinimalAPIMethodGroupsAreEntryPoints(t *testing.T) {
	graph := buildCSharpGraph(t, map[string]string{
		"Shop.csproj": csharpWebProject,
		"Crypto.cs":   csharpHashHelpers,
		"Handlers.cs": `namespace Shop.Api;
public static class Handlers {
    public static byte[] Options() { return null; }
    public static byte[] Audit() { return null; }
}`,
		"Program.cs": `using Shop.Api;
using Shop.Crypto;
var app = WebApplication.Create(args);
app.MapGet("/users/{id}", GetUser);
app.MapMethods("/keys", new[] { "OPTIONS" }, Handlers.Options);
app.MapPost("/sign", () => Hasher.Hash());
app.Run();
static byte[] GetUser(int id) { return null; }
static byte[] Unused() { return null; }
`,
	})
	rules := csharpRootsOf(t, graph)
	assertCSharpRoots(t, rules, map[string]string{
		"Acme.(Program).GetUser#1":      csharpMapRule,
		"Shop.Api.(Handlers).Options#0": csharpMapRule,
	}, "Acme.(Program).Unused#0", "Shop.Api.(Handlers).Audit#0")
	if callers := graph.Callers["Shop.Crypto.(Hasher).Hash#0"]; len(callers) != 1 || callers[0] != "Acme.(Program).Main#1" {
		t.Errorf("callers of the lambda's call = %q, want the generated Main", callers)
	}
}

// An extension method that maps endpoints on an IEndpointRouteBuilder
// registers every overload of the method group it names.
func TestCSharpMappedEndpointsInAnExtensionMethod(t *testing.T) {
	rules := csharpEntryRules(t, map[string]string{
		"OrderHandlers.cs": `namespace Shop.Handlers;
public static class OrderHandlers {
    public static byte[] Create(int id) { return null; }
    public static byte[] Create(int id, string note) { return null; }
    public static byte[] Delete(int id) { return null; }
    public static byte[] Audit() { return null; }
}`,
		"OrderEndpoints.cs": `using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Routing;
using Shop.Handlers;
namespace Shop.Api;
public static class OrderEndpoints {
    public static void MapOrders(this IEndpointRouteBuilder app) {
        app.MapPost("/orders", OrderHandlers.Create);
        app.MapDelete(pattern: "/orders/{id}", handler: OrderHandlers.Delete);
    }
}`,
	})
	assertCSharpRoots(t, rules, map[string]string{
		"Shop.Handlers.(OrderHandlers).Create#1": csharpMapRule,
		"Shop.Handlers.(OrderHandlers).Create#2": csharpMapRule,
		"Shop.Handlers.(OrderHandlers).Delete#1": csharpMapRule,
	}, "Shop.Handlers.(OrderHandlers).Audit#0")
}

// A receiver declared with a Builder type is evidence on its own.
func TestCSharpMapOnAFrameworkReceiver(t *testing.T) {
	rules := csharpEntryRules(t, map[string]string{"Endpoints.cs": `namespace Shop.Api;
public static class Endpoints {
    public static void Map(Microsoft.AspNetCore.Builder.WebApplication app) { app.MapPut("/keys", Rotate); }
    public static byte[] Rotate() { return null; }
}`})
	assertCSharpRoots(t, rules, map[string]string{"Shop.Api.(Endpoints).Rotate#0": csharpMapRule})
}

// A MapGet of the application's own, in a file without the Builder namespace
// in scope, registers nothing.
func TestCSharpOwnMapGetIsNotARegistration(t *testing.T) {
	rules := csharpEntryRules(t, map[string]string{
		"Router.cs": `namespace Shop.Jobs;
public static class Router { public static void MapGet(string path, System.Func<byte[]> run) { } }
public static class Jobs {
    public static byte[] Run() { return null; }
    public static void Schedule() { Router.MapGet("/nightly", Run); }
}`,
	})
	assertCSharpRoots(t, rules, nil, "Shop.Jobs.(Jobs).Run#0")
}
