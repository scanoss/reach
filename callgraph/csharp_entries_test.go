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
