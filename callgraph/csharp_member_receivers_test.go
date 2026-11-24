// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"testing"
)

const csharpShopService = `namespace Shop.Services;
public interface IOrderService { byte[] Sign(byte[] d); }
public class OrderService : IOrderService { public byte[] Sign(byte[] d) { return null; } }
`

// A call on a field, an auto-property or a primary-constructor parameter of
// the enclosing type is an instance call of the member's declared type, so
// it dispatches through the interface to the implementation.
func TestCSharpMemberReceiverDispatches(t *testing.T) {
	cases := map[string]string{
		"field": `using Shop.Services;
namespace Shop.Web;
public class OrdersController {
    private readonly IOrderService _orders;
    public OrdersController(IOrderService orders) { _orders = orders; }
    public byte[] Post(byte[] d) { return _orders.Sign(d); }
}`,
		"this field": `using Shop.Services;
namespace Shop.Web;
public class OrdersController {
    private readonly IOrderService _orders;
    public byte[] Post(byte[] d) { return this._orders.Sign(d); }
}`,
		"auto-property": `using Shop.Services;
namespace Shop.Web;
public class OrdersController {
    public IOrderService Orders { get; set; }
    public byte[] Post(byte[] d) { return Orders.Sign(d); }
}`,
		"primary constructor": `using Shop.Services;
namespace Shop.Web;
public class OrdersController(IOrderService orders) {
    public byte[] Post(byte[] d) { return orders.Sign(d); }
}`,
	}
	for name, controller := range cases {
		t.Run(name, func(t *testing.T) {
			graph := buildCSharpGraph(t, map[string]string{"Services/OrderService.cs": csharpShopService, "Web/OrdersController.cs": controller})
			callers := graph.Callers["Shop.Services.(OrderService).Sign#1"]
			if !slices.Contains(callers, "Shop.Web.(OrdersController).Post#1") {
				t.Errorf("callers of OrderService.Sign = %+v, want OrdersController.Post", callers)
			}
		})
	}
}

// A parameter or a local of the member's name shadows the member.
func TestCSharpLocalShadowsMemberReceiver(t *testing.T) {
	a := parseOneCSharp(t, `namespace Shop.Web;
public class OrdersController {
    private readonly IOrderService _orders;
    public void Post(Ledger _orders) { _orders.Sign(null); }
}`)
	calls := csharpCallsOf(t, a, "Post")
	if len(calls) != 1 || calls[0].Callee.Type != "Ledger" {
		t.Errorf("calls = %+v, want the parameter's type Ledger", calls)
	}
}
