// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "strings"

// ruby_receiver_types.go names the class behind a receiver a constructor
// produced. `@signer = Aws::Sigv4::Signer.new(..)` in one method and
// `@signer.sign_request(..)` in another are the commonest shape Ruby code
// has, and without the pair the second call names no owner at all: it joins
// no declaration of the gem, and the finding behind it is reported as
// unreachable. The pair needs no contract -- `new` returns an instance of
// the constant that receives it -- so it is read while the graph is built,
// where the edge kinds are still being decided.

// resolveRubyReceiverTypes types every call whose receiver one constructor
// produced, whether the receiver is a local of the same body or an instance
// variable of the same class.
func resolveRubyReceiverTypes(graph *CallGraph) {
	producers, bound := rubyConstructedReceivers(graph)
	if len(producers) == 0 {
		return
	}
	for _, fn := range graph.Functions {
		if fn == nil {
			continue
		}
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if call.Callee.Type != "" || call.ReceiverVar == "" {
				continue
			}
			key := rubyReceiverKey(fn, call.ReceiverVar)
			if bound[key] != 1 {
				// Bound more than once, or not at all: two types are no type.
				continue
			}
			if t := producers[key]; t == "" {
				continue
			} else if strings.HasPrefix(call.ReceiverVar, "@") {
				// Only an instance variable takes the class as its owner.
				// A local the constructor beside it types is an instance,
				// and naming its class there makes it answer a rule that
				// spells a class receiver -- `OpenSSL::HMAC.digest(..)` is
				// not what `mac.digest` runs, and the fragment carries no
				// distinction between the two (owner decision).
				call.Callee.Type = t
				call.ResolvedReceiverType = t
				call.ReceiverBoundOnce = true
			} else {
				call.ResolvedReceiverType = t
				call.ReceiverBoundOnce = true
			}
		}
	}
}

// rubyConstructedReceivers is what each receiver name was constructed from,
// and how many calls bind it.
func rubyConstructedReceivers(graph *CallGraph) (map[string]string, map[string]int) {
	producers, bound := map[string]string{}, map[string]int{}
	for _, fn := range graph.Functions {
		if fn == nil {
			continue
		}
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if call.AssignedVar == "" {
				continue
			}
			key := rubyReceiverKey(fn, call.AssignedVar)
			bound[key]++
			if BaseFunctionName(call.Callee.Name) == rubyConstructorName && call.Callee.Type != "" {
				producers[key] = call.Callee.Type
			}
		}
	}
	return producers, bound
}

// rubyReceiverKey scopes a receiver name: an instance variable belongs to
// the class, which is what lets one method's constructor type another
// method's call; a local belongs to the body that binds it.
func rubyReceiverKey(fn *FunctionDecl, name string) string {
	if strings.HasPrefix(name, "@") {
		return fn.ID.Type + "\x00" + name
	}
	return fn.ID.String() + "\x00" + name
}
