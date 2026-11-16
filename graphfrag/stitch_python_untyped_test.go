// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

var pyRequests = ComponentKey{Purl: "pkg:pypi/requests", Version: "2.32.3"}

// pythonUnresolvedVerdict stitches a Python client whose one call is target
// (exact, method) over pyjwt, which declares `jwt.algorithms.(RSAAlgorithm).sign`,
// requests, which re-exports urllib3's Retry from `requests.adapters`, and
// urllib3. The finding sits in sink.
func pythonUnresolvedVerdict(t *testing.T, target, method, sink string) ExportFindingGraph {
	t.Helper()
	const (
		jwtSign   = "jwt.algorithms.(RSAAlgorithm).sign"
		retryInit = "urllib3.util.retry.(Retry).<init>"
		send      = "requests.adapters.(HTTPAdapter).send"
	)
	owner := map[string]ComponentKey{jwtSign: pyJWT, retryInit: pyUrllib3, send: pyRequests}[sink]
	fragments := map[ComponentKey]Fragment{
		pyClient: {
			Component: pyClient, GraphAlgoVersion: GraphAlgoVersionPython,
			Functions: []Function{{Signature: "app.models.handle"}, {Signature: "app.models.(User).save"}},
			ExternalCalls: []ExternalCall{{
				Caller: "app.models.handle", TargetSignature: target, Resolution: ResolutionExact, MethodName: method, CallSite: 3,
			}},
		},
		pyJWT:      {Component: pyJWT, GraphAlgoVersion: GraphAlgoVersionPython, Functions: []Function{{Signature: jwtSign}}},
		pyRequests: {Component: pyRequests, GraphAlgoVersion: GraphAlgoVersionPython, Functions: []Function{{Signature: send}}},
		pyUrllib3:  {Component: pyUrllib3, GraphAlgoVersion: GraphAlgoVersionPython, Functions: []Function{{Signature: retryInit}}},
	}
	frag := fragments[owner]
	frag.CryptoOperations = []CryptoOperation{{Function: sink, FindingID: "f", RuleID: "rule", FilePath: "x.py", StartLine: 1}}
	fragments[owner] = frag
	deps := DependencyGraph{pyClient: {pyJWT, pyRequests, pyUrllib3}, pyRequests: {pyUrllib3}}
	res, err := StitchWithOptions(pyClient, deps, fragments, StitchOptions{EntryRootedOnly: true, ClasspathTargets: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	graphs := res.ToCallgraphExport(pyClient, ScanMeta{Ecosystem: "python"}).FindingGraphs
	if len(graphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(graphs))
	}
	return graphs[0]
}

// A typed call that names a dependency's module but no declaration of it (a
// method of a module-level instance, `jwt.backend.sign(..)`) reaches code of
// that dependency the fragments do not name: a finding in a function of the
// called name reads unknown, never unreachable.
func TestStitch_PythonUnresolvedCallIntoDependencyIsUnknown(t *testing.T) {
	t.Parallel()
	fg := pythonUnresolvedVerdict(t, "jwt.backend.sign", "sign", "jwt.algorithms.(RSAAlgorithm).sign")
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("got %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// A class a dependency re-exports from another component
// (`requests.adapters.Retry(..)`) is declared in neither module the target
// names: calling it may run the `__init__` of a class of that name elsewhere
// in the closure, unknown.
func TestStitch_PythonUnresolvedReexportedClassIsUnknown(t *testing.T) {
	t.Parallel()
	fg := pythonUnresolvedVerdict(t, "requests.adapters.Retry", "Retry", "urllib3.util.retry.(Retry).<init>")
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("got %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// The candidates are those of the dependency the target names: requests'
// `send` is no candidate of a call into pyjwt's module, and a call in the
// client's own module (an instantiation kept at its spelling next to the
// producer's internal edge) or in the standard library is no call into a
// dependency at all. (The stitched export reads a finding without a route
// unknown, with no reason, once it refused any edge; project reachability
// serves that unreachable.)
func TestStitch_PythonUnresolvedCallStaysInItsDependency(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ target, method, sink string }{
		{"jwt.backend.send", "send", "requests.adapters.(HTTPAdapter).send"},
		{"app.models.Retry", "Retry", "urllib3.util.retry.(Retry).<init>"},
		{"app.models.(User).sign", "sign", "jwt.algorithms.(RSAAlgorithm).sign"},
		{"hashlib.sha256().sign", "sign", "jwt.algorithms.(RSAAlgorithm).sign"},
	} {
		if fg := pythonUnresolvedVerdict(t, c.target, c.method, c.sink); fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
			t.Errorf("%s: %q %q, want no route and no reason", c.target, fg.Reachability, fg.UnresolvedReason)
		}
	}
}

// pythonBuiltinNameVerdict stitches a client making calls over cryptography, whose `(Hash).update` holds a finding.
func pythonBuiltinNameVerdict(t *testing.T, calls ...ExternalCall) ExportFindingGraph {
	t.Helper()
	const update = "cryptography.hazmat.primitives.hashes.(Hash).update"
	var callers []Function
	for _, c := range calls {
		callers = append(callers, Function{Signature: c.Caller})
	}
	fragments := map[ComponentKey]Fragment{
		pyClient: {
			Component: pyClient, GraphAlgoVersion: GraphAlgoVersionPython,
			Functions:     callers,
			ExternalCalls: calls,
		},
		pyCryptography: {
			Component: pyCryptography, GraphAlgoVersion: GraphAlgoVersionPython,
			Functions:        []Function{{Signature: update}, {Signature: "cryptography.hazmat.primitives.hashes.(Hash).<init>"}},
			CryptoOperations: []CryptoOperation{{Function: update, FindingID: "f", RuleID: "rule", FilePath: "hashes.py", StartLine: 1}},
		},
	}
	res, err := StitchWithOptions(pyClient, DependencyGraph{pyClient: {pyCryptography}}, fragments, StitchOptions{EntryRootedOnly: true, ClasspathTargets: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	graphs := res.ToCallgraphExport(pyClient, ScanMeta{Ecosystem: "python"}).FindingGraphs
	if len(graphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(graphs))
	}
	return graphs[0]
}

func nameOnlyUpdate(receiver, chain string) ExternalCall {
	return ExternalCall{
		Caller: "app.digest.handle", TargetSignature: "app.digest.(" + receiver + ").update", Resolution: ResolutionNameOnly,
		MethodName: "update", Arity: 1, CallSite: 5, ReceiverVar: receiver, ChainID: chain,
	}
}

// A method name of a builtin value type called on a value the caller did not
// get from a dependency (`params.update(..)` on a parameter or a dict) has no
// candidate: it does not read cryptography's `update` as unknown.
func TestStitch_PythonBuiltinMethodNameNeedsADependencyValue(t *testing.T) {
	t.Parallel()
	fg := pythonBuiltinNameVerdict(t, nameOnlyUpdate("params", ""))
	if fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Fatalf("params.update: %q %q, want no candidate", fg.Reachability, fg.UnresolvedReason)
	}
}

// The same name on a local the caller assigns from a call into a dependency
// (`h = hashes.Hash(..); h.update(..)` with Hash untyped), or on the result of
// such a call in the same chain, keeps its candidates: unknown.
func TestStitch_PythonBuiltinMethodNameOnADependencyValue(t *testing.T) {
	t.Parallel()
	hash := ExternalCall{
		Caller: "app.digest.handle", TargetSignature: "cryptography.hazmat.primitives.hashes.Hash", Resolution: ResolutionExact,
		MethodName: "Hash", CallSite: 4, AssignedVar: "h", ChainID: "c1",
	}
	for name, call := range map[string]ExternalCall{"local": nameOnlyUpdate("h", ""), "chain": nameOnlyUpdate("", "c1")} {
		fg := pythonBuiltinNameVerdict(t, hash, call)
		if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
			t.Errorf("%s: %q %q, want %q %q", name, fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
		}
	}
}

// A chain link is a dependency value only when it is the call's receiver.
// The producer gives every call on a chain's line the chain's id, so a
// dependency call taking the chain as an argument
// (`glob_to_regex(entry.encode("ascii").decode("ascii"))`) shares the id but
// encloses the call: no candidate. A link the call's span starts with
// (`hashes.Hash(..).update(..)`) keeps them.
func TestStitch_PythonBuiltinMethodNameChainLinkMustBeTheReceiver(t *testing.T) {
	t.Parallel()
	link := func(start, end int) ExternalCall {
		return ExternalCall{
			Caller: "app.digest.handle", TargetSignature: "cryptography.hazmat.primitives.hashes.Hash", Resolution: ResolutionExact,
			MethodName: "Hash", CallSite: 5, ChainID: "c1", StartCol: start, EndCol: end,
		}
	}
	update := nameOnlyUpdate("", "c1")
	update.StartCol, update.EndCol = 45, 66
	if fg := pythonBuiltinNameVerdict(t, link(31, 83), update); fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Errorf("enclosing call: %q %q, want no candidate", fg.Reachability, fg.UnresolvedReason)
	}
	if fg := pythonBuiltinNameVerdict(t, link(45, 60), update); fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Errorf("receiver link: %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// A field of the caller's class some method assigns from a call into a
// dependency (`self._h = hashes.Hash(..)` in `__init__`) is a dependency
// value too: `self._h.update(..)` keeps its candidates.
func TestStitch_PythonBuiltinMethodNameOnADependencyField(t *testing.T) {
	t.Parallel()
	hash := ExternalCall{
		Caller: "app.digest.(Digest).<init>", TargetSignature: "cryptography.hazmat.primitives.hashes.Hash", Resolution: ResolutionExact,
		MethodName: "Hash", CallSite: 4, AssignedVar: "self._h",
	}
	update := nameOnlyUpdate("self._h", "")
	update.Caller = "app.digest.(Digest).feed"
	fg := pythonBuiltinNameVerdict(t, update, hash)
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("self._h.update: %q %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
}

// An untyped call inside a dependency can run the dependency's own methods:
// pyjwt's `PyJWT.encode` calls `self._jws.encode(..)`, its own `PyJWS.encode`,
// which the producer links to nothing. Its own methods of the name are
// candidates whatever the name, so the client's typed `jwt.encode` reaches
// the signing finding as unknown, not unreachable.
func TestStitch_PythonNameOnlyReachesItsOwnComponent(t *testing.T) {
	t.Parallel()
	const (
		jwtEncode = "jwt.api_jwt.(PyJWT).encode"
		jwsEncode = "jwt.api_jws.(PyJWS).encode"
	)
	fragments := map[ComponentKey]Fragment{
		pyClient: {
			Component: pyClient, GraphAlgoVersion: GraphAlgoVersionPython,
			Functions: []Function{{Signature: "github.Auth.(JwtSigner).jwt_sign"}},
			ExternalCalls: []ExternalCall{{
				Caller: "github.Auth.(JwtSigner).jwt_sign", TargetSignature: jwtEncode, Resolution: ResolutionExact, MethodName: "encode", CallSite: 204,
			}},
		},
		pyJWT: {
			Component: pyJWT, GraphAlgoVersion: GraphAlgoVersionPython,
			Functions: []Function{{Signature: jwtEncode}, {Signature: jwsEncode}},
			ExternalCalls: []ExternalCall{{
				Caller: jwtEncode, TargetSignature: "jwt.api_jwt.(self._jws).encode", Resolution: ResolutionNameOnly,
				MethodName: "encode", Arity: 2, CallSite: 80, ReceiverVar: "self._jws",
			}},
			CryptoOperations: []CryptoOperation{{Function: jwsEncode, FindingID: "f", RuleID: "rule", FilePath: "jwt/api_jws.py", StartLine: 208}},
		},
	}
	res, err := StitchWithOptions(pyClient, DependencyGraph{pyClient: {pyJWT}}, fragments, StitchOptions{EntryRootedOnly: true, ClasspathTargets: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	graphs := res.ToCallgraphExport(pyClient, ScanMeta{Ecosystem: "python"}).FindingGraphs
	if len(graphs) != 1 || graphs[0].Reachability != ReachabilityUnknown || graphs[0].UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("finding graphs %+v, want one unknown %q", graphs, UnresolvedReasonDispatch)
	}
}

// An import-time edge into a dependency module (`<module>` into `<module>`)
// reaches the module's top level when the dependency declares it, and has no
// name_only reading when it does not: a module without top-level code, or a
// from-imported name that is no module, runs nothing, so another module's
// top-level finding stays without a route rather than unknown.
func TestStitch_PythonImportEdgeHasNoNameOnlyReading(t *testing.T) {
	t.Parallel()
	verdict := func(target string) ExportFindingGraph {
		const sink = "jwt.algorithms.<module>"
		fragments := map[ComponentKey]Fragment{
			pyClient: {
				Component: pyClient, GraphAlgoVersion: GraphAlgoVersionPython,
				Functions: []Function{{Signature: "app.models.<module>"}},
				ExternalCalls: []ExternalCall{{
					Caller: "app.models.<module>", TargetSignature: target, Resolution: ResolutionExact, MethodName: "<module>", CallSite: 1,
				}},
			},
			pyJWT: {
				Component: pyJWT, GraphAlgoVersion: GraphAlgoVersionPython, Functions: []Function{{Signature: sink}},
				CryptoOperations: []CryptoOperation{{Function: sink, FindingID: "f", RuleID: "rule", FilePath: "x.py", StartLine: 1}},
			},
		}
		res, err := StitchWithOptions(pyClient, DependencyGraph{pyClient: {pyJWT}}, fragments, StitchOptions{EntryRootedOnly: true, ClasspathTargets: true})
		if err != nil {
			t.Fatalf("stitch: %v", err)
		}
		return res.ToCallgraphExport(pyClient, ScanMeta{Ecosystem: "python"}).FindingGraphs[0]
	}
	if fg := verdict("jwt.algorithms.<module>"); fg.Reachability != ReachabilityReachable {
		t.Errorf("importing jwt.algorithms: %q, want reachable", fg.Reachability)
	}
	for _, target := range []string{"jwt.utils.<module>", "jwt.algorithms.RSAAlgorithm.<module>"} {
		if fg := verdict(target); fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
			t.Errorf("%s: %q %q, want no route and no reason", target, fg.Reachability, fg.UnresolvedReason)
		}
	}
}

// A class read as a value (`pkg.(K).<class>`, name_only: stored in a table,
// passed or returned) may be instantiated by whatever holds it: a finding in
// K's `__init__` reads unknown, never reachable, and the edge reaches no other
// class's `__init__`.
func TestStitch_PythonClassValueReachesOnlyItsInit(t *testing.T) {
	t.Parallel()
	const (
		rsaInit   = "jwt.algorithms.(RSAAlgorithm).<init>"
		hmacInit  = "jwt.algorithms.(HMACAlgorithm).<init>"
		otherInit = "requests.auth.(RSAAlgorithm).<init>"
	)
	verdicts := func(target string) map[string]ExportFindingGraph {
		fragments := map[ComponentKey]Fragment{
			pyClient: {
				Component: pyClient, GraphAlgoVersion: GraphAlgoVersionPython,
				Functions: []Function{{Signature: "app.models.<module>"}},
				ExternalCalls: []ExternalCall{{
					Caller: "app.models.<module>", TargetSignature: target, Resolution: ResolutionNameOnly, MethodName: "<class>", CallSite: 1,
				}},
			},
			pyJWT: {
				Component: pyJWT, GraphAlgoVersion: GraphAlgoVersionPython,
				Functions: []Function{{Signature: rsaInit}, {Signature: hmacInit}},
				CryptoOperations: []CryptoOperation{
					{Function: rsaInit, FindingID: "rsa", RuleID: "rule", FilePath: "x.py", StartLine: 1},
					{Function: hmacInit, FindingID: "hmac", RuleID: "rule", FilePath: "x.py", StartLine: 2},
				},
			},
			pyRequests: {
				Component: pyRequests, GraphAlgoVersion: GraphAlgoVersionPython, Functions: []Function{{Signature: otherInit}},
				CryptoOperations: []CryptoOperation{{Function: otherInit, FindingID: "other", RuleID: "rule", FilePath: "y.py", StartLine: 1}},
			},
		}
		res, err := StitchWithOptions(pyClient, DependencyGraph{pyClient: {pyJWT, pyRequests}}, fragments,
			StitchOptions{EntryRootedOnly: true, ClasspathTargets: true, EnvironmentTargets: []string{"python"}})
		if err != nil {
			t.Fatalf("stitch: %v", err)
		}
		out := map[string]ExportFindingGraph{}
		for _, fg := range res.ToCallgraphExport(pyClient, ScanMeta{Ecosystem: "python"}).FindingGraphs {
			chain := fg.CallChains[0]
			out[chain[len(chain)-1].FunctionKey] = fg
		}
		return out
	}
	got := verdicts("jwt.algorithms.(RSAAlgorithm).<class>")
	if fg := got[rsaInit]; fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Errorf("RSAAlgorithm.__init__: %q %q, want unknown %q", fg.Reachability, fg.UnresolvedReason, UnresolvedReasonDispatch)
	}
	if fg := got[hmacInit]; fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Errorf("HMACAlgorithm.__init__: %q %q, want no route", fg.Reachability, fg.UnresolvedReason)
	}
	// Declared nowhere: the class of that name in the module's component,
	// not a namesake in another.
	got = verdicts("jwt.(RSAAlgorithm).<class>")
	if fg := got[rsaInit]; fg.Reachability != ReachabilityUnknown {
		t.Errorf("re-exported RSAAlgorithm: %q, want unknown", fg.Reachability)
	}
	if fg := got[otherInit]; fg.Reachability == ReachabilityReachable || fg.UnresolvedReason != "" {
		t.Errorf("requests' RSAAlgorithm: %q %q, want no route", fg.Reachability, fg.UnresolvedReason)
	}
}
