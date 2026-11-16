// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

var (
	pyClient = ComponentKey{Purl: "pkg:pypi/client", Version: "1.0.0"}
	pyJWT    = ComponentKey{Purl: "pkg:pypi/pyjwt", Version: "2.13.0"}
)

// pythonNameOnlyFinding stitches a Python client calling `signer.sign(data)` on a
// duck-typed parameter (name_only, method sign, one argument) into a
// dependency function sinkKey holding crypto, and returns its finding.
// Python function keys carry no arity.
func pythonNameOnlyFinding(t *testing.T, resolution ResolutionKind, sinkKey string) ExportFindingGraph {
	t.Helper()
	root := Fragment{
		Component: pyClient,
		Functions: []Function{{Signature: "app.main.handle"}},
		ExternalCalls: []ExternalCall{{
			Caller: "app.main.handle", TargetSignature: "app.main.(signer).sign",
			Resolution: resolution, MethodName: "sign", Arity: 1, CallSite: 3,
		}},
	}
	sink := Fragment{
		Component: pyJWT,
		Functions: []Function{{Signature: sinkKey}},
		CryptoOperations: []CryptoOperation{
			{Function: sinkKey, FindingID: "f-rsa", RuleID: "rule.rsa"},
		},
	}
	return onlyStitchedFinding(t, pyClient, DependencyGraph{pyClient: {pyJWT}}, map[ComponentKey]Fragment{pyClient: root, pyJWT: sink})
}

// A Python name_only call matches a dependency method by name alone (its key
// has no arity to compare with), so the finding there reads unknown with
// unresolved_dispatch. The same call exported exact (before honest
// resolution) found no target and read unreachable.
func TestStitch_PythonNameOnlyCallMatchesByName(t *testing.T) {
	t.Parallel()
	const sinkKey = "jwt.algorithms.(RSAAlgorithm).sign"
	fg := pythonNameOnlyFinding(t, ResolutionNameOnly, sinkKey)
	if fg.Reachability != ReachabilityUnknown || fg.UnresolvedReason != UnresolvedReasonDispatch {
		t.Fatalf("name_only: reachability %q reason %q, want %q %q", fg.Reachability, fg.UnresolvedReason, ReachabilityUnknown, UnresolvedReasonDispatch)
	}
	fg = pythonNameOnlyFinding(t, ResolutionExact, sinkKey)
	if fg.Reachability != ReachabilityUnreachable {
		t.Fatalf("exact: reachability %q, want %q", fg.Reachability, ReachabilityUnreachable)
	}
}

// The arity-free name never matches a Java key (name#arity, nor a synthetic
// `sign$lambda$0#1` the index cuts at its `$`), and a Python
// method of another name is no candidate: the call reaches nothing, so the
// finding is not unknown for unresolved dispatch. (It still reads unknown
// rather than unreachable: the stitch refused an edge, so it cannot prove the
// negative.)
func TestStitch_PythonNameOnlyCallIgnoresOtherNames(t *testing.T) {
	t.Parallel()
	for _, sinkKey := range []string{"net.crypto.(Signer).sign#1", "net.crypto.(Signer).sign$lambda$0#1", "jwt.algorithms.(RSAAlgorithm).verify"} {
		fg := pythonNameOnlyFinding(t, ResolutionNameOnly, sinkKey)
		if fg.Reachability == ReachabilityReachable || fg.UnresolvedReason == UnresolvedReasonDispatch {
			t.Errorf("%s: reachability %q reason %q, want no dispatch candidate", sinkKey, fg.Reachability, fg.UnresolvedReason)
		}
	}
}
