// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import "testing"

var (
	nodeApp  = ComponentKey{Purl: "pkg:npm/app", Version: "1.0.0"}
	nodeSign = ComponentKey{Purl: "pkg:npm/acme-sign", Version: "2.0.1"}
)

// nodeExportCallFinding stitches an application whose function calls target
// (exact, as the application keys a call through a package specifier) into
// dep, whose function sink holds the target, and returns the finding.
func nodeExportCallFinding(t *testing.T, target, sink string, exports map[string]string) ExportFindingGraph {
	t.Helper()
	app := Fragment{
		Component:        nodeApp,
		GraphAlgoVersion: GraphAlgoVersionNode,
		Functions:        []Function{{Signature: "app/index.run"}},
		ExternalCalls: []ExternalCall{{
			Caller: "app/index.run", TargetSignature: target, Resolution: ResolutionExact, MethodName: "sign", CallSite: 3,
		}},
		EntryKinds: map[string]string{"app/index.run": RootKindMain},
	}
	dep := Fragment{
		Component:        nodeSign,
		GraphAlgoVersion: GraphAlgoVersionNode,
		Functions:        []Function{{Signature: sink}, {Signature: "acme-sign/index.other"}},
		Exports:          exports,
		CryptoOperations: []CryptoOperation{{Function: sink, FindingID: "f-1", RuleID: "rule.hmac"}},
	}
	res, err := StitchWithOptions(nodeApp, DependencyGraph{nodeApp: {nodeSign}},
		map[ComponentKey]Fragment{nodeApp: app, nodeSign: dep}, StitchOptions{EntryRootedOnly: true})
	if err != nil {
		t.Fatalf("stitch: %v", err)
	}
	cg := res.ToCallgraphExport(nodeApp, ScanMeta{Ecosystem: "node"})
	if len(cg.FindingGraphs) != 1 {
		t.Fatalf("finding graphs = %d, want 1", len(cg.FindingGraphs))
	}
	return cg.FindingGraphs[0]
}

// An application's call through a package specifier (`require('acme-sign')
// .sign()`, `import { sign } from 'acme-sign'`, a subpath, a scoped package,
// the default export, a member of an exported object) joins the function the
// dependency's fragment exports under that key; without the export it
// reaches nothing, since the dependency declares it under its module path.
func TestStitch_NodeCallJoinsThroughExports(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, target, sink string
	}{
		{"named export of the entry module", "acme-sign.sign", "acme-sign/index.sign"},
		{"default export", "acme-sign.default", "acme-sign/index.exports"},
		{"subpath", "acme-sign/lib/x.f", "acme-sign/lib/impl.f"},
		{"scoped package", "@acme/sign.sign", "@acme/sign/esm/sign.sign"},
		{"member of an exported object", "acme-sign.totp.gen", "acme-sign/index.(totp).gen"},
	}
	for _, tc := range tests {
		fg := nodeExportCallFinding(t, tc.target, tc.sink, map[string]string{tc.target: tc.sink})
		if fg.Reachability != ReachabilityReachable {
			t.Errorf("%s: reachability %q, want reachable", tc.name, fg.Reachability)
		}
		if fg := nodeExportCallFinding(t, tc.target, tc.sink, nil); fg.Reachability == ReachabilityReachable {
			t.Errorf("%s: reachable without exports", tc.name)
		}
		if fg := nodeExportCallFinding(t, tc.target, tc.sink, map[string]string{tc.target: "acme-sign/index.other"}); fg.Reachability == ReachabilityReachable {
			t.Errorf("%s: an export naming another function reached the sink", tc.name)
		}
	}
}
