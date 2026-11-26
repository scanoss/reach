// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

// Package appreach answers application reachability: given an application's
// call sites into its dependencies and the graph fragments of its pinned
// dependency closure, which annotated operations of those dependencies the
// application reaches, through which call chains, and, when it cannot tell,
// why.
//
// A caller parses the closure (ParseDependencies), loads the fragment of each
// pinned component it has one for, builds the Closure (NewClosure) and runs
// it (Closure.Run). The result holds the stitched callgraph export and one
// Verdict per finding id. What a finding is, how it is rendered and what a
// response looks like are the caller's: this package reads only the graph
// fragments and their annotated operations.
//
// The stitch policy is fixed: classpath targets, hierarchy from supertypes,
// service-provider dispatch, ambiguous dispatch served unknown, and, for
// Python components, targets resolved against the whole pinned environment.
package appreach
