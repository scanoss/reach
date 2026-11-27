// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

// Package fragbuild builds the graph fragment of a call graph: functions,
// edges, call sites and the facts cardmatch reads. Build is the entry point;
// the other exported names let a caller extend the fragment it writes.
package fragbuild
