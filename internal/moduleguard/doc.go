// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

// Package moduleguard holds a test that keeps reach's tests runnable from
// the module cache. The module zip `go mod download` serves leaves out every
// directory that holds a go.mod below the root, so a fixture with its own
// go.mod passes in a checkout and is missing for an application that runs
// reach's tests from its module cache. A fixture that needs one keeps it as
// go.mod.fixture.
package moduleguard
