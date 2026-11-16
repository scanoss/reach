// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

// Package importguard holds a test that keeps reach self-contained: its
// packages, tests included, import only the standard library, other reach
// packages and the third-party modules listed in AllowedModules. In
// particular nothing imports an application built on reach (crypto-finder);
// knowledge reaches the engine through contracts.SetSource and SetHints.
package importguard

// Module is reach's module path.
const Module = "github.com/scanoss/reach"

// AllowedModules are the third-party module paths reach's packages may
// import from. Adding one is a deliberate change: it becomes a dependency of
// every application that builds on reach.
var AllowedModules = []string{
	"github.com/go-enry/go-enry/v2",
	"github.com/package-url/packageurl-go",
	"github.com/pelletier/go-toml/v2",
	"github.com/rs/zerolog",
	"github.com/sabhiram/go-gitignore",
	"github.com/smacker/go-tree-sitter",
	"go.yaml.in/yaml/v3",
}
