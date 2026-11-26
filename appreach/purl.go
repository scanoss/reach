// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package appreach

import (
	"errors"
	"strings"

	packageurl "github.com/package-url/packageurl-go"

	gf "github.com/scanoss/reach/graphfrag"
	pkgpurl "github.com/scanoss/reach/purl"
)

// ErrInvalidPurl is returned for a purl that does not parse, names no package, or misses a
// namespace its ecosystem requires.
var ErrInvalidPurl = errors.New("invalid purl")

// typesRequiringNamespace lists PURL types whose ecosystems make the namespace
// mandatory for addressability (Maven needs groupId).
var typesRequiringNamespace = map[string]bool{packageurl.TypeMaven: true}

// ParsePurl validates and canonicalizes a PURL. Its String() is the form
// a graph store keys components under.
func ParsePurl(s string) (packageurl.PackageURL, error) {
	if s == "" {
		return packageurl.PackageURL{}, ErrInvalidPurl
	}
	p, err := packageurl.FromString(s)
	if err != nil {
		return packageurl.PackageURL{}, ErrInvalidPurl
	}
	if p.Name == "" {
		return packageurl.PackageURL{}, ErrInvalidPurl
	}
	if typesRequiringNamespace[p.Type] && p.Namespace == "" {
		return packageurl.PackageURL{}, ErrInvalidPurl
	}
	if p.Type == packageurl.TypePyPi {
		// A distribution is stored under its PEP 503 name.
		p.Name = canonicalPyPIName(p.Name)
	}
	return p, nil
}

// PurlToModule converts a purl to the module id a graph fragment names a
// component by: "<group>:<artifact>" for Maven, the PEP 503 normalised
// distribution name for PyPI (what the Python dependency resolver names a
// dependency; not the import name, which a distribution may not share and a
// namespace package shares with others), the module path for Go and the
// package id for NuGet. Other purls pass through unchanged.
func PurlToModule(purl string) string {
	if rest, ok := strings.CutPrefix(purl, "pkg:golang/"); ok {
		if i := strings.IndexAny(rest, "@?#"); i >= 0 {
			rest = rest[:i]
		}
		if rest != "" {
			return rest
		}
		return purl
	}
	if rest, ok := strings.CutPrefix(purl, "pkg:pypi/"); ok {
		if i := strings.IndexAny(rest, "@?#"); i >= 0 {
			rest = rest[:i]
		}
		if rest == "" {
			return purl
		}
		return pkgpurl.PyPIName(rest)
	}
	if rest, ok := strings.CutPrefix(purl, "pkg:nuget/"); ok {
		if i := strings.IndexAny(rest, "@?#"); i >= 0 {
			rest = rest[:i]
		}
		if rest != "" {
			return rest
		}
		return purl
	}
	const prefix = "pkg:maven/"
	if !strings.HasPrefix(purl, prefix) {
		return purl
	}
	rest := purl[len(prefix):]
	group, artifact, ok := strings.Cut(rest, "/")
	if !ok {
		return purl
	}
	return group + ":" + artifact
}

// EcosystemForPurl is the graph-fragment ecosystem name for a purl's type.
func EcosystemForPurl(purl string) string {
	return gf.EcosystemForPurl(purl)
}
