// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package appreach

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseDependenciesRejects(t *testing.T) {
	t.Parallel()
	dep := Dependency{Purl: "pkg:maven/g/a", Version: "1", Direct: true}
	cases := map[string]struct {
		deps   []Dependency
		limits Limits
		want   string
	}{
		"empty":      {nil, DefaultLimits, "dependencies: must not be empty"},
		"too many":   {[]Dependency{dep, {Purl: "pkg:maven/g/b", Version: "1"}}, Limits{MaxDependencies: 1}, "dependencies: 2 entries, at most 1"},
		"bad purl":   {[]Dependency{{Purl: "pkg:maven/a", Version: "1", Direct: true}}, DefaultLimits, `dependencies[0]: invalid purl "pkg:maven/a"`},
		"no version": {[]Dependency{{Purl: "pkg:maven/g/a", Direct: true}}, DefaultLimits, "dependencies[0]: version is required"},
		"conflict":   {[]Dependency{dep, {Purl: "pkg:maven/g/a@2"}}, DefaultLimits, "dependencies[1]: conflicting versions for pkg:maven/g/a (1 and 2)"},
		"pypi conflict": {[]Dependency{{Purl: "pkg:pypi/a", Version: "1.0", Direct: true}, {Purl: "pkg:pypi/A", Version: "1.0.0"}, {Purl: "pkg:pypi/a", Version: "1.1"}},
			DefaultLimits, "dependencies[2]: conflicting versions for pkg:pypi/a (1.0 and 1.1)"},
		"no direct": {[]Dependency{{Purl: "pkg:maven/g/a", Version: "1"}}, DefaultLimits, "dependencies: at least one must be direct"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseDependencies(c.deps, c.limits)
			if err == nil || err.Error() != c.want || !errors.Is(err, ErrInvalidClosure) {
				t.Fatalf("err %v, want %q matching ErrInvalidClosure", err, c.want)
			}
		})
	}
}

// Duplicates merge: direct wins, requires add up, the first spelling keeps
// its place; the version may come from the purl.
func TestParseDependenciesMerges(t *testing.T) {
	t.Parallel()
	pins, err := ParseDependencies([]Dependency{
		{Purl: "pkg:maven/g/b@2", Requires: []string{"pkg:maven/g/c"}},
		{Purl: "pkg:maven/g/a", Version: " 1 ", Direct: true},
		{Purl: "pkg:maven/g/b", Version: "2", Direct: true, Requires: []string{"pkg:maven/g/a"}},
		{Purl: "pkg:pypi/Zope.Interface", Version: "7.0-RC1"},
		{Purl: "pkg:pypi/zope_interface", Version: "7.0.0rc1"},
	}, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"pkg:maven/g/b", "pkg:maven/g/a", "pkg:pypi/zope-interface"}; !reflect.DeepEqual(pins.Order, want) {
		t.Fatalf("order %v, want %v", pins.Order, want)
	}
	b := pins.Dep["pkg:maven/g/b"]
	if !b.Direct || b.Version != "2" || !reflect.DeepEqual(b.Requires, []string{"pkg:maven/g/c", "pkg:maven/g/a"}) {
		t.Errorf("merged b %+v", b)
	}
	if v := pins.Dep["pkg:pypi/zope-interface"].Version; v != "7.0rc1" {
		t.Errorf("pypi version %q, want 7.0rc1", v)
	}
	if got, want := pins.Direct(), []string{"pkg:maven/g/b", "pkg:maven/g/a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("direct %v, want %v", got, want)
	}
	if got := pins.Keys(); !reflect.DeepEqual(got, []ComponentKey{
		{Purl: "pkg:maven/g/b", Version: "2"}, {Purl: "pkg:maven/g/a", Version: "1"}, {Purl: "pkg:pypi/zope-interface", Version: "7.0rc1"},
	}) {
		t.Errorf("keys %v", got)
	}
	if k, ok := pins.Key("pkg:pypi/ZOPE_interface@9"); !ok || k.Version != "7.0rc1" {
		t.Errorf("key by another spelling: %v %v", k, ok)
	}
	if _, ok := pins.Key("not a purl"); ok {
		t.Error("an invalid purl is pinned")
	}
}

// The closure's requires edges win; without them the caller's recorded edges
// are kept only between pinned components, whatever version they name.
func TestPinsEdges(t *testing.T) {
	t.Parallel()
	a, b, c := ComponentKey{Purl: "pkg:maven/g/a", Version: "1"}, ComponentKey{Purl: "pkg:maven/g/b", Version: "2"}, ComponentKey{Purl: "pkg:maven/g/c", Version: "3"}
	deps := []Dependency{
		{Purl: a.Purl, Version: a.Version, Direct: true, Requires: []string{b.Purl, "pkg:maven/g/unpinned", a.Purl}},
		{Purl: b.Purl, Version: b.Version},
		{Purl: c.Purl, Version: c.Version},
	}
	pins, err := ParseDependencies(deps, DefaultLimits)
	if err != nil {
		t.Fatal(err)
	}
	edges, fromRequest := pins.RequestEdges()
	if !fromRequest || !reflect.DeepEqual(edges, map[ComponentKey][]ComponentKey{a: {b}}) {
		t.Errorf("request edges %v (%v), want a -> b", edges, fromRequest)
	}
	got := pins.EdgesFrom(map[ComponentKey][]string{b: {"pkg:maven/g/c@9", "pkg:maven/g/x", b.Purl}})
	if !reflect.DeepEqual(got, map[ComponentKey][]ComponentKey{b: {c}}) {
		t.Errorf("recorded edges %v, want b -> c", got)
	}
	deps[0].Requires = nil
	pins, _ = ParseDependencies(deps, DefaultLimits)
	if _, fromRequest := pins.RequestEdges(); fromRequest {
		t.Error("no requires: edges must come from the caller")
	}
}

func TestParsePurl(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"pkg:maven/g/a@1":            "pkg:maven/g/a@1",
		"pkg:pypi/Django_Rest.Frame": "pkg:pypi/django-rest-frame",
		"pkg:npm/left-pad":           "pkg:npm/left-pad",
	} {
		p, err := ParsePurl(in)
		if err != nil || p.String() != want {
			t.Errorf("ParsePurl(%q) = %q, %v; want %q", in, p.String(), err, want)
		}
	}
	for _, in := range []string{"", "nope", "pkg:maven/a", "pkg:npm/"} {
		if _, err := ParsePurl(in); !errors.Is(err, ErrInvalidPurl) {
			t.Errorf("ParsePurl(%q) err %v, want ErrInvalidPurl", in, err)
		}
	}
}

// A PyPI purl's module id is its PEP 503 distribution name, the name the
// Python dependency resolver gives the dependency (not its import name).
func TestPurlToModule(t *testing.T) {
	t.Parallel()
	for purl, want := range map[string]string{
		"pkg:maven/org.example/lib":        "org.example:lib",
		"pkg:maven/nogroup":                "pkg:maven/nogroup",
		"pkg:pypi/pyjwt":                   "pyjwt",
		"pkg:pypi/Matrix_Synapse@1.165.0":  "matrix-synapse",
		"pkg:pypi/zope.interface?extra=x":  "zope-interface",
		"pkg:pypi/":                        "pkg:pypi/",
		"pkg:golang/filippo.io/age@v1.3.2": "filippo.io/age",
		"pkg:golang/":                      "pkg:golang/",
		"pkg:npm/left-pad":                 "pkg:npm/left-pad",
		"pkg:nuget/Acme.Util":              "Acme.Util",
		"pkg:nuget/Acme.Mail@5.0.0":        "Acme.Mail",
		"pkg:nuget/":                       "pkg:nuget/",
	} {
		if got := PurlToModule(purl); got != want {
			t.Errorf("PurlToModule(%q) = %q, want %q", purl, got, want)
		}
	}
	if got := EcosystemForPurl("pkg:maven/g/a"); got != "java" {
		t.Errorf("EcosystemForPurl(maven) = %q, want java", got)
	}
}
