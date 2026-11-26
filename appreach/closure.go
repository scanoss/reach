// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package appreach

import (
	"errors"
	"fmt"
	"strings"
)

// Limits bounds one application's closure.
type Limits struct {
	MaxDependencies int
	MaxCallSites    int
}

// DefaultLimits are the limits a server starts with.
var DefaultLimits = Limits{MaxDependencies: 1000, MaxCallSites: 50000}

// Dependency is one member of the application's pinned dependency closure.
type Dependency struct {
	Purl    string `json:"purl"`
	Version string `json:"version"`
	// Direct marks a dependency the application declares itself.
	Direct bool `json:"direct"`
	// Requires lists the purls this dependency depends on in the application's
	// resolved tree, each pinned elsewhere in the closure. When no dependency
	// carries it, the caller supplies the edges (EdgesFrom), for example those
	// a store recorded when it indexed each component.
	Requires []string `json:"requires,omitempty"`
	// Markers and Extras, for a Python dependency, are the PEP 508
	// environment markers under which the application installs it and the
	// extras it enables, as the lock writes them. They are informational:
	// the closure is the union of every marker branch, and no verdict reads
	// them.
	Markers []string `json:"markers,omitempty"`
	Extras  []string `json:"extras,omitempty"`
}

// Pins is the closure, keyed by canonical versionless purl, in the order the
// caller listed it.
type Pins struct {
	Order []string
	Dep   map[string]Dependency
}

// Direct lists the dependencies the application declares, in order.
func (p Pins) Direct() []string {
	var out []string
	for _, purl := range p.Order {
		if p.Dep[purl].Direct {
			out = append(out, purl)
		}
	}
	return out
}

// Key is the pinned component of a purl, versioned or not, if it is pinned.
func (p Pins) Key(purl string) (ComponentKey, bool) {
	parsed, err := ParsePurl(purl)
	if err != nil {
		return ComponentKey{}, false
	}
	parsed.Version = ""
	d, ok := p.Dep[parsed.String()]
	return ComponentKey{Purl: d.Purl, Version: d.Version}, ok
}

// Keys are the pinned components, in order.
func (p Pins) Keys() []ComponentKey {
	keys := make([]ComponentKey, len(p.Order))
	for i, purl := range p.Order {
		keys[i] = ComponentKey{Purl: purl, Version: p.Dep[purl].Version}
	}
	return keys
}

// ErrInvalidClosure is wrapped by every ParseDependencies rejection.
var ErrInvalidClosure = errors.New("invalid dependency closure")

// closureError is a rejection whose message is the caller-facing reason
// alone; it still matches ErrInvalidClosure.
type closureError struct{ msg string }

func (e *closureError) Error() string { return e.msg }

func (e *closureError) Unwrap() error { return ErrInvalidClosure }

func rejectClosure(format string, args ...any) (Pins, error) {
	return Pins{}, &closureError{msg: fmt.Sprintf(format, args...)}
}

// ParseDependencies canonicalizes the closure. A malformed closure (empty,
// too large, an invalid purl, a missing version, conflicting versions for one
// purl, no direct dependency) is rejected as a whole: the closure is one
// resolved classpath, and a hole in it changes every verdict. The error's
// message names the offending entry, for example
// "dependencies[2]: version is required", and matches ErrInvalidClosure.
func ParseDependencies(deps []Dependency, limits Limits) (Pins, error) {
	if len(deps) == 0 {
		return rejectClosure("dependencies: must not be empty")
	}
	if len(deps) > limits.MaxDependencies {
		return rejectClosure("dependencies: %d entries, at most %d", len(deps), limits.MaxDependencies)
	}
	pins := Pins{Dep: make(map[string]Dependency, len(deps))}
	anyDirect := false
	for i, d := range deps {
		p, err := ParsePurl(d.Purl)
		if err != nil {
			return rejectClosure("dependencies[%d]: invalid purl %q", i, d.Purl)
		}
		version := strings.TrimSpace(d.Version)
		if version == "" {
			version = p.Version
		}
		if version == "" {
			return rejectClosure("dependencies[%d]: version is required", i)
		}
		pypi := p.Type == "pypi"
		if pypi {
			version = PyPIVersion(version)
		}
		p.Version = ""
		canonical := p.String()
		if prev, seen := pins.Dep[canonical]; seen {
			if prev.Version != version && (!pypi || !PyPIVersionsEqual(prev.Version, version)) {
				return rejectClosure("dependencies[%d]: conflicting versions for %s (%s and %s)", i, canonical, prev.Version, version)
			}
			prev.Direct = prev.Direct || d.Direct
			prev.Requires = append(prev.Requires, d.Requires...)
			pins.Dep[canonical] = prev
			continue
		}
		d.Purl, d.Version = canonical, version
		pins.Dep[canonical] = d
		pins.Order = append(pins.Order, canonical)
		anyDirect = anyDirect || d.Direct
	}
	if !anyDirect {
		return rejectClosure("dependencies: at least one must be direct")
	}
	return pins, nil
}

// RequestEdges returns the dependency edges the closure's requires name among
// its pinned components, and whether any dependency named what it requires.
// When none did, the caller supplies the edges (EdgesFrom).
func (p Pins) RequestEdges() (map[ComponentKey][]ComponentKey, bool) {
	out := make(map[ComponentKey][]ComponentKey)
	fromRequest := false
	for _, purl := range p.Order {
		d := p.Dep[purl]
		if len(d.Requires) == 0 {
			continue
		}
		fromRequest = true
		parent := ComponentKey{Purl: d.Purl, Version: d.Version}
		for _, r := range d.Requires {
			if child, ok := p.Key(r); ok && child != parent {
				out[parent] = append(out[parent], child)
			}
		}
	}
	return out, fromRequest
}

// EdgesFrom keeps, of the edges recorded elsewhere (each pinned version and
// the purls it depended on), those between pinned components.
func (p Pins) EdgesFrom(recorded map[ComponentKey][]string) map[ComponentKey][]ComponentKey {
	out := make(map[ComponentKey][]ComponentKey)
	for parent, children := range recorded {
		for _, purl := range children {
			if child, ok := p.Key(purl); ok && child != parent {
				out[parent] = append(out[parent], child)
			}
		}
	}
	return out
}
