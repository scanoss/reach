// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Dependency is the source directory of one dependency a call graph covers.
type Dependency struct {
	// Module and Version name the dependency in exported locations and its
	// purl.
	Module  string
	Version string
	Dir     string
	// Files is nil when the dependency owns every file below Dir, otherwise
	// the files it owns of a directory it shares: absolute, clean and sorted,
	// as ListsFile searches them.
	Files []string
}

// Artifacts locates files in the artifacts a call graph covers: the project,
// and each dependency's source directory.
//
// A reported path is relative to the root of the artifact it was found in, so
// the file it names is that root joined with the path. Matching a path to
// call-graph files by path suffix instead lets it bind to another artifact's
// file at the same relative path, or to a longer path ending the same way.
type Artifacts struct {
	ProjectRoot string
	// Dependencies is ordered longest Dir first, so the first root containing
	// a path is its innermost one.
	Dependencies []Dependency
	// dependencyByDir lists dependencies per Dir. Python distributions
	// installed into one namespace directory share it, each owning its Files.
	dependencyByDir map[string][]*Dependency
	// dependencyByVersion is the first of dependencies per module@version.
	dependencyByVersion map[string]*Dependency
	// cwd resolves relative paths, so a graph built from absolute directories
	// still matches a project given as a relative target. Empty leaves
	// relative paths relative.
	cwd string
}

// NewArtifacts indexes the project root and the dependencies that have a
// source directory.
func NewArtifacts(projectRoot string, dependencies []Dependency) Artifacts {
	artifacts := Artifacts{
		ProjectRoot:         filepath.Clean(projectRoot),
		dependencyByDir:     make(map[string][]*Dependency),
		dependencyByVersion: make(map[string]*Dependency),
	}
	if cwd, err := os.Getwd(); err == nil {
		artifacts.cwd = cwd
	}
	for _, dep := range dependencies {
		if dep.Dir == "" {
			continue
		}
		artifacts.Dependencies = append(artifacts.Dependencies, Dependency{
			Module:  dep.Module,
			Version: dep.Version,
			Dir:     filepath.Clean(dep.Dir),
			Files:   dep.Files,
		})
	}
	sort.SliceStable(artifacts.Dependencies, func(i, j int) bool {
		return len(artifacts.Dependencies[i].Dir) > len(artifacts.Dependencies[j].Dir)
	})
	for i := range artifacts.Dependencies {
		dep := &artifacts.Dependencies[i]
		artifacts.dependencyByDir[dep.Dir] = append(artifacts.dependencyByDir[dep.Dir], dep)
		key := dependencyVersionKey(dep.Module, dep.Version)
		if _, ok := artifacts.dependencyByVersion[key]; !ok {
			artifacts.dependencyByVersion[key] = dep
		}
	}
	return artifacts
}

func dependencyVersionKey(module, version string) string {
	return module + "@" + version
}

// DependencyForPath returns the innermost dependency root containing the
// cleaned path, and among roots sharing a Dir the first that owns it. It
// walks the path's ancestors instead of trying every root, so a lookup costs
// the path's depth, not the number of dependencies.
func (a *Artifacts) DependencyForPath(path string) *Dependency {
	for dir := path; ; {
		for _, dep := range a.dependencyByDir[dir] {
			if _, ok := RelativeToRoot(dep.Dir, path); ok && ListsFile(dep.Files, a.AbsPath(path)) {
				return dep
			}
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// DependencyByVersion returns the first dependency of module@version, or nil.
func (a *Artifacts) DependencyByVersion(module, version string) *Dependency {
	return a.dependencyByVersion[dependencyVersionKey(module, version)]
}

// AbsPath resolves a relative path against the working directory.
func (a *Artifacts) AbsPath(path string) string {
	if filepath.IsAbs(path) || a.cwd == "" {
		return filepath.Clean(path)
	}
	return filepath.Join(a.cwd, path)
}

// ListsFile reports whether files, a dependency's Files (sorted), include
// path, an absolute clean path below the dependency's Dir. Nil files include every
// path.
func ListsFile(files []string, path string) bool {
	if files == nil {
		return true
	}
	_, found := slices.BinarySearch(files, path)
	return found
}

// RelativeToRoot returns path relative to root, and false when path is not
// below root.
func RelativeToRoot(root, path string) (string, bool) {
	if root == "" {
		return "", false
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return "", false
	}
	if rel == "." {
		return ".", true
	}
	if strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return "", false
	}
	return rel, true
}
