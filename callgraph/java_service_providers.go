// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"bufio"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/rs/zerolog/log"
)

// javaServicesDir is where a JAR names, one file per service type, the
// classes java.util.ServiceLoader instantiates for that type.
const javaServicesDir = "META-INF" + string(filepath.Separator) + "services"

// collectJavaServiceProviders reads the ServiceLoader registrations of the
// source packages: every META-INF/services/<service type> file the package
// walk reaches (the walk's exclusions apply, so a test resource directory is
// skipped by default), keyed by the service type's binary name, each listing
// the implementation classes in file order. A registration is runtime data
// the call graph has no edge for: the loader instantiates the class by name
// and code calls it through the service type.
func (b *Builder) collectJavaServiceProviders(packages []PackageDir) map[string][]string {
	var out map[string][]string
	for _, pkg := range packages {
		b.restorePackageState(b.enterPackage(pkg))
		dirs := b.collectParseDirs(pkg.Dir, pkg.ImportPath)
		b.leavePackage()
		for _, dir := range dirs {
			if !strings.HasSuffix(filepath.Clean(dir.dir), string(filepath.Separator)+javaServicesDir) {
				continue
			}
			entries, err := os.ReadDir(dir.dir)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				if entry.IsDir() || !isJavaBinaryName(entry.Name()) {
					continue
				}
				providers := readJavaServiceFile(filepath.Join(dir.dir, entry.Name()))
				if len(providers) == 0 {
					continue
				}
				if out == nil {
					out = make(map[string][]string)
				}
				for _, p := range providers {
					if !slices.Contains(out[entry.Name()], p) {
						out[entry.Name()] = append(out[entry.Name()], p)
					}
				}
			}
		}
	}
	return out
}

// readJavaServiceFile parses a provider-configuration file as ServiceLoader
// does: UTF-8, one binary class name per line, `#` starts a comment, blank
// lines ignored. A line that is not a binary name is skipped.
func readJavaServiceFile(path string) []string {
	f, err := os.Open(path) //nolint:gosec // a file under the scanned tree
	if err != nil {
		return nil
	}
	defer func() {
		if closeErr := f.Close(); closeErr != nil {
			log.Debug().Err(closeErr).Str("path", path).Msg("Failed to close service file")
		}
	}()
	var out []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(strings.TrimPrefix(line, "\uFEFF"))
		if line != "" && isJavaBinaryName(line) && !slices.Contains(out, line) {
			out = append(out, line)
		}
	}
	return out
}

// isJavaBinaryName reports whether s reads as a qualified Java binary class
// name: dot-separated identifiers, nested classes joined by `$`.
func isJavaBinaryName(s string) bool {
	if !strings.Contains(s, ".") {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if part == "" {
			return false
		}
		for i, r := range part {
			letter := r == '_' || r == '$' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || r > 0x7f
			if !letter && (i == 0 || r < '0' || r > '9') {
				return false
			}
		}
	}
	return true
}
