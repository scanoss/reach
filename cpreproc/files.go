// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package cpreproc

import (
	"path/filepath"
	"strings"
)

// cLanguageExtensions lists file extensions for C/C++ source and header files.
var cLanguageExtensions = map[string]bool{
	".c": true, ".h": true,
	".cpp": true, ".cc": true, ".cxx": true,
	".hpp": true, ".hh": true, ".hxx": true,
}

// IsCFile reports a file path with a C/C++ extension.
func IsCFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return cLanguageExtensions[ext]
}
