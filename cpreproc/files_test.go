// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package cpreproc

import "testing"

func TestIsCFile(t *testing.T) {
	t.Parallel()

	tests := []struct {
		path     string
		expected bool
	}{
		{"main.c", true},
		{"header.h", true},
		{"code.cpp", true},
		{"code.cc", true},
		{"code.cxx", true},
		{"header.hpp", true},
		{"header.hh", true},
		{"header.hxx", true},
		{"UPPER.C", true},
		{"main.go", false},
		{"script.py", false},
		{"App.java", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			if got := IsCFile(tt.path); got != tt.expected {
				t.Errorf("IsCFile(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}
