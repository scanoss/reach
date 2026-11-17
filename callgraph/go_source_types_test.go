// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

const goSourceTypesDep = `package dep

type Encoding struct{ alphabet string }

func NewEncoding(alphabet string) *Encoding { return &Encoding{alphabet} }

func (e *Encoding) Strict() *Encoding { return e }

var StdEncoding = NewEncoding("abc")

type Hash uint

const (
	A Hash = 1 + iota
	B
)

type Hasher interface{ Sum() []byte }

func (h Hash) New() Hasher { return nil }

type Key struct{}

func Open(name string) (*Key, error) { return &Key{}, nil }

func (k *Key) Public() *Key { return k }

func (k *Key) Use() {}

type Sealer interface{ Seal([]byte) []byte }

func NewSealer() Sealer { return nil }
`

const goSourceTypesApp = `package app

import "example.com/dep"

func run() {
	dep.StdEncoding.Strict()
	dep.B.New()
	k, _ := dep.Open("x")
	pub := k.Public()
	pub.Use()
	s := dep.NewSealer()
	s.Seal(nil)
}
`

// TestGoSourceTypeResolver: calls on an imported package value and on locals
// bound from a dependency call's result are typed from the dependency's
// declarations: a var's initializer, an iota group's repeated type and the
// declared result of a function or method.
func TestGoSourceTypeResolver(t *testing.T) {
	root := t.TempDir()
	depDir, appDir := filepath.Join(root, "dep"), filepath.Join(root, "app")
	for dir, files := range map[string]map[string]string{
		depDir: {"dep.go": goSourceTypesDep},
		appDir: {"app.go": goSourceTypesApp},
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		for name, content := range files {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	builder := NewBuilderForEcosystem("go", NewGoParser())
	builder.SetTypeResolver(NewGoSourceTypeResolver([]GoSourceRoot{{Dir: depDir, Module: "example.com/dep"}}))
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: appDir, ImportPath: "example.com/app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	got := map[string]string{}
	for _, fn := range graph.Functions {
		for _, c := range fn.Calls {
			got[c.Raw] = c.Callee.String()
		}
	}
	for _, fn := range graph.Functions {
		for i := range fn.Calls {
			c := &fn.Calls[i]
			if iface := graph.GoInterfaceCall(c); iface != (c.Raw == "s.Seal") {
				t.Errorf("%s: GoInterfaceCall = %v, want it only for the call on the interface value", c.Raw, iface)
			}
			if graph.GoUnreadTypeCall(c) {
				t.Errorf("%s: GoUnreadTypeCall on a read package", c.Raw)
			}
		}
	}
	missing := &FunctionCall{Callee: FunctionID{Package: "example.com/missing", Type: "Hasher", Name: "Sum"}}
	if !graph.GoUnreadTypeCall(missing) {
		t.Error("GoUnreadTypeCall: want true for a type of a package no root holds")
	}
	for raw, want := range map[string]string{
		"s.Seal":                 "example.com/dep.(Sealer).Seal",
		"dep.StdEncoding.Strict": "example.com/dep.(*Encoding).Strict",
		"dep.B.New":              "example.com/dep.(Hash).New",
		"k.Public":               "example.com/dep.(*Key).Public",
		"pub.Use":                "example.com/dep.(*Key).Use",
	} {
		if got[raw] != want {
			t.Errorf("%s -> %q, want %q (all: %v)", raw, got[raw], want, got)
		}
	}
}

// TestGoSourcePackage_TypeParamsAndStrayFiles: a type parameter names no type
// of the package, and a `package main` file beside the package lends nothing.
func TestGoSourcePackage_TypeParamsAndStrayFiles(t *testing.T) {
	dir := t.TempDir()
	write := func(name, src string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("box.go", "package dep\n\ntype Box[T any] struct{ v T }\n\nfunc (b *Box[T]) Get() T { return b.v }\n\nfunc Make[T any]() *T { return new(T) }\n\nfunc Open() *Box[int] { return nil }\n")
	write("gen.go", "//go:build ignore\n\npackage main\n\ntype Gen struct{}\n\nfunc Open() *Gen { return nil }\n")
	p := parseGoSourcePackage(dir, "example.com/dep")
	if got := p.methods["Box"]["Get"]; got != "" {
		t.Errorf("Box.Get result %q, want none for a type parameter", got)
	}
	if got := p.funcs["Make"]; got != "" {
		t.Errorf("Make result %q, want none for a type parameter", got)
	}
	if got := p.funcs["Open"]; got != "*example.com/dep.Box" {
		t.Errorf("Open result %q, want the package's own *Box", got)
	}
}
