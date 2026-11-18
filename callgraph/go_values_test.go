// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// The spans are OpenGrep 1.33.1's for the same source (go-port audit E3):
// `tls.Config{..., MinVersion: $V, ...}` 10:7-47 and 19:4-44,
// `&tls.Config{...}` 11:7 to 13:3 (AddrCol 7, the literal from 8),
// `rsa.PSSOptions{...}` 14:11-40, `new(ecdsa.PrivateKey)` 15:10-28 (OpenGrep
// starts it at the parenthesis; the fact keeps the expression's own span, 7),
// `$C.MinVersion = $V` 17:2-33, `($C : *tls.Config).CipherSuites = $V` 18:2-57.
func TestGoParser_Values(t *testing.T) {
	const source = `package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
)

func main() {
	a := tls.Config{MinVersion: tls.VersionTLS10}
	b := &tls.Config{
		InsecureSkipVerify: true,
	}
	opts := &rsa.PSSOptions{SaltLength: 0}
	k := new(ecdsa.PrivateKey)
	var c tls.Config
	c.MinVersion = tls.VersionTLS11
	b.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}
	f(tls.Config{MinVersion: tls.VersionTLS12})
	_, _, _, _ = a, opts, k, c
}

func f(tls.Config) {}
`
	dir := t.TempDir()
	path := filepath.Join(dir, "main.go")
	if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	analysis, err := NewGoParser().ParseFile(path, "example.com/app")
	if err != nil {
		t.Fatal(err)
	}
	const fn = "example.com/app.main"
	want := []GoValue{
		{Kind: GoValueComposite, Function: fn, Line: 10, StartCol: 7, EndCol: 47, TypeText: "tls.Config", Package: "crypto/tls", Type: "Config",
			Fields: []GoValueField{{Name: "MinVersion", Value: "tls.VersionTLS10", Line: 10, StartCol: 30, EndCol: 46}}},
		{Kind: GoValueComposite, Function: fn, Line: 11, StartCol: 8, EndCol: 3, EndLine: 13, AddrCol: 7, TypeText: "tls.Config", Package: "crypto/tls", Type: "Config",
			Fields: []GoValueField{{Name: "InsecureSkipVerify", Value: "true", Line: 12, StartCol: 23, EndCol: 27}}},
		{Kind: GoValueComposite, Function: fn, Line: 14, StartCol: 11, EndCol: 40, AddrCol: 10, TypeText: "rsa.PSSOptions", Package: "crypto/rsa", Type: "PSSOptions",
			Fields: []GoValueField{{Name: "SaltLength", Value: "0", Line: 14, StartCol: 38, EndCol: 39}}},
		{Kind: GoValueNew, Function: fn, Line: 15, StartCol: 7, EndCol: 28, TypeText: "ecdsa.PrivateKey", Package: "crypto/ecdsa", Type: "PrivateKey"},
		{Kind: GoValueStore, Function: fn, Line: 17, StartCol: 2, EndCol: 33, TypeText: "tls.Config", Package: "crypto/tls", Type: "Config", Receiver: "c",
			Fields: []GoValueField{{Name: "MinVersion", Value: "tls.VersionTLS11", Line: 17, StartCol: 17, EndCol: 33}}},
		{Kind: GoValueStore, Function: fn, Line: 18, StartCol: 2, EndCol: 57, TypeText: "*tls.Config", Package: "crypto/tls", Type: "*Config", Receiver: "b",
			Fields: []GoValueField{{Name: "CipherSuites", Value: "[]uint16{tls.TLS_RSA_WITH_RC4_128_SHA}", Line: 18, StartCol: 19, EndCol: 57}}},
		{Kind: GoValueComposite, Function: fn, Line: 18, StartCol: 19, EndCol: 57, TypeText: "[]uint16",
			Fields: []GoValueField{{Value: "tls.TLS_RSA_WITH_RC4_128_SHA", Line: 18, StartCol: 28, EndCol: 56}}},
		{Kind: GoValueComposite, Function: fn, Line: 19, StartCol: 4, EndCol: 44, TypeText: "tls.Config", Package: "crypto/tls", Type: "Config",
			Fields: []GoValueField{{Name: "MinVersion", Value: "tls.VersionTLS12", Line: 19, StartCol: 27, EndCol: 43}}},
	}
	if len(analysis.GoValues) != len(want) {
		t.Fatalf("%d values, want %d: %+v", len(analysis.GoValues), len(want), analysis.GoValues)
	}
	for i := range want {
		if !reflect.DeepEqual(analysis.GoValues[i], want[i]) {
			t.Errorf("value %d:\n got %+v\nwant %+v", i, analysis.GoValues[i], want[i])
		}
	}
}
