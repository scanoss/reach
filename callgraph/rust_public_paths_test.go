// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"reflect"
	"testing"
)

// A crate declares a type in a private module and re-exports it: rsa declares
// SigningKey in src/pkcs1v15/signing_key.rs and consumers import
// rsa::pkcs1v15::SigningKey. Contracts name that public path, so the graph has
// to know it for the declaration keyed by the declaring module.
func TestRustBuilder_RecordsPublicPathsOfReExportedTypes(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for name, content := range map[string]string{
		"Cargo.toml": "[package]\nname = \"rsa\"\nversion = \"0.9.8\"\n",
		"src/lib.rs": `pub mod pkcs1v15;
pub mod pss;
mod key;
mod internal;
pub mod traits;
pub use crate::key::RsaPrivateKey;
pub use crate::pkcs1v15::SigningKey as Pkcs1v15SigningKey;
pub(crate) use crate::internal::Hidden;
use crate::internal::AlsoHidden;
`,
		"src/key.rs":      "pub struct RsaPrivateKey;\nimpl RsaPrivateKey { pub fn new() -> Self { RsaPrivateKey } }\n",
		"src/internal.rs": "pub struct Hidden;\npub struct AlsoHidden;\n",
		"src/pkcs1v15.rs": `mod signing_key;
mod verifying_key;
pub use self::{signing_key::SigningKey, verifying_key::VerifyingKey};
`,
		"src/pkcs1v15/signing_key.rs":   "pub struct SigningKey;\nimpl SigningKey { pub fn new() -> Self { SigningKey } }\n",
		"src/pkcs1v15/verifying_key.rs": "pub struct VerifyingKey;\n",
		"src/pss.rs":                    "mod signing_key;\npub use signing_key::SigningKey;\n",
		"src/pss/signing_key.rs":        "pub struct SigningKey;\nimpl SigningKey { pub fn new() -> Self { SigningKey } }\n",
		"src/traits.rs":                 "mod keys;\npub use keys::PublicKeyParts;\n",
		"src/traits/keys.rs":            "pub trait PublicKeyParts {}\n",
	} {
		writeRustFile(t, dir, name, content)
	}

	graph, err := NewBuilderForEcosystem(ecosystemRust, NewRustParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "rsa"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	want := map[string][]string{
		"rsa::key::RsaPrivateKey":                    {"rsa::RsaPrivateKey"},
		"rsa::pkcs1v15::signing_key::SigningKey":     {"rsa::Pkcs1v15SigningKey", "rsa::pkcs1v15::SigningKey"},
		"rsa::pkcs1v15::verifying_key::VerifyingKey": {"rsa::pkcs1v15::VerifyingKey"},
		"rsa::pss::signing_key::SigningKey":          {"rsa::pss::SigningKey"},
		"rsa::traits::keys::PublicKeyParts":          {"rsa::traits::PublicKeyParts"},
	}
	if !reflect.DeepEqual(graph.PublicTypePaths, want) {
		t.Errorf("PublicTypePaths = %v\nwant %v", graph.PublicTypePaths, want)
	}

	// The declaring key must be the one the declaration carries, or the map
	// joins nothing.
	for _, fn := range graph.Functions {
		if fn.ID.Name != "new" {
			continue
		}
		if _, ok := graph.PublicTypePaths[fn.ID.Package+"::"+fn.ID.Type]; !ok {
			t.Errorf("declaration %s has no public path under %q", fn.ID.String(), fn.ID.Package+"::"+fn.ID.Type)
		}
	}
}

// A dependency crate is called by the paths its `pub use` items give its
// functions, types and modules, not by the modules that declare them: a
// consumer writes `acme_sign::sign(..)` and `acme_sign::Signer::new()` while
// the crate declares `acme_sign::sig::imp.sign` and
// `acme_sign::sig.(Signer).new`. RustExports maps each such public path, in
// function-key form, to the declaration, so the stitch joins a consumer's call
// to the dependency's function. A module is public at its own path too
// (`acme_sign.sig`), which joins the key a call through an imported module
// gets (`use acme_sign::sig; sig::sign(..)` is `acme_sign.(sig).sign`).
func TestRustBuilder_ExportsPublicPaths(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for name, content := range map[string]string{
		"Cargo.toml": "[package]\nname = \"acme-sign\"\nversion = \"1.0.0\"\nedition = \"2021\"\n\n[dependencies]\nacme-rng = \"1\"\n",
		"src/lib.rs": `pub mod sig;
pub use acme_rng::OsRng;
pub use acme_rng::fill;
mod inner;
mod hidden;
pub use sig::{sign, Signer};
pub use crate::inner::Hasher as Digest;
pub use sig::extra::*;
pub use sig::extra as tools;
pub(crate) use hidden::secret;
pub type Wide = inner::Hasher<u8>;
type Private = inner::Hasher;
`,
		"src/sig.rs": `mod imp;
pub mod extra;
pub use self::imp::sign;
pub struct Signer;
impl Signer { pub fn new() -> Self { Signer } }
pub type Fast = Signer;
`,
		"src/sig/imp.rs":   "pub fn sign(data: &[u8]) -> u8 { data[0] }\n",
		"src/inner.rs":     "pub struct Hasher;\nimpl Hasher { pub fn new() -> Self { Hasher } }\n",
		"src/sig/extra.rs": "pub fn mix(x: u8) -> u8 { x }\npub struct Mixer;\nimpl Mixer { pub fn run(&self) {} }\n",
		"src/hidden.rs":    "pub fn secret() -> u8 { 0 }\n",
	} {
		writeRustFile(t, dir, name, content)
	}

	graph, err := NewBuilderForEcosystem(ecosystemRust, NewRustParser()).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "acme_sign"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}

	want := map[string]string{
		"acme_sign.sign":         "acme_sign::sig::imp.sign",
		"acme_sign.Signer":       "acme_sign::sig.(Signer)",
		"acme_sign.Digest":       "acme_sign::inner.(Hasher)",
		"acme_sign.mix":          "acme_sign::sig::extra.mix",
		"acme_sign.Mixer":        "acme_sign::sig::extra.(Mixer)",
		"acme_sign::sig.sign":    "acme_sign::sig::imp.sign",
		"acme_sign.sig":          "acme_sign::sig",
		"acme_sign::sig.imp":     "acme_sign::sig::imp",
		"acme_sign.inner":        "acme_sign::inner",
		"acme_sign::sig.extra":   "acme_sign::sig::extra",
		"acme_sign.tools":        "acme_sign::sig::extra",
		"acme_sign.OsRng":        "acme_rng.(OsRng)",
		"acme_sign.fill":         "acme_rng.fill",
		"acme_sign.Wide":         "acme_sign::inner.(Hasher)",
		"acme_sign::sig.Fast":    "acme_sign::sig.(Signer)",
		"acme_sign::tools.mix":   "acme_sign::sig::extra.mix",
		"acme_sign::tools.Mixer": "acme_sign::sig::extra.(Mixer)",
		"acme_sign.hidden":       "acme_sign::hidden",
	}
	if !reflect.DeepEqual(graph.RustExports, want) {
		t.Errorf("RustExports = %v\nwant %v", graph.RustExports, want)
	}

	// The package name carries a dash; code, function keys and the crate's
	// public type paths spell the library name.
	wantTypes := map[string][]string{
		"acme_rng::OsRng":          {"acme_sign::OsRng"},
		"acme_sign::inner::Hasher": {"acme_sign::Digest"},
		"acme_sign::sig::Signer":   {"acme_sign::Signer"},
	}
	if !reflect.DeepEqual(graph.PublicTypePaths, wantTypes) {
		t.Errorf("PublicTypePaths = %v\nwant %v", graph.PublicTypePaths, wantTypes)
	}

	// Every function declaration an export names must exist under that key.
	declared := make(map[string]bool)
	for _, fn := range graph.Functions {
		declared[fn.ID.String()] = true
	}
	for _, key := range []string{"acme_sign::sig::imp.sign", "acme_sign::sig.(Signer).new", "acme_sign::inner.(Hasher).new", "acme_sign::sig::extra.mix", "acme_sign::sig::extra.(Mixer).run"} {
		if !declared[key] {
			t.Errorf("no declaration %s; declared %v", key, declared)
		}
	}
}
