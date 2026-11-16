// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"testing"

	"github.com/scanoss/reach/callgraph/contracts"
)

// contractsEnv names the knowledge base the contract-typed tests of this
// package run against. reach ships no contracts (an application installs
// them with contracts.SetSource), so these tests need one from outside: a
// directory laid out the way SetSource expects, one subdirectory per
// ecosystem holding *.yaml files. They were written against crypto-finder's
// crypto KB (its internal/cryptokb directory); crypto-finder's test target
// runs them with it. Without the variable they skip.
const contractsEnv = "REACH_TEST_CONTRACTS"

// contractsDir is the installed knowledge base directory, "" when none is.
var contractsDir string

// testHints are the language-level hints installed beside the knowledge base:
// a copy of the ones crypto-finder installs with its crypto KB
// (internal/cryptokb/hints.go), which these tests were written against.
var testHints = contracts.Hints{
	JavaWildcardTypePackages: map[string]string{
		"CertificateFactory": "java.security.cert",
		"Cipher":             "javax.crypto",
		"GCMParameterSpec":   "javax.crypto.spec",
		"IvParameterSpec":    "javax.crypto.spec",
		"KeyAgreement":       "javax.crypto",
		"KeyFactory":         "java.security",
		"KeyGenerator":       "javax.crypto",
		"KeyPairGenerator":   "java.security",
		"KeyStore":           "java.security",
		"Mac":                "javax.crypto",
		"MessageDigest":      "java.security",
		"SecretKeyFactory":   "javax.crypto",
		"SecretKeySpec":      "javax.crypto.spec",
		"SecureRandom":       "java.security",
		"Signature":          "java.security",
	},
	InferenceTriggerTypes: map[string]struct{}{
		"Key":               {},
		"java.security.Key": {},
	},
}

// TestMain installs the knowledge base contractsEnv names.
func TestMain(m *testing.M) {
	contractsDir = os.Getenv(contractsEnv)
	if contractsDir != "" {
		contracts.SetSource(os.DirFS(contractsDir))
		contracts.SetHints(testHints)
	}
	os.Exit(m.Run())
}

// requireContracts skips a test that types calls through library contracts
// when no knowledge base is installed.
func requireContracts(tb testing.TB) {
	tb.Helper()
	// Read again while the test runs, where go test logs it, so its result
	// cache keys on the variable (TestMain's read is not logged).
	_ = os.Getenv(contractsEnv)
	if contractsDir == "" {
		tb.Skip("needs a contracts knowledge base: set " + contractsEnv + " (see contracts_source_test.go)")
	}
}
