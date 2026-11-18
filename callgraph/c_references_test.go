// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// A C function handed out as a value has a caller: the function that hands
// it out (a callback argument, an assignment, a return, a local initializer),
// or the file's <varinit:file> for a file-scope table. A name a parameter or
// a local shadows, and a name that is no declared function, add nothing.
func TestCFunctionValuesAreReferences(t *testing.T) {
	t.Parallel()
	src := `#include <openssl/ts.h>

static int sha_init(void *c) { return SHA256_Init(c); }
static int sha_final(void *c) { return 1; }
static int md_size(void) { return EVP_MD_size(EVP_sha1()); }
static ASN1_INTEGER *serial_cb(TS_RESP_CTX *ctx, void *data) { RAND_bytes(0, 8); return 0; }
static void on_done(void) { RAND_bytes(0, 4); }
static void unused(void) { RAND_bytes(0, 2); }
static int pick(void) { return 0; }

struct ops { int (*init)(void *); int (*fin)(void *); int (*size)(void); };
static const struct ops table = { .init = sha_init, .fin = &sha_final, .size = (int (*)(void))md_size };

void (*done_hook)(void);

static void *chooser(int which) { return which ? (void *)pick : 0; }

int setup(TS_RESP_CTX *ctx, int on_done_flag)
{
    int (*local)(void) = pick;
    TS_RESP_CTX_set_serial_cb(ctx, serial_cb, NULL);
    done_hook = on_done;
    if (on_done_flag)
        return local();
    return table.size();
}

int shadow(int unused)
{
    return use(unused);
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem("c", NewParserForEcosystem("c")).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	callers := func(name string) []string {
		var out []string
		for _, caller := range graph.Callers["app/a.c."+name] {
			out = append(out, graph.Functions[caller].ID.Name)
		}
		sort.Strings(out)
		return out
	}
	want := map[string][]string{
		"sha_init":  {"<varinit:a>"},
		"sha_final": {"<varinit:a>"},
		"md_size":   {"<varinit:a>"},
		"serial_cb": {"setup"},
		"on_done":   {"setup"},
		"pick":      {"chooser", "setup"},
		"unused":    nil,
	}
	for name, w := range want {
		if got := callers(name); !equalStrings(got, w) {
			t.Errorf("callers of %s = %v, want %v", name, got, w)
		}
	}
	varinit := graph.Functions["app/a.c.<varinit:a>"]
	if varinit == nil {
		t.Fatalf("no <varinit:a> declaration; functions: %v", keysOf(graph.Functions))
	}
	if !implicitRoot(varinit) {
		t.Errorf("<varinit:a> is not an implicit root")
	}
	for _, call := range graph.Functions["app.setup"].Calls {
		if call.Reference {
			t.Errorf("setup lists the reference to %s among its calls; references are implicit calls", call.Callee.Name)
		}
	}
}

// After a macro line tree-sitter takes for a declarator
// (`ASN1_SEQUENCE_END(T)` then `IMPLEMENT_ASN1_FUNCTIONS(T)`), it reads the
// file-scope declarations up to the next body as K&R parameter
// declarations of a function. A table among them still belongs to the
// file's <varinit>.
func TestCFunctionTableAfterMacroLines(t *testing.T) {
	t.Parallel()
	src := `ASN1_SEQUENCE(Blob) = {
    ASN1_SIMPLE(Blob, flags, ASN1_BIT_STRING)
} ASN1_SEQUENCE_END(Blob)

IMPLEMENT_ASN1_FUNCTIONS(Blob)

static int blob_digest(void *c);

FORMAT format_blob = {
    .digest = blob_digest,
};

static int first(void)
{
    return 0;
}

static int blob_digest(void *c)
{
    return EVP_MD_size(EVP_sha1());
}
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "blob.c"), []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	graph, err := NewBuilderForEcosystem("c", NewParserForEcosystem("c")).
		BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	callers := graph.Callers["app/blob.c.blob_digest"]
	if len(callers) != 1 || callers[0] != "app/blob.c.<varinit:blob>" {
		t.Fatalf("callers of blob_digest = %v, want [app/blob.c.<varinit:blob>]; functions %v", callers, keysOf(graph.Functions))
	}
}
