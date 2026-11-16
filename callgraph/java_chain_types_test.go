// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"os"
	"path/filepath"
	"testing"
)

// chainDependencyClasses is a dependency JAR as the bytecode indexer reads it:
// Holder.getInfo returns Info, Info.getDigest returns Digest, and Digest
// inherits getBytes from Base.
func chainDependencyClasses() []*classFileInfo {
	return []*classFileInfo{
		{className: "Holder", fullClassName: "dep.Holder", methods: []methodSignature{
			{className: "Holder", fullClass: "dep.Holder", methodName: "getInfo", returnType: "dep.Info"},
		}},
		{className: "Info", fullClassName: "dep.Info", methods: []methodSignature{
			{className: "Info", fullClass: "dep.Info", methodName: "getDigest", returnType: "dep.Digest"},
		}},
		{className: "Base", fullClassName: "dep.Base", methods: []methodSignature{
			{className: "Base", fullClass: "dep.Base", methodName: "getBytes", returnType: "byte[]"},
		}},
		{className: "Digest", fullClassName: "dep.Digest", superClass: "dep.Base"},
	}
}

const chainSource = `package app;
import dep.Holder;
public class A {
  private Holder holder;
  public byte[] digest() { return holder.getInfo().getDigest().getBytes(); }
}
`

func buildChainGraph(t *testing.T, typeOnly []PackageDir) *CallGraph {
	t.Helper()
	disableAmbientJavaHome(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "app"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app", "A.java"), []byte(chainSource), 0o600); err != nil {
		t.Fatal(err)
	}
	builder := NewBuilderForEcosystem(ecosystemJava, NewJavaParser())
	builder.SetTypeResolver(&JavaBytecodeTypeResolver{
		resolveJARPath: func(root PackageDir) string { return root.CompiledArtifactPath },
		extractClassInfo: func(string) ([]*classFileInfo, error) {
			return chainDependencyClasses(), nil
		},
	})
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}}, typeOnly)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

func chainCallees(t *testing.T, graph *CallGraph) map[string]string {
	t.Helper()
	fn := graph.Functions["app.(A).digest#0"]
	if fn == nil {
		t.Fatalf("app.(A).digest#0 not in graph; functions: %v", sortedKeysOf(graph.Functions))
	}
	out := make(map[string]string)
	for i := range fn.Calls {
		out[BaseFunctionName(fn.Calls[i].Callee.Name)] = fn.Calls[i].Callee.String()
	}
	return out
}

func sortedKeysOf(m map[string]*FunctionDecl) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	return keys
}

// TestTypeJavaChainLinks_DependencyReturnTypes: with the dependency JAR as a
// type-only package, each link of a chain on a dependency field is typed from
// the previous link's bytecode return type, inherited methods included.
// Before, only the first link (on the declared field) was typed and the rest
// stayed bare name#arity calls.
func TestTypeJavaChainLinks_DependencyReturnTypes(t *testing.T) {
	graph := buildChainGraph(t, []PackageDir{{ImportPath: "dep-1.0", CompiledArtifactPath: "dep-1.0.jar"}})
	callees := chainCallees(t, graph)
	want := map[string]string{
		"getInfo":   "dep.(Holder).getInfo#0",
		"getDigest": "dep.(Info).getDigest#0",
		"getBytes":  "dep.(Digest).getBytes#0",
	}
	for method, key := range want {
		if callees[method] != key {
			t.Errorf("callee of %s = %q, want %q", method, callees[method], key)
		}
		if !hasCaller(graph, key, "app.(A).digest#0") {
			t.Errorf("Callers[%s] = %v, want app.(A).digest#0", key, graph.Callers[key])
		}
	}
	for _, bare := range []string{"getDigest#0", "getBytes#0"} {
		if hasCaller(graph, bare, "app.(A).digest#0") {
			t.Errorf("Callers[%s] still lists app.(A).digest#0", bare)
		}
	}
}

// TestTypeJavaChainLinks_NoTypesNoRetype: without the JAR nothing records the
// return types, and the links stay untyped.
func TestTypeJavaChainLinks_NoTypesNoRetype(t *testing.T) {
	callees := chainCallees(t, buildChainGraph(t, nil))
	if got := callees["getDigest"]; got != "getDigest#0" {
		t.Errorf("callee of getDigest = %q, want the bare getDigest#0", got)
	}
}

func chainUnitGraph() (*CallGraph, *FunctionDecl) {
	caller := FunctionID{Package: "app", Type: "A", Name: "run#0"}
	fn := &FunctionDecl{ID: caller, Calls: []FunctionCall{
		{Callee: FunctionID{Package: "dep", Type: "Holder", Name: "getInfo#0"}, ChainID: "1", Raw: "h.getInfo", Line: 3, StartCol: 5, EndCol: 16},
		{Callee: FunctionID{Name: "size#0"}, ChainID: "1", Raw: "h.getInfo().size", Line: 3, StartCol: 5, EndCol: 23},
		{Callee: FunctionID{Name: "size#0"}, Raw: "list.size", Line: 4, StartCol: 5, EndCol: 16},
		{Callee: FunctionID{Package: "dep", Type: "Holder", Name: "getInfo#0"}, ChainID: "2", Raw: "h.getInfo", Line: 5, StartCol: 5, EndCol: 16},
		{Callee: FunctionID{Name: "missing#0"}, ChainID: "2", Raw: "h.getInfo().missing", Line: 5, StartCol: 5, EndCol: 26},
		{Callee: FunctionID{Package: "dep", Type: "Holder", Name: "getInfo#0"}, ChainID: "3", Raw: "h.getInfo", Line: 6, StartCol: 5, EndCol: 16},
		{Callee: FunctionID{Name: "size#0"}, ChainID: "3", Raw: "items.size", Line: 6, StartCol: 20, EndCol: 31},
		{Callee: FunctionID{Package: "dep", Type: "Holder", Name: "getInfo#0"}, ChainID: "4", Raw: "h.getInfo", Line: 7, StartCol: 5, EndCol: 16},
		{Callee: FunctionID{Package: "app", Type: "Sized", Name: "size#0"}, ChainID: "4", Raw: "h.getInfo().size", Line: 7, StartCol: 5, EndCol: 23},
	}}
	graph := &CallGraph{
		Functions: map[string]*FunctionDecl{caller.String(): fn},
		Callers: map[string][]string{
			"dep.(Holder).getInfo#0": {caller.String()},
			"size#0":                 {caller.String()},
			"missing#0":              {caller.String()},
			"dep.(Info).size#0":      {caller.String()},
		},
		EdgeResolutions: map[string]EdgeResolution{},
		ExternalMethodSignatures: map[string][]ExternalMethodSignature{
			ExternalMethodSignatureKey(FunctionID{Package: "dep", Type: "Holder", Name: "getInfo#0"}): {{ReturnType: "dep.Info"}},
			ExternalMethodSignatureKey(FunctionID{Package: "dep", Type: "Info", Name: "size#0"}):      {{ReturnType: "int"}},
		},
	}
	// Another call site of run already resolves to Info.size and recorded its
	// resolution, so the export lists that pair's recorded sites only.
	recordEdgeResolution(graph, caller.String(), "dep.(Info).size#0", EdgeKindExact, "", 9, 1, 2)
	// The bare link was recorded as a name-only edge at its own site.
	recordEdgeResolution(graph, caller.String(), "size#0", EdgeKindNameOnly, "", 3, 5, 23)
	return graph, fn
}

// TestTypeJavaChainLinks_MovesTheEdge: the retyped link leaves the bare
// callee's resolution and joins the typed pair's recorded sites; the caller
// stays on the bare callee while its other bare size() call still names it.
// A method the return type does not have, a link whose text does not extend
// the previous one's, and a link the parser typed are left as they were.
func TestTypeJavaChainLinks_MovesTheEdge(t *testing.T) {
	graph, fn := chainUnitGraph()
	if typed := typeJavaChainLinks(graph); typed != 1 {
		t.Fatalf("typed = %d, want 1", typed)
	}
	caller := fn.ID.String()
	if got := fn.Calls[1].Callee.String(); got != "dep.(Info).size#0" {
		t.Fatalf("chain link callee = %q, want dep.(Info).size#0", got)
	}
	if got := fn.Calls[2].Callee.String(); got != "size#0" {
		t.Errorf("unchained call callee = %q, want size#0", got)
	}
	if got := fn.Calls[4].Callee.String(); got != "missing#0" {
		t.Errorf("link on a method Info lacks = %q, want missing#0", got)
	}
	if got := fn.Calls[6].Callee.String(); got != "size#0" {
		t.Errorf("link not on the previous link's value = %q, want size#0", got)
	}
	if got := fn.Calls[8].Callee.String(); got != "app.(Sized).size#0" {
		t.Errorf("link the parser typed = %q, want app.(Sized).size#0", got)
	}
	if !hasCaller(graph, "size#0", caller) {
		t.Errorf("Callers[size#0] = %v, want %s kept for list.size()", graph.Callers["size#0"], caller)
	}
	sites := map[string][]int{}
	for key, res := range graph.EdgeResolutions {
		_, callee, _ := EdgeResolutionEndpoints(key, res)
		sites[callee] = append(sites[callee], res.CallSite)
	}
	if len(sites["size#0"]) != 0 {
		t.Errorf("bare size#0 still has resolutions at lines %v", sites["size#0"])
	}
	if got := sites["dep.(Info).size#0"]; len(got) != 2 {
		t.Errorf("dep.(Info).size#0 resolutions at lines %v, want 9 and 3", got)
	}
}

// importedReturnSources: u.Utils names its return type through a single-type
// import; app.A reaches it through an on-demand import and chains a call on
// the result.
var importedReturnSources = map[string]string{
	"u/Utils.java": `package u;
import dep.Factory;
public class Utils {
  public static Factory get() { return null; }
}
`,
	"app/A.java": `package app;
import u.*;
public class A {
  public Object run() { return Utils.get().make(); }
}
`,
}

func buildImportedReturnGraph(t *testing.T, classes []*classFileInfo) *CallGraph {
	t.Helper()
	disableAmbientJavaHome(t)
	dir := t.TempDir()
	for name, src := range importedReturnSources {
		path := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	builder := NewBuilderForEcosystem(ecosystemJava, NewJavaParser())
	builder.SetTypeResolver(&JavaBytecodeTypeResolver{
		resolveJARPath:   func(root PackageDir) string { return root.CompiledArtifactPath },
		extractClassInfo: func(string) ([]*classFileInfo, error) { return classes, nil },
	})
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: dir, ImportPath: "app"}},
		[]PackageDir{{ImportPath: "dep-1.0", CompiledArtifactPath: "dep-1.0.jar"}})
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	return graph
}

// factoryClasses is dep.Factory plus one class named Factory for each name in
// others, every one with a recorded superclass.
func factoryClasses(others ...string) []*classFileInfo {
	classes := []*classFileInfo{
		{className: "Factory", fullClassName: "dep.Factory", superClass: "dep.Spi", methods: []methodSignature{
			{className: "Factory", fullClass: "dep.Factory", methodName: "make", returnType: "java.lang.Object"},
		}},
	}
	for _, full := range others {
		classes = append(classes, &classFileInfo{className: "Factory", fullClassName: full, superClass: "dep.Spi"})
	}
	return classes
}

// TestTypeJavaChainLinks_SingleTypeImportedReturnType: a return type the
// declaring file names through a single-type import is certain however many
// top-level types elsewhere share its simple name (sshj 0.27.0 with bcprov
// and eddsa type JARs, each with a class named KeyFactory, lost
// SecurityUtils.getKeyFactory(..).generatePrivate(..)). A type that may be a
// member type in scope still leaves it in doubt.
func TestTypeJavaChainLinks_SingleTypeImportedReturnType(t *testing.T) {
	callee := func(graph *CallGraph) string {
		fn := graph.Functions["app.(A).run#0"]
		if fn == nil {
			t.Fatalf("app.(A).run#0 not in graph; functions: %v", sortedKeysOf(graph.Functions))
		}
		for i := range fn.Calls {
			if BaseFunctionName(fn.Calls[i].Callee.Name) == "make" {
				return fn.Calls[i].Callee.String()
			}
		}
		t.Fatal("no make() call in app.(A).run#0")
		return ""
	}
	if got := callee(buildImportedReturnGraph(t, factoryClasses("one.Factory", "two.Factory"))); got != "dep.(Factory).make#0" {
		t.Errorf("with two other top-level Factory types: callee = %q, want dep.(Factory).make#0", got)
	}
	if got := callee(buildImportedReturnGraph(t, factoryClasses("one.Factory", "two.Outer$Factory"))); got != "make#0" {
		t.Errorf("with a nested Factory type: callee = %q, want the bare make#0", got)
	}
}
