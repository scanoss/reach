// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"sync"
	"testing"
)

// sharedIndexFixture is a generated Java platform and a set of type JARs
// whose class names overlap by simple name, whose classes inherit across the
// JAR/platform boundary, and whose methods are overloaded.
type sharedIndexFixture struct {
	platform map[string][]*classFileInfo // archive path -> classes
	jars     map[string][]*classFileInfo // JAR path -> classes
}

var sharedIndexSimpleNames = []string{"Builder", "Node", "Cipher", "Key", "Util"}
var sharedIndexMethodNames = []string{"build", "get", "init", "update", "digest"}

func generateSharedIndexClasses(rng *rand.Rand, packages []string, count int, parentPool []string) []*classFileInfo {
	classes := make([]*classFileInfo, 0, count)
	seen := make(map[string]bool)
	for len(classes) < count {
		pkg := packages[rng.Intn(len(packages))]
		simple := sharedIndexSimpleNames[rng.Intn(len(sharedIndexSimpleNames))]
		if rng.Intn(3) == 0 {
			simple += fmt.Sprintf("%d", rng.Intn(4))
		}
		full := pkg + "." + simple
		if seen[full] {
			continue
		}
		seen[full] = true
		info := &classFileInfo{className: simple, fullClassName: full}
		if len(parentPool) > 0 && rng.Intn(4) != 0 {
			info.superClass = parentPool[rng.Intn(len(parentPool))]
		}
		if len(parentPool) > 0 && rng.Intn(3) == 0 {
			info.interfaces = []string{parentPool[rng.Intn(len(parentPool))]}
		}
		for range rng.Intn(4) {
			method := sharedIndexMethodNames[rng.Intn(len(sharedIndexMethodNames))]
			params := make([]string, rng.Intn(3))
			for i := range params {
				params[i] = fmt.Sprintf("T%d", rng.Intn(3))
			}
			info.methods = append(info.methods, methodSignature{
				className:  simple,
				methodName: method,
				paramTypes: params,
				returnType: fmt.Sprintf("R%d", rng.Intn(3)),
				fullClass:  full,
			})
		}
		classes = append(classes, info)
		// Later classes may extend this one; the hierarchy stays acyclic.
		parentPool = append(parentPool, full)
	}
	return classes
}

func classNames(classes []*classFileInfo) []string {
	names := make([]string, 0, len(classes))
	for _, c := range classes {
		names = append(names, c.fullClassName)
	}
	return names
}

func newSharedIndexFixture(seed int64) *sharedIndexFixture {
	rng := rand.New(rand.NewSource(seed))
	platformA := generateSharedIndexClasses(rng, []string{"java.lang", "java.util", "java.security"}, 60, nil)
	platformB := generateSharedIndexClasses(rng, []string{"javax.crypto", "java.io"}, 40, classNames(platformA))
	platformClasses := append(append([]*classFileInfo{}, platformA...), platformB...)
	platformNames := classNames(platformClasses)

	jarA := generateSharedIndexClasses(rng, []string{"com.acme", "zz.tail"}, 25, platformNames)
	jarB := generateSharedIndexClasses(rng, []string{"aa.head", "org.lib"}, 25, append(append([]string{}, platformNames...), classNames(jarA)...))
	// jarC redefines a platform class, as xml-apis redefines org.w3c.dom.
	collider := *platformA[0]
	collider.methods = append([]methodSignature{{
		className:  collider.className,
		methodName: "extra",
		paramTypes: []string{"T9"},
		returnType: "R9",
		fullClass:  collider.fullClassName,
	}}, collider.methods...)
	jarC := []*classFileInfo{&collider}
	// jarD repeats some of jarA's classes with other methods and parents, so
	// the order of the type JARs decides the merged index and hierarchy.
	var jarD []*classFileInfo
	for i, c := range jarA[:10] {
		dup := *c
		dup.methods = []methodSignature{{
			className:  c.className,
			methodName: sharedIndexMethodNames[i%len(sharedIndexMethodNames)],
			paramTypes: []string{"D"},
			returnType: "RD",
			fullClass:  c.fullClassName,
		}}
		dup.superClass = platformNames[i]
		jarD = append(jarD, &dup)
	}
	// Three overloads of one arity give external signature slices spare
	// capacity.
	platformA = append(platformA, &classFileInfo{
		className:     "Overloaded",
		fullClassName: "java.lang.Overloaded",
		methods: []methodSignature{
			{className: "Overloaded", methodName: "of", paramTypes: []string{"A"}, returnType: "R", fullClass: "java.lang.Overloaded"},
			{className: "Overloaded", methodName: "of", paramTypes: []string{"B"}, returnType: "R", fullClass: "java.lang.Overloaded"},
			{className: "Overloaded", methodName: "of", paramTypes: []string{"C"}, returnType: "R", fullClass: "java.lang.Overloaded"},
		},
	})

	return &sharedIndexFixture{
		platform: map[string][]*classFileInfo{
			"/virtual/java.base.jmod":  platformA,
			"/virtual/java.other.jmod": platformB,
		},
		jars: map[string][]*classFileInfo{
			"/virtual/a.jar": jarA,
			"/virtual/b.jar": jarB,
			"/virtual/c.jar": jarC,
			"/virtual/d.jar": jarD,
		},
	}
}

func (f *sharedIndexFixture) resolver(shared *SharedJavaTypeIndex) *JavaBytecodeTypeResolver {
	r := &JavaBytecodeTypeResolver{
		resolveJARPath: func(root PackageDir) string { return root.CompiledArtifactPath },
		resolvePlatformSource: func() (*javaPlatformIndexSource, error) {
			return &javaPlatformIndexSource{
				RuntimeVersion:  "21.0.1",
				SignatureSource: "jmods",
				ArchivePaths:    []string{"/virtual/java.base.jmod", "/virtual/java.other.jmod"},
				ArtifactKey:     "jdk-platform@21.0.1:jmods",
			}, nil
		},
		extractClassInfo: func(path string) ([]*classFileInfo, error) {
			if classes, ok := f.platform[path]; ok {
				return classes, nil
			}
			if classes, ok := f.jars[path]; ok {
				return classes, nil
			}
			return nil, fmt.Errorf("no archive %s", path)
		},
	}
	r.SetSharedIndex(shared)
	return r
}

func sharedIndexRoots(jars ...string) []PackageDir {
	roots := make([]PackageDir, 0, len(jars))
	for _, jar := range jars {
		roots = append(roots, PackageDir{ImportPath: "g:" + jar, Version: "1", CompiledArtifactPath: jar})
	}
	return roots
}

// newSharedIndexGraph declares one method per JAR class and calls every
// class of the fixture by simple name under a guessed package, so lookups go
// through the simple buckets both layers share.
func (f *sharedIndexFixture) newGraph() *CallGraph {
	graph := &CallGraph{Functions: map[string]*FunctionDecl{}, Callers: map[string][]string{}}
	caller := &FunctionDecl{ID: FunctionID{Package: "app", Type: "Main", Name: "run#0"}}
	addCalls := func(classes []*classFileInfo) {
		for _, c := range classes {
			for _, method := range sharedIndexMethodNames {
				for arity := range 3 {
					caller.Calls = append(caller.Calls, FunctionCall{
						Callee:    FunctionID{Package: "app", Type: c.className, Name: fmt.Sprintf("%s#%d", method, arity)},
						Arguments: make([]string, arity),
					})
				}
			}
		}
	}
	for _, path := range []string{"/virtual/a.jar", "/virtual/b.jar", "/virtual/c.jar", "/virtual/d.jar"} {
		for _, c := range f.jars[path] {
			pkg, _, _ := splitQualifiedJavaType(c.fullClassName)
			for _, method := range sharedIndexMethodNames {
				decl := &FunctionDecl{
					ID:         FunctionID{Package: pkg, Type: c.className, Name: method + "#1"},
					Parameters: []FunctionParameter{{Type: ""}},
				}
				graph.Functions[decl.ID.String()] = decl
			}
		}
		addCalls(f.jars[path])
	}
	addCalls(f.platform["/virtual/java.base.jmod"])
	graph.Functions[caller.ID.String()] = caller
	return graph
}

type graphTypeSnapshot struct {
	Hierarchy  map[string][]string
	External   map[string][]ExternalMethodSignature
	Platform   JavaPlatformSignatureMetadata
	Decls      map[string]string
	CallTarget []string
	Callers    map[string][]string
}

func snapshotGraphTypes(graph *CallGraph) graphTypeSnapshot {
	snap := graphTypeSnapshot{
		Hierarchy: graph.TypeHierarchy,
		External:  graph.ExternalMethodSignatures,
		Decls:     map[string]string{},
		Callers:   graph.Callers,
	}
	if graph.JavaPlatformSignatures != nil {
		snap.Platform = *graph.JavaPlatformSignatures
	}
	for key, fn := range graph.Functions {
		snap.Decls[key] = fmt.Sprintf("%v -> %s", fn.Parameters, fn.ReturnType)
		for _, call := range fn.Calls {
			snap.CallTarget = append(snap.CallTarget, key+" => "+call.Callee.String())
		}
	}
	sort.Strings(snap.CallTarget)
	return snap
}

// flatLookup is every non-empty lookup entry, whichever layer holds it.
func flatLookup(lookup *javaMethodLookup) map[string][]methodSignature {
	out := map[string][]methodSignature{}
	buckets := map[string]func(*javaMethodLookup) map[string][]methodSignature{
		"q:": lookupQualified, "s:": lookupSimple, "qa:": lookupQualifiedArity, "sa:": lookupSimpleArity,
	}
	for prefix, bucket := range buckets {
		for layer := lookup; layer != nil; layer = layer.base {
			for key := range bucket(layer) {
				if sigs := lookup.find(bucket, key); len(sigs) > 0 {
					out[prefix+key] = sigs
				}
			}
		}
	}
	return out
}

func unsharedProducts(t *testing.T, f *sharedIndexFixture, jars ...string) *javaTypeProducts {
	t.Helper()
	r := f.resolver(nil)
	source, err := r.discoverPlatformSource()
	if err != nil {
		t.Fatal(err)
	}
	index, hierarchy, _ := r.buildIndexes(r.collectJARTasks(sharedIndexRoots(jars...)), 2)
	r.mergePlatformIndex(index, hierarchy, source, r.platformSignatureMetadata(source, nil))
	return buildJavaTypeProducts(index, hierarchy)
}

func sharedProducts(t *testing.T, f *sharedIndexFixture, shared *SharedJavaTypeIndex, jars ...string) *javaTypeProducts {
	t.Helper()
	r := f.resolver(shared)
	source, err := r.discoverPlatformSource()
	if err != nil {
		t.Fatal(err)
	}
	products, _ := shared.resolve(r, r.collectJARTasks(sharedIndexRoots(jars...)), 2, source, r.platformSignatureMetadata(source, nil))
	return products
}

func layersShareSimpleBuckets(lookup *javaMethodLookup) bool {
	for key := range lookup.simpleArity {
		if _, ok := lookup.base.simpleArity[key]; ok {
			return true
		}
	}
	return false
}

func mergedLayers[V any](layers []map[string]V) map[string]V {
	out := map[string]V{}
	for _, layer := range layers {
		for k, v := range layer {
			out[k] = v
		}
	}
	return out
}

func TestSharedJavaTypeIndex_ProductsMatchUnsharedResolution(t *testing.T) {
	cases := []struct {
		name string
		jars []string
		path string
	}{
		{"platform only", nil, sharedJavaTypesPlatformOnly},
		{"one jar", []string{"/virtual/a.jar"}, sharedJavaTypesLayered},
		{"two jars", []string{"/virtual/b.jar", "/virtual/a.jar"}, sharedJavaTypesLayered},
		{"overlapping jars", []string{"/virtual/a.jar", "/virtual/d.jar"}, sharedJavaTypesLayered},
		{"overlapping jars reversed", []string{"/virtual/d.jar", "/virtual/b.jar", "/virtual/a.jar"}, sharedJavaTypesLayered},
		{"jar redefining a platform class", []string{"/virtual/a.jar", "/virtual/c.jar"}, sharedJavaTypesFull},
	}
	for seed := range int64(8) {
		f := newSharedIndexFixture(seed)
		shared := NewSharedJavaTypeIndex()
		for _, tc := range cases {
			want := unsharedProducts(t, f, tc.jars...)
			// Twice: the second resolution reuses everything memoized.
			for round := range 2 {
				got := sharedProducts(t, f, shared, tc.jars...)
				if got.sharedPath != tc.path {
					t.Fatalf("seed %d %s: shared path = %q, want %q", seed, tc.name, got.sharedPath, tc.path)
				}
				if got.sharedPath == sharedJavaTypesLayered && !layersShareSimpleBuckets(got.lookup) {
					t.Fatalf("seed %d %s: fixture has no simple bucket in both layers", seed, tc.name)
				}
				if got.methods != want.methods {
					t.Errorf("seed %d %s round %d: methods = %d, want %d", seed, tc.name, round, got.methods, want.methods)
				}
				if !reflect.DeepEqual(mergedLayers(got.hierarchies), mergedLayers(want.hierarchies)) {
					t.Errorf("seed %d %s round %d: hierarchy differs", seed, tc.name, round)
				}
				if !reflect.DeepEqual(mergedLayers(got.externals), mergedLayers(want.externals)) {
					t.Errorf("seed %d %s round %d: external signatures differ", seed, tc.name, round)
				}
				if !reflect.DeepEqual(flatLookup(got.lookup), flatLookup(want.lookup)) {
					t.Errorf("seed %d %s round %d: method lookup differs", seed, tc.name, round)
				}
			}
		}
	}
}

func TestSharedJavaTypeIndex_GraphsMatchUnsharedResolution(t *testing.T) {
	f := newSharedIndexFixture(42)
	shared := NewSharedJavaTypeIndex()
	for _, jars := range [][]string{
		nil,
		{"/virtual/a.jar", "/virtual/b.jar"},
		{"/virtual/c.jar", "/virtual/a.jar"},
		{"/virtual/a.jar", "/virtual/d.jar"},
		{"/virtual/d.jar", "/virtual/a.jar"},
		{"/virtual/a.jar", "/virtual/b.jar"},
	} {
		wantGraph := f.newGraph()
		if err := f.resolver(nil).ResolveTypes(wantGraph, sharedIndexRoots(jars...)); err != nil {
			t.Fatal(err)
		}
		want := snapshotGraphTypes(wantGraph)
		for round := range 2 {
			gotGraph := f.newGraph()
			if err := f.resolver(shared).ResolveTypes(gotGraph, sharedIndexRoots(jars...)); err != nil {
				t.Fatal(err)
			}
			if got := snapshotGraphTypes(gotGraph); !reflect.DeepEqual(got, want) {
				t.Fatalf("jars %v round %d: graph differs from unshared resolution", jars, round)
			}
		}
	}
}

// A consumer appending to a graph's stored slices must not reach the shared
// index or another graph.
func TestSharedJavaTypeIndex_GraphAppendsDoNotLeak(t *testing.T) {
	f := newSharedIndexFixture(3)
	// A platform decoded from the on-disk cache, whose slices have spare
	// capacity as JSON decoding leaves them.
	var classes []*classFileInfo
	classes = append(classes, f.platform["/virtual/java.base.jmod"]...)
	classes = append(classes, f.platform["/virtual/java.other.jmod"]...)
	index, hierarchy := buildMethodIndexFromClassInfos(classes)
	for key, parents := range hierarchy {
		hierarchy[key] = append(make([]string, 0, len(parents)+2), parents...)
	}
	cache := newFakeBytecodeIndexCache()
	cache.entries[bytecodeCacheStorageKey("jdk-platform@21.0.1:jmods")] = &CachedBytecodeIndex{
		SchemaVersion: bytecodeCacheSchemaVersion,
		ArtifactKey:   "jdk-platform@21.0.1:jmods",
		MethodsIndex:  index,
		TypeHierarchy: hierarchy,
	}
	newResolver := func(shared *SharedJavaTypeIndex) *JavaBytecodeTypeResolver {
		r := f.resolver(shared)
		r.SetBytecodeIndexCache(cache)
		return r
	}
	shared := NewSharedJavaTypeIndex()
	first := f.newGraph()
	if err := newResolver(shared).ResolveTypes(first, nil); err != nil {
		t.Fatal(err)
	}
	for key, sigs := range first.ExternalMethodSignatures {
		first.ExternalMethodSignatures[key] = append(sigs, ExternalMethodSignature{ReturnType: "LEAK"})
	}
	for key, parents := range first.TypeHierarchy {
		first.TypeHierarchy[key] = append(parents, "LEAK")
	}
	second := f.newGraph()
	if err := newResolver(shared).ResolveTypes(second, nil); err != nil {
		t.Fatal(err)
	}
	want := f.newGraph()
	if err := newResolver(nil).ResolveTypes(want, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(snapshotGraphTypes(second), snapshotGraphTypes(want)) {
		t.Fatal("appends to one graph's products reached the next graph")
	}
	products := shared.platforms[func() string {
		for key := range shared.platforms {
			return key
		}
		return ""
	}()].platformProducts()
	for _, layer := range products.hierarchies {
		for key, parents := range layer {
			if full := parents[:cap(parents)]; len(full) > len(parents) && full[len(parents)] == "LEAK" {
				t.Fatalf("append wrote into the shared backing array of %s", key)
			}
		}
	}
	for _, layer := range products.externals {
		for key, sigs := range layer {
			if full := sigs[:cap(sigs)]; len(full) > len(sigs) && full[len(sigs)].ReturnType == "LEAK" {
				t.Fatalf("append wrote into the shared backing array of %s", key)
			}
		}
	}
}

func TestSharedJavaTypeIndex_ConcurrentGraphBuilds(t *testing.T) {
	f := newSharedIndexFixture(7)
	jarSets := [][]string{nil, {"/virtual/a.jar"}, {"/virtual/b.jar", "/virtual/a.jar"}, {"/virtual/c.jar"}}
	want := make([]graphTypeSnapshot, len(jarSets))
	for i, jars := range jarSets {
		graph := f.newGraph()
		if err := f.resolver(nil).ResolveTypes(graph, sharedIndexRoots(jars...)); err != nil {
			t.Fatal(err)
		}
		want[i] = snapshotGraphTypes(graph)
	}

	shared := NewSharedJavaTypeIndex()
	var wg sync.WaitGroup
	errs := make(chan string, 64)
	for worker := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jarSets {
				set := (i + worker) % len(jarSets)
				graph := f.newGraph()
				if err := f.resolver(shared).ResolveTypes(graph, sharedIndexRoots(jarSets[set]...)); err != nil {
					errs <- err.Error()
					return
				}
				// Consumers append to graph entries; this must stay private.
				for key, parents := range graph.TypeHierarchy {
					graph.TypeHierarchy[key] = append(parents, "mine")
				}
				graph.TypeHierarchy = nil
				graph2 := f.newGraph()
				if err := f.resolver(shared).ResolveTypes(graph2, sharedIndexRoots(jarSets[set]...)); err != nil {
					errs <- err.Error()
					return
				}
				if !reflect.DeepEqual(snapshotGraphTypes(graph2), want[set]) {
					errs <- fmt.Sprintf("worker %d jar set %d: graph differs", worker, set)
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for msg := range errs {
		t.Error(msg)
	}
}

func TestMergeJavaLookupBuckets_OrdersRunsByIndexKey(t *testing.T) {
	sig := func(class, method string, arity int) methodSignature {
		return methodSignature{fullClass: class, methodName: method, paramTypes: make([]string, arity)}
	}
	a := []methodSignature{sig("a.Foo", "m", 0), sig("a.Foo", "m", 1), sig("x.y.Foo", "m", 0)}
	b := []methodSignature{sig("a.Foo.b.Foo", "m", 2), sig("java.Foo", "m", 0), sig("java.Foo", "m", 1)}
	got := mergeJavaLookupBuckets(a, b)
	var keys []string
	for i := range got {
		keys = append(keys, fmt.Sprintf("%s.%s#%d", got[i].fullClass, got[i].methodName, len(got[i].paramTypes)))
	}
	// Sorted by "class.method", not by class: "a.Foo.b.Foo.m" < "a.Foo.m".
	want := []string{"a.Foo.b.Foo.m#2", "a.Foo.m#0", "a.Foo.m#1", "java.Foo.m#0", "java.Foo.m#1", "x.y.Foo.m#0"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("merged bucket = %v, want %v", keys, want)
	}
}
