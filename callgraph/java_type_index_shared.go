// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Paths a shared resolution takes, reported in the resolver's log.
const (
	sharedJavaTypesPlatformOnly = "platform_only"
	sharedJavaTypesLayered      = "layered"
	sharedJavaTypesFull         = "full"
)

// SharedJavaTypeIndex memoizes the Java platform's bytecode type index for
// every graph a process builds, so that building many graphs pays for the
// platform once. It holds the decoded platform index and the products derived
// from the platform alone, one copy per platform. It is safe for concurrent
// use; everything it hands out is read-only. Type JARs are still indexed per
// graph: they take milliseconds, and keeping each one would cost memory.
//
// A graph resolved through it gets the same products as a resolver without
// it would compute for the same type JARs and Java platform:
//   - With no type JAR, the graph reuses the platform's products.
//   - With type JARs whose classes are disjoint from the platform's, the
//     JAR layer is propagated, looked up and indexed over the platform's
//     products, and the lookup buckets both layers share are merged in the
//     order a single index would list them.
//   - Otherwise (a JAR redefines or is an ancestor of a platform class, as
//     xml-apis is) the full computation runs over the memoized platform
//     index.
type SharedJavaTypeIndex struct {
	mu        sync.Mutex
	platforms map[string]*sharedJavaPlatform
}

// NewSharedJavaTypeIndex returns an empty index.
func NewSharedJavaTypeIndex() *SharedJavaTypeIndex {
	return &SharedJavaTypeIndex{platforms: make(map[string]*sharedJavaPlatform)}
}

type sharedJavaPlatform struct {
	once      sync.Once
	index     map[string][]methodSignature
	hierarchy map[string][]string
	err       error

	productsOnce sync.Once
	products     *javaTypeProducts

	layerOnce sync.Once
	layerable bool
	// names holds every class the platform declares, or names as a parent.
	names map[string]struct{}
	// effective groups the propagated platform index by type.
	effective map[string]map[string][]methodSignature
}

func (s *SharedJavaTypeIndex) resolve(
	r *JavaBytecodeTypeResolver,
	tasks []jarTask,
	workers int,
	platformSource *javaPlatformIndexSource,
	platformMeta *JavaPlatformSignatureMetadata,
) (*javaTypeProducts, javaBytecodeIndexStats) {
	jarIndex, jarHierarchy, stats := r.buildIndexes(tasks, workers)

	platform := s.platform(r, platformSource)
	if platform != nil {
		if platform.err != nil {
			if platformMeta.UnavailableReason == "" {
				platformMeta.UnavailableReason = "platform_index_failed"
			}
			log.Debug().Err(platform.err).Str("source", platformSource.SignatureSource).Msg("Failed to index Java platform signatures")
			platform = nil
		} else {
			platformMeta.SignaturesUsed = true
		}
	}

	if platform == nil {
		products := buildJavaTypeProducts(jarIndex, jarHierarchy)
		products.sharedPath = sharedJavaTypesFull
		return products, stats
	}
	if len(jarIndex) == 0 && len(jarHierarchy) == 0 {
		// A copy, so the log reports no derivation time for a reuse.
		products := *platform.platformProducts()
		products.inheritanceDuration, products.lookupBuildDuration, products.externalBuildDuration = 0, 0, 0
		return &products, stats
	}
	if products, ok := platform.layer(jarIndex, jarHierarchy); ok {
		return products, stats
	}

	mergeMethodIndex(jarIndex, platform.index)
	mergeTypeHierarchy(jarHierarchy, platform.hierarchy)
	products := buildJavaTypeProducts(jarIndex, jarHierarchy)
	products.sharedPath = sharedJavaTypesFull
	return products, stats
}

// platform returns the decoded Java platform index of source, decoding it at
// most once per process, or nil when the source has no archives.
func (s *SharedJavaTypeIndex) platform(r *JavaBytecodeTypeResolver, source *javaPlatformIndexSource) *sharedJavaPlatform {
	if source == nil || len(source.ArchivePaths) == 0 {
		return nil
	}
	key := source.ArtifactKey + "\x00" + source.SignatureSource + "\x00" + strings.Join(source.ArchivePaths, "\x00")
	s.mu.Lock()
	entry := s.platforms[key]
	if entry == nil {
		entry = &sharedJavaPlatform{}
		s.platforms[key] = entry
	}
	s.mu.Unlock()

	entry.once.Do(func() {
		start := time.Now()
		entry.index, entry.hierarchy, entry.err = r.indexPlatformSource(source)
		log.Info().
			Str("signature_source", source.SignatureSource).
			Int("archives", len(source.ArchivePaths)).
			Int("methods", len(entry.index)).
			Int("types", len(entry.hierarchy)).
			Dur("duration", time.Since(start)).
			Msg("Shared Java platform index loaded")
	})
	return entry
}

// platformProducts returns the products of the platform alone, which are
// also the products of any graph with no type JAR.
func (p *sharedJavaPlatform) platformProducts() *javaTypeProducts {
	p.productsOnce.Do(func() {
		index := make(map[string][]methodSignature, len(p.index))
		for key, sigs := range p.index {
			index[key] = sigs
		}
		p.products = buildJavaTypeProducts(index, p.hierarchy)
		p.products.sharedPath = sharedJavaTypesPlatformOnly
	})
	return p.products
}

func (p *sharedJavaPlatform) prepareLayering() {
	p.layerOnce.Do(func() {
		products := p.platformProducts()
		if products.lookup == nil || !javaHierarchyAcyclic(p.hierarchy) {
			return
		}
		index := products.lookup.qualified
		if !javaIndexKeysMatchSignatures(index) {
			return
		}
		names := make(map[string]struct{}, len(p.hierarchy)*2)
		for key := range index {
			names[key[:strings.LastIndex(key, ".")]] = struct{}{}
		}
		for className, parents := range p.hierarchy {
			names[className] = struct{}{}
			for _, parent := range parents {
				names[parent] = struct{}{}
			}
		}
		p.names = names
		p.effective = groupMethodIndexByType(index)
		p.layerable = true
	})
}

// layer computes the products of the platform plus a JAR layer from the
// platform's products, or reports false when the result could differ from
// the full computation. It leaves its arguments unchanged.
func (p *sharedJavaPlatform) layer(jarIndex map[string][]methodSignature, jarHierarchy map[string][]string) (*javaTypeProducts, bool) {
	p.prepareLayering()
	if !p.layerable || !javaIndexKeysMatchSignatures(jarIndex) {
		return nil, false
	}
	jarNames := make(map[string]struct{}, len(jarIndex)+len(jarHierarchy))
	for key := range jarIndex {
		jarNames[key[:strings.LastIndex(key, ".")]] = struct{}{}
	}
	for className := range jarHierarchy {
		jarNames[className] = struct{}{}
	}
	for name := range jarNames {
		if _, ok := p.names[name]; ok {
			log.Debug().Str("class", name).Msg("A type JAR shares a class with the Java platform; resolving the full type index")
			return nil, false
		}
	}

	base := p.platformProducts()
	products := &javaTypeProducts{sharedPath: sharedJavaTypesLayered}
	// Propagation only adds keys, so a shallow copy keeps jarIndex intact
	// for the full computation if layering gives up below.
	jarIndex = maps.Clone(jarIndex)

	inheritanceStart := time.Now()
	propagateInheritedMethodsOver(jarIndex, jarHierarchy, func(typeName string) (map[string][]methodSignature, bool) {
		if _, ok := jarNames[typeName]; ok {
			return nil, false
		}
		return p.effective[typeName], true
	})
	products.inheritanceDuration = time.Since(inheritanceStart)

	externalStart := time.Now()
	jarExternal := buildExternalMethodSignatureIndex(jarIndex)
	platformExternal := base.externals[0]
	for key := range jarExternal {
		if _, ok := platformExternal[key]; ok {
			return nil, false
		}
	}
	products.externalBuildDuration = time.Since(externalStart)

	lookupStart := time.Now()
	lookup := buildJavaMethodLookup(jarIndex)
	for key, sigs := range lookup.simple {
		if baseSigs, ok := base.lookup.simple[key]; ok {
			lookup.simple[key] = mergeJavaLookupBuckets(sigs, baseSigs)
		}
	}
	for key, sigs := range lookup.simpleArity {
		if baseSigs, ok := base.lookup.simpleArity[key]; ok {
			lookup.simpleArity[key] = mergeJavaLookupBuckets(sigs, baseSigs)
		}
	}
	lookup.base = base.lookup
	products.lookupBuildDuration = time.Since(lookupStart)

	products.lookup = lookup
	products.methods = len(jarIndex) + base.methods
	products.hierarchies = []map[string][]string{p.hierarchy, jarHierarchy}
	products.externals = []map[string][]ExternalMethodSignature{platformExternal, jarExternal}
	return products, true
}

// javaIndexKeysMatchSignatures reports whether every signature of the index
// sits under the key of its own class and method. Lookup buckets list the
// signatures of each key in a run, so a run's key can then be read off its
// first signature.
func javaIndexKeysMatchSignatures(index map[string][]methodSignature) bool {
	for key, sigs := range index {
		dot := strings.LastIndex(key, ".")
		if dot <= 0 || dot == len(key)-1 {
			return false
		}
		for i := range sigs {
			if sigs[i].fullClass != key[:dot] || sigs[i].methodName != key[dot+1:] {
				return false
			}
		}
	}
	return true
}

// mergeJavaLookupBuckets merges two lookup buckets of disjoint index keys,
// each listing its keys' signatures in sorted key order, into the bucket a
// lookup over both indexes would hold.
func mergeJavaLookupBuckets(a, b []methodSignature) []methodSignature {
	out := make([]methodSignature, 0, len(a)+len(b))
	for len(a) > 0 && len(b) > 0 {
		if javaSignatureKey(&a[0]) < javaSignatureKey(&b[0]) {
			n := javaSignatureRun(a)
			out, a = append(out, a[:n]...), a[n:]
		} else {
			n := javaSignatureRun(b)
			out, b = append(out, b[:n]...), b[n:]
		}
	}
	out = append(out, a...)
	return append(out, b...)
}

func javaSignatureKey(sig *methodSignature) string {
	return sig.fullClass + "." + sig.methodName
}

// javaSignatureRun is the length of the leading run of signatures that share
// the first one's index key.
func javaSignatureRun(sigs []methodSignature) int {
	n := 1
	for n < len(sigs) && sigs[n].fullClass == sigs[0].fullClass && sigs[n].methodName == sigs[0].methodName {
		n++
	}
	return n
}

// javaHierarchyAcyclic reports whether no type is its own ancestor. Method
// propagation over a cyclic hierarchy depends on map iteration order, so no
// layered result can be shown equal to it.
func javaHierarchyAcyclic(hierarchy map[string][]string) bool {
	const (
		unvisited = iota
		active
		done
	)
	state := make(map[string]int, len(hierarchy))
	var visit func(string) bool
	visit = func(typeName string) bool {
		switch state[typeName] {
		case active:
			return false
		case done:
			return true
		}
		state[typeName] = active
		for _, parent := range hierarchy[typeName] {
			if !visit(parent) {
				return false
			}
		}
		state[typeName] = done
		return true
	}
	for typeName := range hierarchy {
		if !visit(typeName) {
			return false
		}
	}
	return true
}
