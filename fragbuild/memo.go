// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import (
	"hash/maphash"
	"sync"
)

const memoShards = 64

// Memo memoizes a pure function of a string key. The forks of an export
// context that build edges concurrently share their memos, so a lookup or a
// store locks only the shard of its key. A nil Memo memoizes nothing.
type Memo[V any] struct {
	seed   maphash.Seed
	shards [memoShards]memoShard[V]
}

type memoShard[V any] struct {
	mu     sync.Mutex
	values map[string]V
}

// NewMemo returns an empty Memo.
func NewMemo[V any]() *Memo[V] {
	return &Memo[V]{seed: maphash.MakeSeed()}
}

func (m *Memo[V]) shard(key string) *memoShard[V] {
	return &m.shards[maphash.String(m.seed, key)%memoShards]
}

// Lookup returns the value memoized for key.
func (m *Memo[V]) Lookup(key string) (V, bool) {
	if m == nil {
		var zero V
		return zero, false
	}
	s := m.shard(key)
	s.mu.Lock()
	value, ok := s.values[key]
	s.mu.Unlock()
	return value, ok
}

// Store memoizes value for key and returns the value memoized for key: value,
// or the one another goroutine stored first, which is equal since the
// memoized function is pure.
func (m *Memo[V]) Store(key string, value V) V {
	if m == nil {
		return value
	}
	s := m.shard(key)
	s.mu.Lock()
	defer s.mu.Unlock()
	if stored, ok := s.values[key]; ok {
		return stored
	}
	if s.values == nil {
		s.values = make(map[string]V)
	}
	s.values[key] = value
	return value
}
