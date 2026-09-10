// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package transpiler

import "sync"

// RenderCache memoizes the result of rendering each input against each set of vars across calls
// to RenderInputsCached.
//
// An entry is keyed by the position of the input in the inputs list and the cache key of the
// vars set (see Vars.SetCacheKey), so the cache must be Reset whenever the inputs change. Entries
// that are not used by a call are dropped at the end of it, which keeps the cache bounded to the
// live set of (input, vars) pairs. Inputs that reference a fetch context provider are never cached
// as their values are resolved at lookup time.
type RenderCache struct {
	mu      sync.Mutex
	entries map[renderKey]*renderEntry
	// providers holds the provider names referenced by each input, by input position.
	providers map[int]map[string]struct{}
}

type renderKey struct {
	input   int
	varsKey string
}

type renderEntry struct {
	// rendered is nil when the input was removed by an unresolved variable or a false condition.
	rendered *Dict
	// mapped is the native form of rendered, computed on first use. It is shared with every
	// caller and must be treated as read-only.
	mapped map[string]interface{}
	// hash is the hash of the rendered input before the id and processors were finalized. It
	// is used to deduplicate identical renders produced by different vars sets.
	hash uint64
	// id is the final id of the rendered input, only set when rendered with a dynamic vars set.
	id string
	// providerVars are the variables of the dynamic provider resolved while rendering.
	providerVars []string
	used         bool
}

// NewRenderCache creates an empty RenderCache.
func NewRenderCache() *RenderCache {
	return &RenderCache{
		entries:   make(map[renderKey]*renderEntry),
		providers: make(map[int]map[string]struct{}),
	}
}

// Reset drops every entry. It must be called when the inputs being rendered change.
func (c *RenderCache) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[renderKey]*renderEntry)
	c.providers = make(map[int]map[string]struct{})
}

// Len returns the number of entries in the cache.
func (c *RenderCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

func (c *RenderCache) get(key renderKey) *renderEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if ok {
		entry.used = true
	}
	return entry
}

func (c *RenderCache) put(key renderKey, entry *renderEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry.used = true
	c.entries[key] = entry
}

// sweep drops the entries that were not used since the previous sweep.
func (c *RenderCache) sweep() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if !entry.used {
			delete(c.entries, key)
			continue
		}
		entry.used = false
	}
}

// inputProviders returns the names of the providers referenced by the input at the given
// position, computing and remembering them on first use.
func (c *RenderCache) inputProviders(idx int, dict *Dict, defaultProvider string) map[string]struct{} {
	c.mu.Lock()
	providers, ok := c.providers[idx]
	c.mu.Unlock()
	if ok {
		return providers
	}
	providers = referencedProviders(dict, defaultProvider)
	c.mu.Lock()
	c.providers[idx] = providers
	c.mu.Unlock()
	return providers
}
