// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetessecrets

import (
	"sync"
	"time"
)

// expirationCache is a store that expires items after time.Now - secret.lastAccess > ttl (if ttl > 0) at Get or List.
// expirationCache works with *cacheEntry, a pointer struct that wraps secret, instead of secret directly because map
// structure in standard go library never removes the buckets from memory even after removing all the elements from it.
// However, since *cacheEntry is a pointer it can be garbage collected when no longer referenced by the GC, such as
// when deleted from the map. More importantly working with a pointer makes the entry in the map bucket, that doesn't
// get deallocated, to utilise only 8 bytes on a 64-bit system.
type expirationCache struct {
	sync.Mutex
	// ttl is the time-to-live for items in the cache
	ttl time.Duration
	// items is the underlying cache store.
	items map[string]*cacheEntry
}

type cacheEntry struct {
	s          secret
	lastAccess time.Time
}

// Get returns the secret associated with the given key from the store if it exists and is not expired. If updateAccess is true
// and the secret exists, essentially the expiration check is skipped and the lastAccess timestamp is updated to time.Now().
func (c *expirationCache) Get(key string, updateAccess bool) (secret, bool) {
	c.Lock()
	defer c.Unlock()

	entry, exists := c.items[key]
	if !exists {
		return secret{}, false
	}
	if updateAccess {
		entry.lastAccess = time.Now()
	} else if c.isExpired(entry.lastAccess) {
		delete(c.items, key)
		return secret{}, false
	}

	return entry.s, true
}

// AddConditionally adds the given secret to the store if the given condition returns true. If there is no existing
// secret, the condition will be called with an empty secret and false. If updateAccess is true and the secret already exists,
// then the lastAccess timestamp is updated to time.Now() independently of the condition result.
func (c *expirationCache) AddConditionally(key string, in secret, updateAccess bool, condition conditionFn) {
	c.Lock()
	defer c.Unlock()
	entry, exists := c.items[key]
	if !exists {
		if condition != nil && condition(secret{}, false) {
			c.items[key] = &cacheEntry{in, time.Now()}
		}
		return
	}

	if condition != nil && condition(entry.s, true) {
		entry.s = in
		entry.lastAccess = time.Now()
	} else if updateAccess {
		entry.lastAccess = time.Now()
	}
}

// isExpired returns true if the item has expired based on the ttl
func (c *expirationCache) isExpired(lastAccess time.Time) bool {
	if c.ttl <= 0 {
		// no expiration
		return false
	}
	// we expire if the last access is older than the ttl
	return time.Since(lastAccess) > c.ttl
}

// ListKeys returns a list of all the keys of the secrets in the store without checking for expiration
func (c *expirationCache) ListKeys() []string {
	c.Lock()
	defer c.Unlock()

	length := len(c.items)
	if length == 0 {
		return nil
	}
	list := make([]string, 0, length)
	for key := range c.items {
		list = append(list, key)
	}
	return list
}

// List returns a list of all the secrets in the store that are not expired
func (c *expirationCache) List() []secret {
	c.Lock()
	defer c.Unlock()

	length := len(c.items)
	if length == 0 {
		return nil
	}
	list := make([]secret, 0, length)
	for _, entry := range c.items {
		if c.isExpired(entry.lastAccess) {
			continue
		}
		list = append(list, entry.s)
	}
	return list
}

// newExpirationCache creates and returns an expirationCache
func newExpirationCache(ttl time.Duration) *expirationCache {
	return &expirationCache{
		items: make(map[string]*cacheEntry),
		ttl:   ttl,
	}
}
