// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package component

import (
	"encoding/base64"
	"math"

	"github.com/cespare/xxhash/v2"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
)

// ExpectedConfigCache reuses the proto.UnitExpectedConfig generated for a unit configuration
// across component model refreshes.
//
// Generating the expected configuration converts the whole configuration into a protobuf
// structure, which dominates the cost of a refresh when most of the configuration is unchanged
// (for example when a single pod starts or stops). Entries are looked up by a hash of the
// configuration and then verified against the source of the stored result, so a hit always
// corresponds to a configuration with an identical source. Numbers are compared as the float64
// they are converted to in the source, as structpb does, so integers beyond 2^53 that convert to
// the same float64 are considered identical. Entries not used since the previous Sweep are
// dropped by it, keeping the cache bounded to the live set of units.
//
// The generated proto.UnitExpectedConfig is shared with every caller and must be treated as
// read-only, which is already the case everywhere it is used.
type ExpectedConfigCache struct {
	entries map[uint64][]*expectedConfigEntry
}

type expectedConfigEntry struct {
	result *proto.UnitExpectedConfig
	used   bool
}

// NewExpectedConfigCache creates an empty ExpectedConfigCache.
func NewExpectedConfigCache() *ExpectedConfigCache {
	return &ExpectedConfigCache{entries: make(map[uint64][]*expectedConfigEntry)}
}

// ExpectedConfig returns the proto.UnitExpectedConfig for the configuration, reusing a previously
// generated one when the configuration is identical. A nil cache generates it every time.
func (c *ExpectedConfigCache) ExpectedConfig(cfg map[string]interface{}) (*proto.UnitExpectedConfig, error) {
	if c == nil {
		return ExpectedConfig(cfg)
	}
	hash := hashConfigValue(cfg)
	for _, entry := range c.entries[hash] {
		if structEqualsMap(entry.result.GetSource(), cfg) {
			entry.used = true
			return entry.result, nil
		}
	}
	result, err := ExpectedConfig(cfg)
	if err != nil {
		return nil, err
	}
	if c.entries == nil {
		c.entries = make(map[uint64][]*expectedConfigEntry)
	}
	c.entries[hash] = append(c.entries[hash], &expectedConfigEntry{result: result, used: true})
	return result, nil
}

// Sweep drops the entries that were not used since the previous Sweep.
func (c *ExpectedConfigCache) Sweep() {
	if c == nil {
		return
	}
	for hash, entries := range c.entries {
		kept := entries[:0]
		for _, entry := range entries {
			if entry.used {
				entry.used = false
				kept = append(kept, entry)
			}
		}
		if len(kept) == 0 {
			delete(c.entries, hash)
			continue
		}
		c.entries[hash] = kept
	}
}

// Len returns the number of entries in the cache.
func (c *ExpectedConfigCache) Len() int {
	if c == nil {
		return 0
	}
	n := 0
	for _, entries := range c.entries {
		n += len(entries)
	}
	return n
}

// hashConfigValue hashes a configuration value. The hash of a map doesn't depend on the order
// of its keys, so no sorting (and no allocation) is needed.
func hashConfigValue(v interface{}) uint64 {
	const (
		tagNil    = 0x1
		tagBool   = 0x2
		tagNumber = 0x3
		tagString = 0x4
		tagMap    = 0x5
		tagList   = 0x6
	)
	switch t := v.(type) {
	case nil:
		return mix64(tagNil)
	case bool:
		if t {
			return mix64(tagBool | 1<<8)
		}
		return mix64(tagBool)
	case string:
		return mix64(tagString ^ xxhash.Sum64String(t))
	case []byte:
		return mix64(tagString ^ xxhash.Sum64(t))
	case map[string]interface{}:
		// commutative combination so key order doesn't matter
		var sum uint64
		for k, val := range t {
			sum += mix64(xxhash.Sum64String(k) ^ rotl64(hashConfigValue(val), 29))
		}
		return mix64(tagMap ^ sum ^ uint64(len(t))<<8)
	case []interface{}:
		h := tagList ^ uint64(len(t))<<8
		for _, e := range t {
			h = mix64(h ^ hashConfigValue(e))
		}
		return mix64(h)
	default:
		if f, ok := numberValue(v); ok {
			return mix64(tagNumber ^ math.Float64bits(f))
		}
		// unsupported type; the value is rejected when generating the config anyway
		return mix64(0xff)
	}
}

// mix64 is the splitmix64 finalizer.
func mix64(x uint64) uint64 {
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func rotl64(x uint64, k uint) uint64 {
	return x<<k | x>>(64-k)
}

// structEqualsMap returns true when the structpb.Struct is exactly what the map converts to.
func structEqualsMap(s *structpb.Struct, m map[string]interface{}) bool {
	if s == nil {
		return false
	}
	fields := s.GetFields()
	if len(fields) != len(m) {
		return false
	}
	for k, v := range m {
		fv, ok := fields[k]
		if !ok || !valueEqualsInterface(fv, v) {
			return false
		}
	}
	return true
}

// valueEqualsInterface returns true when the structpb.Value is exactly what the value converts to.
func valueEqualsInterface(pv *structpb.Value, v interface{}) bool {
	if pv == nil {
		return false
	}
	switch t := v.(type) {
	case nil:
		_, ok := pv.GetKind().(*structpb.Value_NullValue)
		return ok
	case bool:
		b, ok := pv.GetKind().(*structpb.Value_BoolValue)
		return ok && b.BoolValue == t
	case string:
		s, ok := pv.GetKind().(*structpb.Value_StringValue)
		return ok && s.StringValue == t
	case []byte:
		s, ok := pv.GetKind().(*structpb.Value_StringValue)
		return ok && s.StringValue == base64.StdEncoding.EncodeToString(t)
	case map[string]interface{}:
		s, ok := pv.GetKind().(*structpb.Value_StructValue)
		return ok && structEqualsMap(s.StructValue, t)
	case []interface{}:
		l, ok := pv.GetKind().(*structpb.Value_ListValue)
		if !ok {
			return false
		}
		values := l.ListValue.GetValues()
		if len(values) != len(t) {
			return false
		}
		for i, e := range t {
			if !valueEqualsInterface(values[i], e) {
				return false
			}
		}
		return true
	default:
		f, ok := numberValue(v)
		if !ok {
			return false
		}
		n, ok := pv.GetKind().(*structpb.Value_NumberValue)
		return ok && n.NumberValue == f
	}
}
