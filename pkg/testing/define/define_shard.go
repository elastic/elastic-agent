// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package define

import (
	"fmt"
	"hash/fnv"
	"os"
	"strconv"
	"strings"
	"sync"
)

// ShardEnvVar is the environment variable read when the shard flag is not set.
// It exists for runners that cannot pass test binary flags through (the
// integration test runner only forwards -test.* flags via GOTEST_FLAGS).
const ShardEnvVar = "TEST_SHARD"

// shardSeed is mixed into the test name hash. It was picked so that the groups
// sharded in CI (default sudo on Linux and Windows, kubernetes wolfi) split
// into halves of similar duration as of October 2026. Changing it moves tests
// between shards, which is harmless but shows up as a one-off change in the
// per-shard durations.
const shardSeed = "shard-seed-136"

// Shard selects one slice of a test group: the tests whose stable hash falls
// into slice Index of Count. A zero Shard selects every test.
type Shard struct {
	Index int
	Count int
}

// ParseShard parses "<index>/<count>", with 0 <= index < count.
// The empty string parses to the zero Shard (no sharding).
func ParseShard(s string) (Shard, error) {
	if s == "" {
		return Shard{}, nil
	}
	idxStr, countStr, ok := strings.Cut(s, "/")
	if !ok {
		return Shard{}, fmt.Errorf("invalid shard %q: expected <index>/<count>", s)
	}
	idx, err := strconv.Atoi(idxStr)
	if err != nil {
		return Shard{}, fmt.Errorf("invalid shard %q: index: %w", s, err)
	}
	count, err := strconv.Atoi(countStr)
	if err != nil {
		return Shard{}, fmt.Errorf("invalid shard %q: count: %w", s, err)
	}
	if count < 1 {
		return Shard{}, fmt.Errorf("invalid shard %q: count must be at least 1", s)
	}
	if idx < 0 || idx >= count {
		return Shard{}, fmt.Errorf("invalid shard %q: index must be in [0, %d)", s, count)
	}
	return Shard{Index: idx, Count: count}, nil
}

// Enabled reports whether the shard restricts the set of tests.
func (s Shard) Enabled() bool {
	return s.Count > 1
}

func (s Shard) String() string {
	if s.Count == 0 {
		return ""
	}
	return fmt.Sprintf("%d/%d", s.Index, s.Count)
}

// Contains reports whether the test belongs to this shard. Subtests follow
// their top-level test: only the part of the name before the first "/" is
// hashed, so a define.Require inside a subtest stays with its parent.
func (s Shard) Contains(testName string) bool {
	if !s.Enabled() {
		return true
	}
	return shardOf(testName, s.Count) == s.Index
}

// shardOf assigns a test to one of count shards by a stable hash of its
// top-level name. The assignment depends only on the name, so every shard of
// a run agrees on the split without coordinating.
func shardOf(testName string, count int) int {
	if top, _, ok := strings.Cut(testName, "/"); ok {
		testName = top
	}
	h := fnv.New64a()
	_, _ = h.Write([]byte(shardSeed))
	_, _ = h.Write([]byte(testName))
	x := h.Sum64()
	// Murmur3 fmix64 finalizer. The low bits of FNV-1a alone are just the
	// parity of the input bytes, so x % 2 would put all tests in one shard.
	x ^= x >> 33
	x *= 0xff51afd7ed558ccd
	x ^= x >> 33
	x *= 0xc4ceb9fe1a85ec53
	x ^= x >> 33
	return int(x % uint64(count)) //nolint:gosec // G115: count is a small positive int, the modulo fits.
}

// shardFlag is the flag.Value behind -integration.shard.
type shardFlag struct {
	shard Shard
	set   bool
}

func (f *shardFlag) String() string {
	return f.shard.String()
}

func (f *shardFlag) Set(s string) error {
	shard, err := ParseShard(s)
	if err != nil {
		return err
	}
	f.shard = shard
	f.set = true
	return nil
}

var (
	envShardOnce sync.Once
	envShard     Shard
	envShardErr  error
)

// activeShard returns the shard the tests run in: the -integration.shard flag
// if given, otherwise the TEST_SHARD environment variable. The second value is
// false when no sharding is configured. An unparsable value is an error, not a
// silent full run, so a CI misconfiguration cannot double-run or skip tests.
func activeShard() (Shard, bool, error) {
	if ShardFilter.set {
		return ShardFilter.shard, ShardFilter.shard.Enabled(), nil
	}
	envShardOnce.Do(func() {
		envShard, envShardErr = ParseShard(os.Getenv(ShardEnvVar))
	})
	if envShardErr != nil {
		return Shard{}, false, fmt.Errorf("%s: %w", ShardEnvVar, envShardErr)
	}
	return envShard, envShard.Enabled(), nil
}
