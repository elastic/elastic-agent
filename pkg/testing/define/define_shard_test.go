// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package define

import (
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseShard(t *testing.T) {
	cases := []struct {
		in      string
		want    Shard
		wantErr bool
	}{
		{in: "", want: Shard{}},
		{in: "0/1", want: Shard{Index: 0, Count: 1}},
		{in: "0/2", want: Shard{Index: 0, Count: 2}},
		{in: "1/2", want: Shard{Index: 1, Count: 2}},
		{in: "2/2", wantErr: true},
		{in: "-1/2", wantErr: true},
		{in: "0/0", wantErr: true},
		{in: "1", wantErr: true},
		{in: "a/2", wantErr: true},
		{in: "0/b", wantErr: true},
		{in: "0of2", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			got, err := ParseShard(tc.in)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, tc.in, got.String())
		})
	}
}

func TestShardContains(t *testing.T) {
	names := []string{
		"TestEnrollReplaceToken", "TestInstallSecondAgentInDevelopmentNamespace",
		"TestClassicAndReceiverAgentMonitoring", "TestReEnrollUnprivileged",
		"TestMonitoringNoDuplicates", "TestAgentInfoInEventsStandalone",
		"TestInstallUninstallAudit", "TestAgentMetricsInput", "TestComponentWorkDir",
		"TestBeatsReceiverLogs", "TestKubernetesAgentHelm", "TestOtelKubeStackHelm",
	}

	t.Run("zero shard selects everything", func(t *testing.T) {
		for _, n := range names {
			assert.True(t, Shard{}.Contains(n), n)
		}
	})

	t.Run("count of one selects everything", func(t *testing.T) {
		for _, n := range names {
			assert.True(t, Shard{Index: 0, Count: 1}.Contains(n), n)
		}
	})

	for count := 2; count <= 5; count++ {
		t.Run(fmt.Sprintf("every test is in exactly one of %d shards", count), func(t *testing.T) {
			for _, n := range names {
				hits := 0
				for i := 0; i < count; i++ {
					if (Shard{Index: i, Count: count}).Contains(n) {
						hits++
					}
				}
				assert.Equal(t, 1, hits, n)
			}
		})
	}

	t.Run("two shards both get tests", func(t *testing.T) {
		var counts [2]int
		for _, n := range names {
			counts[shardOf(n, 2)]++
		}
		assert.NotZero(t, counts[0])
		assert.NotZero(t, counts[1])
	})

	t.Run("subtests follow their top-level test", func(t *testing.T) {
		for _, n := range names {
			assert.Equal(t, shardOf(n, 3), shardOf(n+"/some_subtest", 3), n)
			assert.Equal(t, shardOf(n, 3), shardOf(n+"/a/b", 3), n)
		}
	})

	t.Run("assignment is stable", func(t *testing.T) {
		// Pinned values: a change here moves tests between CI jobs.
		assert.Equal(t, 0, shardOf("TestEnrollReplaceToken", 2))
		assert.Equal(t, 1, shardOf("TestInstallSecondAgentInDevelopmentNamespace", 2))
		assert.Equal(t, 0, shardOf("TestKubernetesAgentHelm", 2))
		assert.Equal(t, 1, shardOf("TestOtelKubeStackHelm", 2))
	})
}

func TestShardFlag(t *testing.T) {
	var f shardFlag
	assert.False(t, f.set)
	assert.Equal(t, "", f.String())

	require.NoError(t, f.Set("1/3"))
	assert.True(t, f.set)
	assert.Equal(t, Shard{Index: 1, Count: 3}, f.shard)
	assert.Equal(t, "1/3", f.String())

	require.Error(t, f.Set("3/3"))
}

func TestActiveShard(t *testing.T) {
	resetEnvShard := func() {
		envShardOnce = sync.Once{}
		envShard = Shard{}
		envShardErr = nil
	}

	t.Run("flag wins over the environment", func(t *testing.T) {
		t.Setenv(ShardEnvVar, "0/4")
		resetEnvShard()
		ShardFilter = shardFlag{}
		t.Cleanup(func() { ShardFilter = shardFlag{} })
		require.NoError(t, ShardFilter.Set("1/2"))

		shard, sharded, err := activeShard()
		require.NoError(t, err)
		assert.True(t, sharded)
		assert.Equal(t, Shard{Index: 1, Count: 2}, shard)
	})

	t.Run("environment is the fallback", func(t *testing.T) {
		t.Setenv(ShardEnvVar, "2/3")
		resetEnvShard()
		ShardFilter = shardFlag{}

		shard, sharded, err := activeShard()
		require.NoError(t, err)
		assert.True(t, sharded)
		assert.Equal(t, Shard{Index: 2, Count: 3}, shard)
	})

	t.Run("unset means no sharding", func(t *testing.T) {
		t.Setenv(ShardEnvVar, "")
		resetEnvShard()
		ShardFilter = shardFlag{}

		_, sharded, err := activeShard()
		require.NoError(t, err)
		assert.False(t, sharded)
	})

	t.Run("invalid environment value is an error", func(t *testing.T) {
		t.Setenv(ShardEnvVar, "0of2")
		resetEnvShard()
		ShardFilter = shardFlag{}

		_, _, err := activeShard()
		require.Error(t, err)
	})
}
