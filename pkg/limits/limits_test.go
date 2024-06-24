// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package limits

import (
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/config"
)

func TestApply(t *testing.T) {
	cpuCount := runtime.NumCPU()
	cases := []struct {
		name                string
		c                   *config.Config
		expGoMaxProcsStored int
		expGoMaxProcsReal   int
	}{
		{
			name:                "does not set GOMAXPROCS if there is no section",
			c:                   config.MustNewConfigFrom(``),
			expGoMaxProcsStored: 0,
			expGoMaxProcsReal:   cpuCount,
		},
		{
			name:                "does not set GOMAXPROCS if there is no limits",
			c:                   config.MustNewConfigFrom(`agent.limits:`),
			expGoMaxProcsStored: 0,
			expGoMaxProcsReal:   cpuCount,
		},
		{
			name:                "sets GOMAXPROCS if set in the config",
			c:                   config.MustNewConfigFrom(`agent.limits.go_max_procs: 99`),
			expGoMaxProcsStored: 99,
			expGoMaxProcsReal:   99,
		},
		{
			name:                "resets GOMAXPROCS if there is no value",
			c:                   config.MustNewConfigFrom(``),
			expGoMaxProcsStored: 0,
			expGoMaxProcsReal:   cpuCount,
		},
	}

	_ = runtime.GOMAXPROCS(cpuCount) // reset before the tests in case changed elsewhere

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {

			err := Apply(tc.c)
			require.NoError(t, err)
			require.Equal(t, tc.expGoMaxProcsStored, GoMaxProcs(), "stored value should be valid")
			require.Equal(t, tc.expGoMaxProcsReal, runtime.GOMAXPROCS(0), "actual runtime value should be valid")
		})
	}
}

func TestAddLimitsOnChangeCallback(t *testing.T) {
	id := "test-id"
	called := false

	t.Run("triggers added callback on setting a new value", func(t *testing.T) {
		called = false
		AddLimitsOnChangeCallback(func(new, old LimitsConfig) {
			require.Equal(t, 0, old.GoMaxProcs)
			require.Equal(t, 99, new.GoMaxProcs)
			called = true
		}, id)
		err := Apply(config.MustNewConfigFrom(`agent.limits.go_max_procs: 99`))
		require.NoError(t, err)
		require.True(t, called, "callback must be called")
	})

	t.Run("triggers added callback on resetting the value", func(t *testing.T) {
		called = false
		AddLimitsOnChangeCallback(func(new, old LimitsConfig) {
			require.Equal(t, 99, old.GoMaxProcs)
			require.Equal(t, 0, new.GoMaxProcs)
			called = true
		}, id)
		err := Apply(config.MustNewConfigFrom(`agent.limits.go_max_procs: 0`))
		require.NoError(t, err)
		require.True(t, called, "callback must be called")
	})

	t.Run("does not trigger removed callback", func(t *testing.T) {
		called = false
		RemoveLimitsOnChangeCallback(id)
		err := Apply(config.MustNewConfigFrom(`agent.limits.go_max_procs: 99`))
		require.NoError(t, err)
		require.False(t, called, "callback must not be called")
	})
}
