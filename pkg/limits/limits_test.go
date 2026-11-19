// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

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

// restoreLimits restores the global limits and the runtime GOMAXPROCS value when the test ends.
func restoreLimits(t *testing.T) {
	current.mu.RLock()
	prevCfg := current.cfg
	current.mu.RUnlock()
	prevGoMaxProcs := runtime.GOMAXPROCS(0)
	t.Cleanup(func() {
		current.mu.Lock()
		current.cfg = prevCfg
		current.mu.Unlock()
		runtime.GOMAXPROCS(prevGoMaxProcs)
	})
}

func TestApplyCPU(t *testing.T) {
	t.Run("a change of only the CPU limit does not change GOMAXPROCS", func(t *testing.T) {
		restoreLimits(t)
		require.NoError(t, Apply(config.MustNewConfigFrom(`agent.limits.go_max_procs: 2`)))
		// A different runtime value shows that Apply does not set it again.
		runtime.GOMAXPROCS(3)

		called := false
		AddLimitsOnChangeCallback(func(new, old LimitsConfig) { called = true }, "cpu-test")
		t.Cleanup(func() { RemoveLimitsOnChangeCallback("cpu-test") })

		require.NoError(t, Apply(config.MustNewConfigFrom(`agent.limits: {go_max_procs: 2, cpu: 50}`)))
		require.False(t, called, "callback must not be called")
		require.Equal(t, 2, GoMaxProcs(), "stored value should be valid")
		require.Equal(t, 3, runtime.GOMAXPROCS(0), "runtime value must not be set again")
	})

	t.Run("an invalid CPU limit rejects the whole config", func(t *testing.T) {
		restoreLimits(t)
		require.NoError(t, Apply(config.MustNewConfigFrom(`agent.limits.go_max_procs: 2`)))

		require.Error(t, Apply(config.MustNewConfigFrom(`agent.limits: {go_max_procs: 3, cpu: 0}`)))
		require.Equal(t, 2, GoMaxProcs(), "stored value should be valid")
		require.Equal(t, 2, runtime.GOMAXPROCS(0), "actual runtime value should be valid")
	})

	t.Run("the stored CPU limit follows the config", func(t *testing.T) {
		restoreLimits(t)
		for _, tc := range []struct {
			c          string
			expPercent int
		}{
			{c: `agent.limits: {go_max_procs: 2, cpu: 50}`, expPercent: 50},
			{c: `agent.limits: {go_max_procs: 2, cpu: 60}`, expPercent: 60},
			{c: `agent.limits: {go_max_procs: 2}`, expPercent: 0},
		} {
			require.NoError(t, Apply(config.MustNewConfigFrom(tc.c)))
			current.mu.RLock()
			percent := current.cfg.CPU.Percent()
			current.mu.RUnlock()
			require.Equal(t, tc.expPercent, percent, tc.c)
		}
	})
}

func TestParseCPU(t *testing.T) {
	cases := []struct {
		name       string
		policy     any
		expErr     bool
		expPercent int
	}{
		{name: "the limit is off if cpu is absent", policy: config.MustNewConfigFrom(`agent.limits.go_max_procs: 2`)},
		{name: "the limit is off if cpu is empty", policy: config.MustNewConfigFrom(`agent.limits.cpu:`)},
		{name: "accepts 1", policy: config.MustNewConfigFrom(`agent.limits.cpu: 1`), expPercent: 1},
		{name: "accepts 100", policy: config.MustNewConfigFrom(`agent.limits.cpu: 100`), expPercent: 100},
		{name: "accepts a quoted number", policy: config.MustNewConfigFrom(`agent.limits.cpu: "50"`), expPercent: 50},
		{
			name:       "accepts a map with a JSON number",
			policy:     map[string]any{"agent": map[string]any{"limits": map[string]any{"cpu": float64(50)}}},
			expPercent: 50,
		},
		{name: "rejects 0", policy: config.MustNewConfigFrom(`agent.limits.cpu: 0`), expErr: true},
		{name: "rejects a negative number", policy: config.MustNewConfigFrom(`agent.limits.cpu: -1`), expErr: true},
		{name: "rejects 101", policy: config.MustNewConfigFrom(`agent.limits.cpu: 101`), expErr: true},
		{name: "rejects a fraction", policy: config.MustNewConfigFrom(`agent.limits.cpu: 50.5`), expErr: true},
		{name: "rejects a string", policy: config.MustNewConfigFrom(`agent.limits.cpu: abc`), expErr: true},
		{name: "rejects a boolean", policy: config.MustNewConfigFrom(`agent.limits.cpu: true`), expErr: true},
		{name: "rejects a list", policy: config.MustNewConfigFrom(`agent.limits.cpu: [50]`), expErr: true},
		{name: "rejects an object", policy: config.MustNewConfigFrom(`agent.limits.cpu.value: 50`), expErr: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, err := Parse(tc.policy)
			if tc.expErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expPercent, l.CPU.Percent())
		})
	}
}

func TestEffectiveCPUs(t *testing.T) {
	cases := []struct {
		name        string
		percent     int
		logicalCPUs int
		exp         float64
	}{
		{name: "the cap is off", percent: 0, logicalCPUs: 8, exp: 0},
		{name: "50% of 8 CPUs", percent: 50, logicalCPUs: 8, exp: 4},
		{name: "1% of 4 CPUs is raised to the floor", percent: 1, logicalCPUs: 4, exp: 0.2},
		{name: "1% of 200 CPUs is above the floor", percent: 1, logicalCPUs: 200, exp: 2},
		{name: "5% of 8 CPUs equals the floor", percent: 5, logicalCPUs: 8, exp: 0.4},
		{name: "1% of 32 CPUs is raised to the floor", percent: 1, logicalCPUs: 32, exp: 1.6},
		{name: "the floor does not grow above 32 CPUs", percent: 1, logicalCPUs: 33, exp: 1.6},
		{name: "4% of 40 CPUs equals the floor", percent: 4, logicalCPUs: 40, exp: 1.6},
		{name: "100% of 4096 CPUs", percent: 100, logicalCPUs: 4096, exp: 4096},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l := CPULimit{percent: tc.percent}
			require.Equal(t, tc.exp, l.EffectiveCPUs(tc.logicalCPUs))
		})
	}
}
