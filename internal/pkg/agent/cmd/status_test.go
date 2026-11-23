// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/pkg/control"

	"github.com/jedib0t/go-pretty/v6/list"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
)

func TestHumanOutput(t *testing.T) {
	var b bytes.Buffer
	stateDegraded := &client.AgentState{
		Info: client.AgentStateInfo{
			ID:        "9a4921cc-36d4-4b5a-9395-9ec2d204862e",
			Version:   "8.8.0",
			Commit:    "adf44ef2c6dfc56b5e60400ecdfbf46ceda5a6f4",
			BuildTime: "2023-05-24 00:01:09 +0000 UTC",
			Snapshot:  false,
		},
		State:        client.Degraded,
		Message:      "1 or more components/units in a failed state",
		FleetState:   client.Healthy,
		FleetMessage: "Connected",
		Components: []client.ComponentState{
			{
				ID:      "log-default",
				Name:    "log",
				State:   client.Healthy,
				Message: "Healthy: communicating with pid '1813'",
				Units: []client.ComponentUnitState{
					{
						UnitID:   "log-default-logfile-system-7bc17120-0951-11ee-bd02-734625f2144c",
						UnitType: client.UnitTypeInput,
						State:    client.Healthy,
						Message:  "Healthy",
					},
					{
						UnitID:   "log-default",
						UnitType: client.UnitTypeOutput,
						State:    client.Healthy,
						Message:  "Healthy",
					},
				},
			},
			{
				ID:      "httpjson-default",
				Name:    "httpjson",
				State:   client.Healthy,
				Message: "Healthy communicating with pid '2875'",
				Units: []client.ComponentUnitState{
					{
						UnitID:   "httpjson-default-httpjson-generic-ca7fa460-0bab-11ee-8598-c3f64dd59b06",
						UnitType: client.UnitTypeInput,
						State:    client.Failed,
						Message:  "[failed to reloading inputs: 1 error: Error creating runner from config: required 'object', but found 'string' in field 'processors.6']",
					},
					{
						UnitID:   "httpjson-default",
						UnitType: client.UnitTypeOutput,
						State:    client.Failed,
						Message:  "[failed to reloading inputs: 1 error: Error creating runner from config: required 'object', but found 'string' in field 'processors.6']",
					},
				},
			},
		},
	}
	stateHealthy := &client.AgentState{
		Info: client.AgentStateInfo{
			ID:        "9a4921cc-36d4-4b5a-9395-9ec2d204862e",
			Version:   "8.8.0",
			Commit:    "adf44ef2c6dfc56b5e60400ecdfbf46ceda5a6f4",
			BuildTime: "2023-05-24 00:01:09 +0000 UTC",
			Snapshot:  false,
		},
		State:        client.Healthy,
		Message:      "Running",
		FleetState:   client.Healthy,
		FleetMessage: "Connected",
		Components: []client.ComponentState{
			{
				ID:      "log-default",
				Name:    "log",
				State:   client.Healthy,
				Message: "Healthy: communicating with pid '1813'",
				Units: []client.ComponentUnitState{
					{
						UnitID:   "log-default-logfile-system-7bc17120-0951-11ee-bd02-734625f2144c",
						UnitType: client.UnitTypeInput,
						State:    client.Healthy,
						Message:  "Healthy",
					},
					{
						UnitID:   "log-default",
						UnitType: client.UnitTypeOutput,
						State:    client.Healthy,
						Message:  "Healthy",
					},
				},
			},
			{
				ID:      "system/metrics-default",
				Name:    "system/metrics",
				State:   client.Healthy,
				Message: "Healthy communicating with pid '1825'",
				Units: []client.ComponentUnitState{
					{
						UnitID:   "system/metrics-default-system/metrics-system-7bc17120-0951-11ee-bd02-734625f2144c",
						UnitType: client.UnitTypeInput,
						State:    client.Healthy,
						Message:  "Healthy",
					},
					{
						UnitID:   "system/metrics-default",
						UnitType: client.UnitTypeOutput,
						State:    client.Healthy,
						Message:  "Healthy",
					},
				},
			},
		},
	}
	tests := []struct {
		state      *client.AgentState
		state_name string
		output     string
	}{
		{output: "human", state_name: "degraded", state: stateDegraded},
		{output: "human", state_name: "healthy", state: stateHealthy},
		{output: "full", state_name: "healthy", state: stateHealthy},
		{output: "full", state_name: "degraded", state: stateDegraded},
	}
	for _, test := range tests {
		b.Reset()
		expected, err := os.ReadFile(filepath.Join("testdata/status", test.output+"_"+test.state_name))
		require.NoErrorf(t, err, "error reading testdata for output: %s state: %s", test.output, test.state_name)
		outputFunc, ok := statusOutputs[test.output]
		require.Truef(t, ok, "Could not find output %s", test.output)
		err = outputFunc(&b, test.state)
		require.NoErrorf(t, err, "error applying output function: %s with state: %s", test.output, test.state_name)
		require.Equalf(t, string(expected), b.String(), "unexpected input with output: %s, state: %s", test.output, test.state_name)
	}
}

func TestListUpgradeDetails(t *testing.T) {
	now := time.Now().UTC()
	cases := map[string]struct {
		upgradeDetails *cproto.UpgradeDetails
		expectedOutput string
	}{
		"no_details": {
			upgradeDetails: nil,
			expectedOutput: "",
		},
		"no_metadata": {
			upgradeDetails: &cproto.UpgradeDetails{
				TargetVersion: "8.12.0",
				State:         "UPG_REQUESTED",
				ActionId:      "foobar",
			},
			expectedOutput: `── upgrade_details
   ├─ target_version: 8.12.0
   ├─ state: UPG_REQUESTED
   └─ action_id: foobar`,
		},
		"no_action_id": {
			upgradeDetails: &cproto.UpgradeDetails{
				TargetVersion: "8.12.0",
				State:         "UPG_REQUESTED",
			},
			expectedOutput: `── upgrade_details
   ├─ target_version: 8.12.0
   └─ state: UPG_REQUESTED`,
		},
		"no_scheduled_at": {
			upgradeDetails: &cproto.UpgradeDetails{
				TargetVersion: "8.12.0",
				State:         "UPG_FAILED",
				Metadata: &cproto.UpgradeDetailsMetadata{
					FailedState:     "UPG_DOWNLOADING",
					ErrorMsg:        "error downloading",
					DownloadPercent: 0.104,
				},
			},
			expectedOutput: `── upgrade_details
   ├─ target_version: 8.12.0
   ├─ state: UPG_FAILED
   └─ metadata
      ├─ failed_state: UPG_DOWNLOADING
      └─ error_msg: error downloading`,
		},
		"no_failed_state": {
			upgradeDetails: &cproto.UpgradeDetails{
				TargetVersion: "8.12.0",
				State:         "UPG_DOWNLOADING",
				Metadata: &cproto.UpgradeDetailsMetadata{
					ScheduledAt:     now.Format(control.TimeFormat()),
					DownloadPercent: 0.17679,
				},
			},
			expectedOutput: fmt.Sprintf(`── upgrade_details
   ├─ target_version: 8.12.0
   ├─ state: UPG_DOWNLOADING
   └─ metadata
      ├─ scheduled_at: %s
      └─ download_percent: 17.68%%`, now.Format(control.TimeFormat())),
		},
		"retrying_downloading": {
			upgradeDetails: &cproto.UpgradeDetails{
				TargetVersion: "8.12.0",
				State:         "UPG_DOWNLOADING",
				Metadata: &cproto.UpgradeDetailsMetadata{
					ScheduledAt:     now.Format(control.TimeFormat()),
					DownloadPercent: 0,
					RetryErrorMsg:   "unable to download, will retry",
					RetryUntil:      "1h59m32s",
				},
			},
			expectedOutput: fmt.Sprintf(`── upgrade_details
   ├─ target_version: 8.12.0
   ├─ state: UPG_DOWNLOADING
   └─ metadata
      ├─ scheduled_at: %s
      ├─ download_percent: 0.00%%
      ├─ retry_until: 1h59m32s
      └─ retry_error_msg: unable to download, will retry`, now.Format(control.TimeFormat())),
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			l := list.NewWriter()
			l.SetStyle(list.StyleConnectedLight)

			listUpgradeDetails(l, test.upgradeDetails)
			actualOutput := l.Render()
			require.Equal(t, test.expectedOutput, actualOutput)
		})
	}
}

func TestHumanDurationUntil(t *testing.T) {
	now := time.Now()
	cases := map[string]struct {
		targetTimeStr string

		// For some reason the calculated duration is never precise
		// so we use a regexp instead.
		expectedDurationRegexp string
	}{
		"valid_time": {
			targetTimeStr:          now.Add(3 * time.Hour).Format(control.TimeFormat()),
			expectedDurationRegexp: `^3h0m0s$`,
		},
		"invalid_time": {
			targetTimeStr:          "foobar",
			expectedDurationRegexp: "^foobar$",
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			actualTimeStr := humanDurationUntil(test.targetTimeStr, now)
			require.Regexp(t, regexp.MustCompile(test.expectedDurationRegexp), actualTimeStr)
		})
	}
}

func TestListCPULimit(t *testing.T) {
	cases := map[string]struct {
		cpuLimit       *client.CPULimitState
		all            bool
		expectedOutput string
	}{
		"not_reported": {
			cpuLimit:       nil,
			all:            true,
			expectedOutput: "",
		},
		"human_unknown_state": {
			cpuLimit: &client.CPULimitState{State: "throttled", ConfiguredPercent: 50, TargetCPUs: 2, ActiveQuota: "none"},
			expectedOutput: `── cpu_limit
   ├─ state: throttled
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   └─ active_quota: none`,
		},
		"human_unknown_quota": {
			cpuLimit: &client.CPULimitState{State: "pending", ConfiguredPercent: 50, ActiveQuota: "partial"},
			expectedOutput: `── cpu_limit
   ├─ state: pending
   ├─ configured: 50%
   └─ active_quota: partial`,
		},
		"full_cap_100": {
			cpuLimit: &client.CPULimitState{
				State:              "applied",
				ConfiguredPercent:  100,
				TargetCPUs:         4,
				ActiveQuota:        "set",
				ActiveQuotaCPUs:    4,
				EffectiveQuota:     "set",
				EffectiveQuotaCPUs: 4,
			},
			all: true,
			expectedOutput: `── cpu_limit
   ├─ state: applied
   ├─ configured: 100%
   ├─ target_cpus: 4.00
   ├─ active_quota: 4.00 CPUs
   └─ effective_quota: 4.00 CPUs`,
		},
		"full_effective_lower": {
			cpuLimit: &client.CPULimitState{
				State:              "applied",
				ConfiguredPercent:  50,
				TargetCPUs:         2,
				ActiveQuota:        "set",
				ActiveQuotaCPUs:    2,
				EffectiveQuota:     "set",
				EffectiveQuotaCPUs: 1.5,
			},
			all: true,
			expectedOutput: `── cpu_limit
   ├─ state: applied
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: 2.00 CPUs
   ├─ effective_quota: 1.50 CPUs
   └─ limited_by: a quota above the Agent`,
		},
		"full_effective_lower_within_rounding": {
			cpuLimit: &client.CPULimitState{
				State:              "applied",
				ConfiguredPercent:  50,
				TargetCPUs:         2,
				ActiveQuota:        "set",
				ActiveQuotaCPUs:    2,
				EffectiveQuota:     "set",
				EffectiveQuotaCPUs: 1.999,
			},
			all: true,
			expectedOutput: `── cpu_limit
   ├─ state: applied
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: 2.00 CPUs
   └─ effective_quota: 2.00 CPUs`,
		},
		"full_effective_lower_by_tolerance": {
			cpuLimit: &client.CPULimitState{
				State:              "applied",
				ConfiguredPercent:  50,
				TargetCPUs:         2,
				ActiveQuota:        "set",
				ActiveQuotaCPUs:    2,
				EffectiveQuota:     "set",
				EffectiveQuotaCPUs: 1.99,
			},
			all: true,
			expectedOutput: `── cpu_limit
   ├─ state: applied
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: 2.00 CPUs
   └─ effective_quota: 1.99 CPUs`,
		},
		"full_effective_lower_above_tolerance": {
			cpuLimit: &client.CPULimitState{
				State:              "applied",
				ConfiguredPercent:  50,
				TargetCPUs:         2,
				ActiveQuota:        "set",
				ActiveQuotaCPUs:    2,
				EffectiveQuota:     "set",
				EffectiveQuotaCPUs: 1.98,
			},
			all: true,
			expectedOutput: `── cpu_limit
   ├─ state: applied
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: 2.00 CPUs
   ├─ effective_quota: 1.98 CPUs
   └─ limited_by: a quota above the Agent`,
		},
		"full_effective_higher": {
			cpuLimit: &client.CPULimitState{
				State:              "applied",
				ConfiguredPercent:  50,
				TargetCPUs:         2,
				ActiveQuota:        "set",
				ActiveQuotaCPUs:    2,
				EffectiveQuota:     "set",
				EffectiveQuotaCPUs: 3,
			},
			all: true,
			expectedOutput: `── cpu_limit
   ├─ state: applied
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: 2.00 CPUs
   └─ effective_quota: 3.00 CPUs`,
		},
		"full_effective_set_active_none": {
			cpuLimit: &client.CPULimitState{State: "pending", ConfiguredPercent: 50, TargetCPUs: 2, ActiveQuota: "none", EffectiveQuota: "set", EffectiveQuotaCPUs: 1.5},
			all:      true,
			expectedOutput: `── cpu_limit
   ├─ state: pending
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: none
   └─ effective_quota: 1.50 CPUs`,
		},
		"full_effective_none": {
			cpuLimit: &client.CPULimitState{State: "pending", ConfiguredPercent: 50, TargetCPUs: 2, ActiveQuota: "none", EffectiveQuota: "none"},
			all:      true,
			expectedOutput: `── cpu_limit
   ├─ state: pending
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: none
   └─ effective_quota: none`,
		},
		"full_effective_unknown": {
			cpuLimit: &client.CPULimitState{State: "applied", ConfiguredPercent: 50, TargetCPUs: 2, ActiveQuota: "set", ActiveQuotaCPUs: 2, EffectiveQuota: "unknown"},
			all:      true,
			expectedOutput: `── cpu_limit
   ├─ state: applied
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: 2.00 CPUs
   └─ effective_quota: unknown`,
		},
		"full_effective_not_reported": {
			cpuLimit: &client.CPULimitState{State: "applied", ConfiguredPercent: 50, TargetCPUs: 2, ActiveQuota: "set", ActiveQuotaCPUs: 2},
			all:      true,
			expectedOutput: `── cpu_limit
   ├─ state: applied
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: 2.00 CPUs
   └─ effective_quota: unknown`,
		},
		"full_effective_unknown_kind": {
			cpuLimit: &client.CPULimitState{State: "pending", ConfiguredPercent: 50, ActiveQuota: "none", EffectiveQuota: "partial"},
			all:      true,
			expectedOutput: `── cpu_limit
   ├─ state: pending
   ├─ configured: 50%
   ├─ active_quota: none
   └─ effective_quota: partial`,
		},
		"human_disabled": {
			cpuLimit:       &client.CPULimitState{State: "disabled", ActiveQuota: "unknown"},
			expectedOutput: "",
		},
		"full_disabled": {
			cpuLimit: &client.CPULimitState{State: "disabled", ActiveQuota: "unknown"},
			all:      true,
			expectedOutput: `── cpu_limit
   └─ state: disabled`,
		},
		"human_pending_cap_off": {
			cpuLimit: &client.CPULimitState{State: "pending", ActiveQuota: "set", ActiveQuotaCPUs: 2},
			expectedOutput: `── cpu_limit
   ├─ state: pending
   ├─ configured: off
   └─ active_quota: 2.00 CPUs`,
		},
		"human_applied": {
			cpuLimit:       &client.CPULimitState{State: "applied", ConfiguredPercent: 50, TargetCPUs: 2, ActiveQuota: "set", ActiveQuotaCPUs: 2},
			expectedOutput: "",
		},
		"human_pending": {
			cpuLimit: &client.CPULimitState{State: "pending", ConfiguredPercent: 50},
			expectedOutput: `── cpu_limit
   ├─ state: pending
   ├─ configured: 50%
   └─ active_quota: unknown`,
		},
		"human_unsupported": {
			cpuLimit: &client.CPULimitState{State: "unsupported", ConfiguredPercent: 25, ActiveQuota: "unknown", Reason: "not supported here"},
			expectedOutput: `── cpu_limit
   ├─ state: unsupported
   ├─ configured: 25%
   ├─ active_quota: unknown
   └─ reason: not supported here`,
		},
		"human_degraded": {
			cpuLimit: &client.CPULimitState{
				State:              "degraded",
				ConfiguredPercent:  50,
				TargetCPUs:         2,
				ActiveQuota:        "set",
				ActiveQuotaCPUs:    3.25,
				EffectiveQuota:     "set",
				EffectiveQuotaCPUs: 1,
				Error:              "set failed",
			},
			expectedOutput: `── cpu_limit
   ├─ state: degraded
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: 3.25 CPUs
   └─ error: set failed`,
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			l := list.NewWriter()
			l.SetStyle(list.StyleConnectedLight)

			listCPULimit(l, test.cpuLimit, test.all)
			require.Equal(t, test.expectedOutput, l.Render())
		})
	}
}

func TestStatusOutputCPULimit(t *testing.T) {
	state := &client.AgentState{
		Info:         client.AgentStateInfo{ID: "agent-id", Version: "9.7.0", Commit: "abc"},
		State:        client.Healthy,
		Message:      "Running",
		FleetState:   client.Healthy,
		FleetMessage: "Connected",
		CPULimit: &client.CPULimitState{
			State:              "applied",
			ConfiguredPercent:  50,
			TargetCPUs:         2,
			ActiveQuota:        "set",
			ActiveQuotaCPUs:    2,
			EffectiveQuota:     "set",
			EffectiveQuotaCPUs: 1.5,
		},
	}

	t.Run("human", func(t *testing.T) {
		var b bytes.Buffer
		require.NoError(t, humanOutput(&b, state))
		require.Equal(t, `┌─ fleet
│  └─ status: (HEALTHY) Connected
└─ elastic-agent
   └─ status: (HEALTHY) Running
`, b.String())
	})

	t.Run("full", func(t *testing.T) {
		var b bytes.Buffer
		require.NoError(t, humanFullOutput(&b, state))
		require.Equal(t, `┌─ fleet
│  └─ status: (HEALTHY) Connected
├─ elastic-agent
│  ├─ status: (HEALTHY) Running
│  └─ info
│     ├─ id: agent-id
│     ├─ version: 9.7.0
│     └─ commit: abc
└─ cpu_limit
   ├─ state: applied
   ├─ configured: 50%
   ├─ target_cpus: 2.00
   ├─ active_quota: 2.00 CPUs
   ├─ effective_quota: 1.50 CPUs
   └─ limited_by: a quota above the Agent
`, b.String())
	})

	t.Run("json", func(t *testing.T) {
		var b bytes.Buffer
		require.NoError(t, jsonOutput(&b, state))
		var out struct {
			CPULimit map[string]any `json:"cpu_limit"`
		}
		require.NoError(t, json.Unmarshal(b.Bytes(), &out))
		require.Equal(t, map[string]any{
			"state":                "applied",
			"configured_percent":   float64(50),
			"target_cpus":          float64(2),
			"active_quota":         "set",
			"active_quota_cpus":    float64(2),
			"effective_quota":      "set",
			"effective_quota_cpus": 1.5,
		}, out.CPULimit)
	})

	t.Run("yaml", func(t *testing.T) {
		var b bytes.Buffer
		require.NoError(t, yamlOutput(&b, state))
		// Typed fields, because YAML may write the same number as 2 or 2.0.
		type cpuLimitYAML struct {
			State              string  `yaml:"state"`
			ConfiguredPercent  uint32  `yaml:"configured_percent"`
			TargetCPUs         float64 `yaml:"target_cpus"`
			ActiveQuota        string  `yaml:"active_quota"`
			ActiveQuotaCPUs    float64 `yaml:"active_quota_cpus"`
			EffectiveQuota     string  `yaml:"effective_quota"`
			EffectiveQuotaCPUs float64 `yaml:"effective_quota_cpus"`
		}
		var out struct {
			CPULimit cpuLimitYAML `yaml:"cpu_limit"`
		}
		require.NoError(t, yaml.Unmarshal(b.Bytes(), &out))
		require.Equal(t, cpuLimitYAML{
			State:              "applied",
			ConfiguredPercent:  50,
			TargetCPUs:         2,
			ActiveQuota:        "set",
			ActiveQuotaCPUs:    2,
			EffectiveQuota:     "set",
			EffectiveQuotaCPUs: 1.5,
		}, out.CPULimit)
	})
}

func TestStatusOutputCPULimitDisabled(t *testing.T) {
	state := &client.AgentState{
		Info:         client.AgentStateInfo{ID: "agent-id", Version: "9.7.0", Commit: "abc"},
		State:        client.Healthy,
		Message:      "Running",
		FleetState:   client.Healthy,
		FleetMessage: "Connected",
		CPULimit:     &client.CPULimitState{State: "disabled", ActiveQuota: "unknown", EffectiveQuota: "unknown"},
	}

	t.Run("human", func(t *testing.T) {
		var b bytes.Buffer
		require.NoError(t, humanOutput(&b, state))
		require.Equal(t, `┌─ fleet
│  └─ status: (HEALTHY) Connected
└─ elastic-agent
   └─ status: (HEALTHY) Running
`, b.String())
	})

	t.Run("full", func(t *testing.T) {
		var b bytes.Buffer
		require.NoError(t, humanFullOutput(&b, state))
		require.Equal(t, `┌─ fleet
│  └─ status: (HEALTHY) Connected
├─ elastic-agent
│  ├─ status: (HEALTHY) Running
│  └─ info
│     ├─ id: agent-id
│     ├─ version: 9.7.0
│     └─ commit: abc
└─ cpu_limit
   └─ state: disabled
`, b.String())
	})

	t.Run("json", func(t *testing.T) {
		var b bytes.Buffer
		require.NoError(t, jsonOutput(&b, state))
		var out struct {
			CPULimit map[string]any `json:"cpu_limit"`
		}
		require.NoError(t, json.Unmarshal(b.Bytes(), &out))
		require.Equal(t, map[string]any{
			"state":              "disabled",
			"configured_percent": float64(0),
			"target_cpus":        float64(0),
			"active_quota":       "unknown",
			"effective_quota":    "unknown",
		}, out.CPULimit)
	})

	t.Run("yaml", func(t *testing.T) {
		var b bytes.Buffer
		require.NoError(t, yamlOutput(&b, state))
		// Typed fields, because YAML may write the same number as 0 or 0.0.
		type cpuLimitYAML struct {
			State             string  `yaml:"state"`
			ConfiguredPercent uint32  `yaml:"configured_percent"`
			TargetCPUs        float64 `yaml:"target_cpus"`
			ActiveQuota       string  `yaml:"active_quota"`
			EffectiveQuota    string  `yaml:"effective_quota"`
		}
		var out struct {
			CPULimit *cpuLimitYAML `yaml:"cpu_limit"`
		}
		require.NoError(t, yaml.Unmarshal(b.Bytes(), &out))
		require.Equal(t, &cpuLimitYAML{State: "disabled", ActiveQuota: "unknown", EffectiveQuota: "unknown"}, out.CPULimit)
	})
}

func TestStatusOutputCPULimitNotReported(t *testing.T) {
	state := &client.AgentState{State: client.Healthy, Message: "Running", FleetState: client.Healthy, FleetMessage: "Connected"}

	t.Run("json", func(t *testing.T) {
		var b bytes.Buffer
		require.NoError(t, jsonOutput(&b, state))
		var out map[string]any
		require.NoError(t, json.Unmarshal(b.Bytes(), &out))
		require.Contains(t, out, "state")
		require.NotContains(t, out, "cpu_limit")
	})

	t.Run("yaml", func(t *testing.T) {
		var b bytes.Buffer
		require.NoError(t, yamlOutput(&b, state))
		var out map[string]any
		require.NoError(t, yaml.Unmarshal(b.Bytes(), &out))
		require.Contains(t, out, "state")
		require.NotContains(t, out, "cpu_limit")
	})
}
