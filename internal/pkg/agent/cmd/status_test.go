// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/pkg/control"

	"github.com/jedib0t/go-pretty/v6/list"

	"github.com/stretchr/testify/require"

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
			expectedDurationRegexp: `^2h59m59\.\d+s$`,
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
