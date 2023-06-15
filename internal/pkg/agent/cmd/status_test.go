// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
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
		{output: "human_full", state_name: "healthy", state: stateHealthy},
		{output: "human_full", state_name: "degraded", state: stateDegraded},
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
