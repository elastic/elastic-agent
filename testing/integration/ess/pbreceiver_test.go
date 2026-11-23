// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
//go:build integration

package ess

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPbReceiverSubcomponentStatus verifies that pbreceiver correctly propagates per-stream
// status to the elastic-agent component and unit statuses.
func TestPbReceiverSubcomponentStatus(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Default,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
			{Type: define.Windows},
		},
		Stack: nil,
	})

	esURL := integration.StartMockES(t, 0, 0, 0, 0)

	// unique-packet-input has a single http stream and should be HEALTHY.
	// unique-packet-input-2 has http (HEALTHY) + bogus (DEGRADED): packetbeat's
	// unknownProtocolsReason fires for the "bogus" type and marks that receiver
	// DEGRADED, which rolls up to the unit and component.
	config := fmt.Sprintf(`agent:
  logging:
    to_stderr: true
    to_files: false
    level: debug
  monitoring:
    enabled: false
inputs:
- data_stream:
    namespace: default
  id: unique-packet-input
  streams:
  - data_stream:
      dataset: network_traffic.http
    id: unique-packet-input-http
    type: http
  type: packet
  use_output: default
- data_stream:
    namespace: default
  id: unique-packet-input-2
  streams:
  - data_stream:
      dataset: network_traffic.http
    id: unique-packet-input-2-http
    type: http
  - data_stream:
      dataset: network_traffic.bogus
    id: unique-packet-input-2-bogus
    type: bogus
  type: packet
  use_output: default
outputs:
  default:
    api_key: placeholder
    hosts:
    - %s
    type: elasticsearch
    preset: latency
`, esURL.Host)

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	err = fixture.Prepare(ctx)
	require.NoError(t, err)
	err = fixture.Configure(ctx, []byte(config))
	require.NoError(t, err)

	installOutput, err := fixture.Install(ctx, &atesting.InstallOpts{Privileged: true, Force: true})
	require.NoError(t, err, "install failed, output: %s", string(installOutput))

	expectedComponentVersionInfoName := componentVersionInfoNameForRuntime(component.OtelRuntimeManager)
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		status, statusErr := fixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		// unique-packet-input-2 has a DEGRADED unit, so the agent should be DEGRADED
		assert.Equal(collect, int(cproto.State_DEGRADED), status.State)
		// both packet inputs merge into a single packet-default component
		require.Len(collect, status.Components, 1, "expected one packet-default component")

		comp := status.Components[0]
		assert.Truef(collect, strings.HasPrefix(comp.ID, "packet"),
			"expected component ID to start with 'packet', got %s", comp.ID)
		assert.Equal(collect, expectedComponentVersionInfoName, comp.VersionInfo.Name)
		assert.Equal(collect, int(cproto.State_DEGRADED), comp.State,
			"packet component should be DEGRADED due to the bogus stream")
		// 1 output unit + 2 input units
		require.Lenf(collect, comp.Units, 3, "expected 3 units (1 output + 2 inputs), got %d", len(comp.Units))

		for _, unit := range comp.Units {
			if unit.UnitType == int(cproto.UnitType_OUTPUT) {
				continue
			}

			var expectedUnitState int
			var expectedStreamCount int
			if unit.UnitID == "packet-default-unique-packet-input-2" {
				expectedUnitState = int(cproto.State_DEGRADED)
				expectedStreamCount = 2
			} else {
				expectedUnitState = int(cproto.State_HEALTHY)
				expectedStreamCount = 1
			}
			assert.Equalf(collect, expectedUnitState, unit.State,
				"unit %s: expected state %d, got %d", unit.UnitID, expectedUnitState, unit.State)

			unitPayload := unit.Payload
			require.Lenf(collect, unitPayload.Streams, expectedStreamCount,
				"unit %s: expected %d streams, got %d", unit.UnitID, expectedStreamCount, len(unitPayload.Streams))

			for streamName, streamState := range unitPayload.Streams {
				if strings.Contains(streamName, "bogus") {
					assert.Equalf(collect, "DEGRADED", streamState.Status,
						"stream %s: expected DEGRADED, got %s", streamName, streamState.Status)
					assert.Containsf(collect, streamState.Error, "configuration ignored for unknown protocol plugins",
						"stream %s: unexpected error %q", streamName, streamState.Error)
				} else {
					assert.Equalf(collect, "HEALTHY", streamState.Status,
						"stream %s: expected HEALTHY, got %s", streamName, streamState.Status)
					assert.Emptyf(collect, streamState.Error,
						"stream %s: expected no error, got %q", streamName, streamState.Error)
				}
			}
		}
	}, 1*time.Minute, 1*time.Second)
}
