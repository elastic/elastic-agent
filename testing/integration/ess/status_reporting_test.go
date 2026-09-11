// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// suppressedHealthConfig opts both units out of contributing their state with
// the matching flag: report_degraded for the Degraded unit, report_failed for
// the Failed unit. The agent must stay Healthy.
var suppressedHealthConfig = `
outputs:
  default:
    type: fake-output
inputs:
  - id: degraded
    type: fake
    state: 3
    message: Degraded but suppressed
    status_reporting:
      report_degraded: false
  - id: failed
    type: fake
    state: 4
    message: Failed but suppressed
    status_reporting:
      report_failed: false
`

// wrongFlagHealthConfig sets the non-matching flag on each unit (report_failed
// on a Degraded unit, report_degraded on a Failed unit), so neither unit is
// suppressed and the agent must be Degraded. This guards against the flags being
// applied to the wrong state, and proves the suppression is not unconditional.
var wrongFlagHealthConfig = `
outputs:
  default:
    type: fake-output
inputs:
  - id: degraded
    type: fake
    state: 3
    message: Degraded, wrong flag
    status_reporting:
      report_failed: false
  - id: failed
    type: fake
    state: 4
    message: Failed, wrong flag
    status_reporting:
      report_degraded: false
`

// TestFakeComponentStatusReportingSuppressesHealth verifies the status_reporting
// opt-out end to end: a unit with the matching report_* flag does not degrade
// the agent's aggregate health (while still reporting its own state), and the
// non-matching flag does not suppress.
func TestFakeComponentStatusReportingSuppressesHealth(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
	})

	// The test intentionally drives units into Failed/Degraded, which the agent
	// logs at error level; allow those so the harness does not flag them.
	f, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithAllowErrors())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = f.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	err = f.Run(ctx,
		// Matching flags: units stay Degraded/Failed, agent stays Healthy.
		atesting.State{
			Configure:  suppressedHealthConfig,
			AgentState: atesting.NewClientState(client.Healthy),
			Components: map[string]atesting.ComponentState{
				"fake-default": {
					State: atesting.NewClientState(client.Healthy),
					Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
						atesting.ComponentUnitKey{UnitType: client.UnitTypeOutput, UnitID: "fake-default"}: {
							State: atesting.NewClientState(client.Healthy),
						},
						atesting.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-degraded"}: {
							State: atesting.NewClientState(client.Degraded),
						},
						atesting.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-failed"}: {
							State: atesting.NewClientState(client.Failed),
						},
					},
				},
			},
		},
		// Non-matching flags: neither unit is suppressed, agent is Degraded.
		atesting.State{
			Configure:  wrongFlagHealthConfig,
			AgentState: atesting.NewClientState(client.Degraded),
			Components: map[string]atesting.ComponentState{
				"fake-default": {
					State: atesting.NewClientState(client.Healthy),
					Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
						atesting.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-degraded"}: {
							State: atesting.NewClientState(client.Degraded),
						},
						atesting.ComponentUnitKey{UnitType: client.UnitTypeInput, UnitID: "fake-default-failed"}: {
							State: atesting.NewClientState(client.Failed),
						},
					},
				},
			},
		},
	)
	require.NoError(t, err)
}
