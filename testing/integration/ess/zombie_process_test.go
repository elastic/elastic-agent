// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/control/v2/client"
	"github.com/elastic/elastic-agent/pkg/core/process"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

var zombieTestConfig = `
outputs:
  default:
    type: fake-output
inputs:
  - id: fake
    type: fake
    state: 2
    message: Healthy
`

// TestNoZombieOnAgentShutdown verifies that when the agent shuts down while a
// component has not responded to SIGTERM, the component process is forcefully
// killed and reaped rather than being left running or as a zombie.
//
// The test uses a fake component configured with --sigterm-ignore (ignores
// SIGTERM) and --clear-pdeathsig (clears the Linux parent-death signal). This
// combination means the component will survive the agent's exit unless the
// agent explicitly sends SIGKILL during its shutdown sequence.
func TestNoZombieOnAgentShutdown(t *testing.T) {
	define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	f, err := define.NewFixtureFromLocalBuild(t, define.Version(), atesting.WithAllowErrors())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = f.Prepare(ctx, fakeSIGTERMComponent)
	require.NoError(t, err)

	pidRe := regexp.MustCompile(`pid '(\d+)'`)
	var componentPID int
	// Run the agent: wait for the component to become healthy, record its
	// PID, then let the fixture shut the agent down (all states exhausted →
	// fixture calls f.proc.Stop → SIGTERM to agent → agent shutdown
	// sequence → context cancellation after managerShutdownTimeout).
	err = f.Run(ctx, atesting.State{
		Configure:  zombieTestConfig,
		AgentState: atesting.NewClientState(client.Healthy),
		Components: map[string]atesting.ComponentState{
			"fake-default": {
				State: atesting.NewClientState(client.Healthy),
				Units: map[atesting.ComponentUnitKey]atesting.ComponentUnitState{
					{UnitType: client.UnitTypeOutput, UnitID: "fake-default"}: {
						State: atesting.NewClientState(client.Healthy),
					},
					{UnitType: client.UnitTypeInput, UnitID: "fake-default-fake"}: {
						State: atesting.NewClientState(client.Healthy),
					},
				},
			},
		},
		After: func(ctx context.Context) error {
			status, err := f.ExecStatus(ctx)
			if err != nil {
				return fmt.Errorf("failed to get agent status: %w", err)
			}
			for _, comp := range status.Components {
				if comp.ID == "fake-default" {
					m := pidRe.FindStringSubmatch(comp.Message)
					if len(m) > 1 {
						componentPID, _ = strconv.Atoi(m[1])
					}
				}
			}
			if componentPID == 0 {
				return fmt.Errorf("could not extract component PID from agent status")
			}
			t.Logf("component PID: %d — agent will now shut down", componentPID)
			return nil
		},
	})
	require.NoError(t, err)

	// Wait up until reap timeout for process to be reaped
	reaped := assert.Eventually(t, func() bool { return process.IsReaped(componentPID) }, process.KillReapTime, 100*time.Millisecond, "Process may still be running as a zombie after agent shutdown")
	if !reaped {
		// The component is still running - the test will fail, however we should try to clean up.
		t.Logf("Process %d survived agent shutdown! Attempting SIGKILL...", componentPID)
		proc, err := os.FindProcess(componentPID)
		require.NoError(t, err, "process not found")
		_ = proc.Kill()
		assert.Eventually(t, func() bool { return process.IsReaped(componentPID) }, process.KillReapTime, 100*time.Millisecond, "Process may still be running as a zombie after explicit kill")
	}
}
