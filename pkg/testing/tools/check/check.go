// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package check

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/beats/v7/pkg/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/process"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

// ConnectedToFleet waits until the agent in the fixture is connected to Fleet
// Server. If it is not connected in time, the errors from the last attempt are
// printed. cmdOptions change how the status command runs, for example its
// environment. It returns true if the agent is connected.
func ConnectedToFleet(ctx context.Context, t *testing.T, fixture *integrationtest.Fixture, timeout time.Duration, cmdOptions ...process.CmdOption) bool {
	t.Helper()

	return assert.EventuallyWithT(t, func(c *assert.CollectT) {
		agentStatus, err := fixture.ExecStatus(ctx, integrationtest.WithCmdOptions(cmdOptions...))
		require.NoError(c, err, "elastic-agent status failed")
		require.Equal(c, int(cproto.State_HEALTHY), agentStatus.FleetState,
			"agent isn't connected to fleet-server, agent status: %+v", agentStatus)
	}, timeout, 5*time.Second)
}

// FleetAgentStatus returns a niladic function that returns true if the agent
// has reached expectedStatus; false otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func FleetAgentStatus(ctx context.Context,
	t *testing.T,
	client *kibana.Client,
	agentID string,
	expectedStatus string) func() bool {
	return func() bool {
		currentStatus, err := fleettools.GetAgentStatus(ctx, client, agentID)
		if err != nil {
			t.Errorf("unable to determine agent status: %s", err.Error())
			return false
		}

		if currentStatus == expectedStatus {
			return true
		}
		return false
	}
}
