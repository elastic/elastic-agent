// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package check

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

// ConnectedToFleet checks if the agent defined in the fixture is connected to
// Fleet Server. It uses assert.Eventually and if it fails the last error will
// be printed. It returns if the agent is connected to Fleet Server or not.
func ConnectedToFleet(ctx context.Context, t *testing.T, fixture *integrationtest.Fixture, timeout time.Duration) bool {
	t.Helper()

	var err error
	var agentStatus integrationtest.AgentStatusOutput
	assertFn := func() bool {
		agentStatus, err = fixture.ExecStatus(ctx)
		return agentStatus.FleetState == int(cproto.State_HEALTHY)
	}

	connected := assert.Eventually(t, assertFn, timeout, 5*time.Second,
		"want fleet state %s, got %s. agent status: %v",
		cproto.State_HEALTHY, cproto.State(agentStatus.FleetState), agentStatus) //nolint:gosec // G115 always under 32-bit

	if !connected && err != nil {
		t.Logf("agent isn't connected to fleet-server: last error from agent status command: %v",
			err)
	}

	return connected
}

// FleetAgentStatus returns a niladic function that returns true if the agent
// has reached expectedStatus; false otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func FleetAgentStatus(ctx context.Context,
	t *testing.T,
	client *kibana.Client,
	policyID,
	expectedStatus string) func() bool {
	return func() bool {
		currentStatus, err := fleettools.GetAgentStatus(ctx, client, policyID)
		if err != nil {
			t.Errorf("unable to determine agent status: %s", err.Error())
			return false
		}

		if currentStatus == expectedStatus {
			return true
		}

		t.Logf("Agent fleet status: %s", currentStatus)
		return false
	}
}

// FleetAgentStatusByAgentID returns a niladic function that returns true if the agent with given ID
// has reached expectedStatus; false otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func FleetAgentStatusByAgentID(ctx context.Context,
	t *testing.T,
	client *kibana.Client,
	agentID,
	expectedStatus string) func() bool {
	return func() bool {
		req := kibana.GetAgentRequest{
			ID: agentID,
		}
		resp, err := client.GetAgent(ctx, req)
		if err != nil {
			t.Logf("failed to get agent by ID: %s", err)
			return false
		}
		if resp.Status == expectedStatus {
			return true
		}
		t.Logf("Agent fleet status: %s", resp.Status)
		return false
	}
}
