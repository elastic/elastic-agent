// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

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

const FleetStatusOnline = "online"

// ConnectedToFleet checks if the agent defined in the fixture is connected to
// Fleet Server. It uses assert.Eventually and if it fails the last error will
// be printed. It returns if the agent is connected to Fleet Server or not.
func ConnectedToFleet(t *testing.T, fixture *integrationtest.Fixture, timeout time.Duration) bool {
	t.Helper()

	var err error
	var agentStatus integrationtest.AgentStatusOutput
	assertFn := func() bool {
		agentStatus, err = fixture.ExecStatus(context.Background())
		return agentStatus.FleetState == int(cproto.State_HEALTHY)
	}

	connected := assert.Eventually(t, assertFn, timeout, 5*time.Second,
		"want fleet state %s, got %s. agent status: %v",
		cproto.State_HEALTHY, cproto.State(agentStatus.FleetState), agentStatus)

	if !connected && err != nil {
		t.Logf("agent isn't connected to fleet-server: last error from agent status command: %v",
			err)
	}

	return connected
}

// FleetAgentStatus returns a niladic function that returns true if the agent
// has reached expectedStatus; false otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func FleetAgentStatus(t *testing.T,
	client *kibana.Client,
	policyID,
	expectedStatus string) func() bool {
	return func() bool {
		currentStatus, err := fleettools.GetAgentStatus(client, policyID)
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
