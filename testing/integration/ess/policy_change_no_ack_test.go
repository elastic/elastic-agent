// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// TestPolicyChangePersistsWithoutAck verifies that an agent enrolled in a
// policy with disable_policy_change_acks=true still advances Fleet's view of
// its applied policy revision after the policy is updated.
//
// Without persisting the POLICY_CHANGE action in the state store when acks
// are disabled, and without reading agent_policy_id and policy_revision_idx
// from the policy data fields fleet-server actually emits, the agent's
// checkin reports zero values for those fields and Fleet's record of the
// agent's policy revision never advances. See
// https://github.com/elastic/kibana/issues/264983
func TestPolicyChangePersistsWithoutAck(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS: []define.OS{ // Flaky test see: https://github.com/elastic/elastic-agent/issues/14249, only windows is undefined so those tests are skipped
			{
				Type: define.Darwin,
			}, {
				Type: define.Linux,
			},
		},
	})

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(15*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	policyFeatures := []map[string]interface{}{
		{
			"name":    "disable_policy_change_acks",
			"enabled": true,
		},
	}

	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-no-ack-%s", uuid.Must(uuid.NewV4()).String()),
		Namespace:   info.Namespace,
		Description: "test policy for policy_change persistence without ack",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		AgentFeatures: policyFeatures,
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}

	policy, agentID, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, agentFixture, info.KibanaClient, createPolicyReq)
	require.NoError(t, err)
	t.Logf("created policy %s, enrolled agent %s", policy.ID, agentID)

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), time.Minute)
		defer cleanupCancel()
		assert.NoError(t, fleettools.UnEnrollAgent(cleanupCtx, info.KibanaClient, agentID))
	})

	check.ConnectedToFleet(ctx, t, agentFixture, 5*time.Minute)

	initialAgent, err := info.KibanaClient.GetAgent(ctx, kibana.GetAgentRequest{ID: agentID})
	require.NoError(t, err)
	initialRevision := initialAgent.PolicyRevision
	t.Logf("agent reported initial policy revision %d", initialRevision)

	// Update the policy to bump its revision. Description is the only field
	// that changes; the disable_policy_change_acks feature flag must remain
	// enabled so that the second POLICY_CHANGE action is processed with acks
	// disabled.
	updatePolicyReq := kibana.AgentPolicyUpdateRequest{
		Name:              policy.Name,
		Namespace:         info.Namespace,
		Description:       "test policy for policy_change persistence without ack - revision bump",
		MonitoringEnabled: createPolicyReq.MonitoringEnabled,
		AgentFeatures:     policyFeatures,
	}
	_, err = info.KibanaClient.UpdatePolicy(ctx, policy.ID, updatePolicyReq)
	require.NoError(t, err)

	expectedRevision := initialRevision + 1
	t.Logf("waiting for agent to report policy revision %d", expectedRevision)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		agent, err := info.KibanaClient.GetAgent(ctx, kibana.GetAgentRequest{ID: agentID})
		if !assert.NoError(c, err) {
			return
		}
		assert.GreaterOrEqual(c, agent.PolicyRevision, expectedRevision,
			"agent.policy_revision did not advance after policy update with acks disabled; "+
				"the POLICY_CHANGE action was either not persisted in the state store or "+
				"its policy id/revision fields were not reported in the next checkin")
	}, 5*time.Minute, 5*time.Second)
}
