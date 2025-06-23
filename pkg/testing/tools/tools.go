// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package tools

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

// IsPolicyRevision returns a niladic function that returns true if the
// given agent's policy revision has reached the given policy revision; false
// otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func IsPolicyRevision(ctx context.Context, t *testing.T, client *kibana.Client, agentID string, policyRevision int) func() bool {
	return func() bool {
		getAgentReq := kibana.GetAgentRequest{ID: agentID}
		updatedPolicyAgent, err := client.GetAgent(ctx, getAgentReq)
		if err != nil {
			t.Logf("failed to get agent document to check policy revision: %v", err)
			return false
		}

		return updatedPolicyAgent.PolicyRevision == policyRevision
	}
}

// InstallAgentWithPolicy creates the given policy, enrolls the given agent
// fixture in Fleet using the default Fleet Server, waits for the agent to be
// online, and returns the created policy.
func InstallAgentWithPolicy(ctx context.Context, t *testing.T,
	installOpts atesting.InstallOpts,
	agentFixture *atesting.Fixture,
	kibClient *kibana.Client,
	createPolicyReq kibana.AgentPolicy,
) (kibana.PolicyResponse, string, error) {
	t.Helper()

	// Create policy
	policy, err := kibClient.CreatePolicy(ctx, createPolicyReq)
	if err != nil {
		return policy, "", fmt.Errorf("unable to create policy: %w", err)
	}

	if createPolicyReq.IsProtected {
		// If protected fetch uninstall token and set it for the fixture
		resp, err := kibClient.GetPolicyUninstallTokens(ctx, policy.ID)
		if err != nil {
			return policy, "", fmt.Errorf("failed to fetch uninstal tokens: %w", err)
		}
		if len(resp.Items) == 0 {
			return policy, "", fmt.Errorf("expected non-zero number of tokens: %w", err)
		}

		if len(resp.Items[0].Token) == 0 {
			return policy, "", fmt.Errorf("expected non-empty token: %w", err)
		}

		uninstallToken := resp.Items[0].Token
		t.Logf("Protected with uninstall token: %v", uninstallToken)
		agentFixture.SetUninstallToken(uninstallToken)
	}

	agentID, err := InstallAgentForPolicy(ctx, t, installOpts, agentFixture, kibClient, policy.ID)
	return policy, agentID, err
}

// InstallAgentForPolicy enrolls the provided agent fixture with Fleet. If
// either the enroll URL or the enrollmentToken is empty, they'll be generated
// using the default fleet-server. Then if delay enroll isn't set it waits for
// the agent to come online, otherwise it returns immediately.
// If the context (ctx) has a deadline, it will wait for the agent to become
// online until the deadline of the context, or if not, a default 5-minute
// deadline will be applied.
func InstallAgentForPolicy(ctx context.Context, t *testing.T,
	installOpts atesting.InstallOpts,
	agentFixture *atesting.Fixture,
	kibClient *kibana.Client,
	policyID string,
) (string, error) {
	enrollmentToken, err := CreateEnrollmentToken(t, ctx, kibClient, policyID)
	if err != nil {
		return "", fmt.Errorf("failed to create enrollment token while preparing to install agent for policy: %w", err)
	}
	return InstallAgentForPolicyWithToken(ctx, t, installOpts, agentFixture, kibClient, enrollmentToken)
}

func CreateEnrollmentToken(t *testing.T, ctx context.Context, kibClient *kibana.Client, policyID string) (kibana.CreateEnrollmentAPIKeyResponse, error) {
	// Create enrollment API key
	createEnrollmentAPIKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policyID,
	}

	t.Logf("Creating enrollment API key...")
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(ctx, createEnrollmentAPIKeyReq)
	if err != nil {
		return kibana.CreateEnrollmentAPIKeyResponse{}, fmt.Errorf("failed creating enrollment API key: %w", err)
	}

	return enrollmentToken, nil
}

// InstallAgentForPolicyWithToken installs the Elastic Agent and enrolls into the policy that the provided
// enrollmentToken belongs to.
//
// This function waits for the Elastic Agent to be reported as online by Kibana, unless installOpts.DelayEnroll is set
// to true.
func InstallAgentForPolicyWithToken(ctx context.Context, t *testing.T,
	installOpts atesting.InstallOpts,
	agentFixture *atesting.Fixture,
	kibClient *kibana.Client,
	enrollmentToken kibana.CreateEnrollmentAPIKeyResponse,
) (string, error) {
	t.Helper()

	if installOpts.EnrollmentToken == "" {
		t.Logf("Creating enrollment API key...")
		installOpts.EnrollmentToken = enrollmentToken.APIKey
	}

	if installOpts.URL == "" {
		fleetServerURL, err := fleettools.DefaultURL(ctx, kibClient)
		if err != nil {
			return "", fmt.Errorf("failed getting fleet server URL: %w", err)
		}

		installOpts.URL = fleetServerURL
	}

	output, err := agentFixture.Install(ctx, &installOpts)
	if err != nil {
		t.Log(string(output))
		return "", fmt.Errorf("failed installing the agent: %w", err)
	}

	t.Logf(">>> Enroll succeeded. Output: %s", output)

	timeout := 10 * time.Minute
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	// Don't check fleet status if --delay-enroll
	if installOpts.DelayEnroll {
		// agentID is not returned if delay enroll is used as it has not actually enrolled
		return "", nil
	}

	// Get the Agent ID of Agent once it has been enrolled and is healthy.
	var agentID string
	require.Eventually(t, func() bool {
		status, err := agentFixture.ExecStatus(ctx)
		if err != nil {
			t.Logf("failed to get agent status: %v", err)
			return false
		}
		if cproto.State(status.FleetState) == cproto.State_HEALTHY { //nolint:gosec // G115 always under 32-bit
			agentID = status.Info.ID
			return true
		}
		t.Logf("wanted fleet status to be %v, was %v", cproto.State_HEALTHY, cproto.State(status.FleetState)) //nolint:gosec // G115 always under 32-bit
		return false
	}, timeout, 10*time.Second, "timed out waiting for agent ID to be reported as managed")
	t.Logf(">>> Enrolled Agent ID: %s", agentID)

	// Wait for Agent to be healthy
	require.Eventually(
		t,
		check.FleetAgentStatus(ctx, t, kibClient, agentID, "online"),
		timeout,
		10*time.Second,
		"Elastic Agent status is not online",
	)

	return agentID, nil
}
