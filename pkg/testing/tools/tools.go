// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

// IsPolicyRevision returns a niladic function that returns true if the
// given agent's policy revision has reached the given policy revision; false
// otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func IsPolicyRevision(t *testing.T, client *kibana.Client, agentID string, policyRevision int) func() bool {
	return func() bool {
		getAgentReq := kibana.GetAgentRequest{ID: agentID}
		updatedPolicyAgent, err := client.GetAgent(context.Background(), getAgentReq)
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
	createPolicyReq kibana.AgentPolicy) (kibana.PolicyResponse, error) {
	t.Helper()

	// Create policy
	policy, err := kibClient.CreatePolicy(ctx, createPolicyReq)
	if err != nil {
		return policy, fmt.Errorf("unable to create policy: %w", err)
	}

	if createPolicyReq.IsProtected {
		// If protected fetch uninstall token and set it for the fixture
		resp, err := kibClient.GetPolicyUninstallTokens(ctx, policy.ID)
		if err != nil {
			return policy, fmt.Errorf("failed to fetch uninstal tokens: %w", err)
		}
		if len(resp.Items) == 0 {
			return policy, fmt.Errorf("expected non-zero number of tokens: %w", err)
		}

		if len(resp.Items[0].Token) == 0 {
			return policy, fmt.Errorf("expected non-empty token: %w", err)
		}

		uninstallToken := resp.Items[0].Token
		t.Logf("Protected with uninstall token: %v", uninstallToken)
		agentFixture.SetUninstallToken(uninstallToken)
	}

	err = InstallAgentForPolicy(ctx, t, installOpts, agentFixture, kibClient, policy.ID)
	return policy, err
}

// InstallAgentForPolicy enrolls the provided agent fixture in Fleet using the
// default Fleet Server, waits for the agent to come online, and returns either
// an error or nil.
// If the context (ctx) has a deadline, it will wait for the agent to become
// online until the deadline of the context, or if not, a default 5-minute
// deadline will be applied.
func InstallAgentForPolicy(ctx context.Context, t *testing.T,
	installOpts atesting.InstallOpts,
	agentFixture *atesting.Fixture,
	kibClient *kibana.Client,
	policyID string) error {
	t.Helper()

	// Create enrollment API key
	createEnrollmentAPIKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policyID,
	}

	t.Logf("Creating enrollment API key...")
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(ctx, createEnrollmentAPIKeyReq)
	if err != nil {
		return fmt.Errorf("unable to create enrollment API key: %w", err)
	}

	// Get default Fleet Server URL
	fleetServerURL, err := fleettools.DefaultURL(kibClient)
	if err != nil {
		return fmt.Errorf("unable to get default Fleet Server URL: %w", err)
	}

	// Enroll agent
	t.Logf("Unpacking and installing Elastic Agent")
	installOpts.EnrollOpts = atesting.EnrollOpts{
		URL:             fleetServerURL,
		EnrollmentToken: enrollmentToken.APIKey,
	}

	output, err := agentFixture.Install(ctx, &installOpts)
	if err != nil {
		t.Log(string(output))
		return fmt.Errorf("unable to enroll Elastic Agent: %w", err)
	}
	t.Logf(">>> Ran Enroll. Output: %s", output)

	timeout := 10 * time.Minute
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	assert.Eventually(
		t,
		check.FleetAgentStatus(t, kibClient, policyID, "online"),
		timeout,
		10*time.Second,
		"Elastic Agent status is not online",
	)
	// Wait for Agent to be healthy
	assert.Eventually(
		t,
		check.FleetAgentStatus(t, kibClient, policyID, "online"),
		timeout,
		10*time.Second,
		"Elastic Agent status is not online",
	)

	return nil
}

// InstallStandaloneAgent force install the Elastic Agent through agentFixture.
func InstallStandaloneAgent(agentFixture *atesting.Fixture) ([]byte, error) {
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}
	return agentFixture.Install(context.Background(), &installOpts)
}
