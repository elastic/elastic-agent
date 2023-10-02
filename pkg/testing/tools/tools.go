// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package tools

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"

	atesting "github.com/elastic/elastic-agent/pkg/testing"

	"github.com/stretchr/testify/require"
)

// WaitForAgentStatus returns a niladic function that returns true if the agent
// has reached expectedStatus; false otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func WaitForAgentStatus(t *testing.T, client *kibana.Client, expectedStatus string) func() bool {
	return func() bool {
		currentStatus, err := GetAgentStatus(client)
		if err != nil {
			t.Errorf("unable to determine agent status: %s", err.Error())
			return false
		}

		if currentStatus == expectedStatus {
			return true
		}

		t.Logf("Agent status: %s", currentStatus)
		return false
	}
}

// WaitForPolicyRevision returns a niladic function that returns true if the
// given agent's policy revision has reached the given policy revision; false
// otherwise. The returned function is intended
// for use with assert.Eventually or require.Eventually.
func WaitForPolicyRevision(t *testing.T, client *kibana.Client, agentID string, expectedPolicyRevision int) func() bool {
	return func() bool {
		getAgentReq := kibana.GetAgentRequest{ID: agentID}
		updatedPolicyAgent, err := client.GetAgent(context.TODO(), getAgentReq)
		require.NoError(t, err)

		return updatedPolicyAgent.PolicyRevision == expectedPolicyRevision
	}
}

// InstallAgentWithPolicy creates the given policy, enrolls the given agent
// fixture in Fleet using the default Fleet Server, waits for the agent to be
// online, and returns the created policy.
<<<<<<< HEAD
func InstallAgentWithPolicy(t *testing.T, agentFixture *atesting.Fixture, kibClient *kibana.Client, createPolicyReq kibana.AgentPolicy) (*kibana.PolicyResponse, error) {
=======
func InstallAgentWithPolicy(ctx context.Context, t *testing.T, installOpts atesting.InstallOpts, agentFixture *atesting.Fixture, kibClient *kibana.Client, createPolicyReq kibana.AgentPolicy) (kibana.PolicyResponse, error) {
>>>>>>> 35dbbdea9b (Add Windows support to integration testing runner (#2941))
	t.Helper()

	policy, err := kibClient.CreatePolicy(context.TODO(), createPolicyReq)
	if err != nil {
		return nil, fmt.Errorf("unable to create policy: %w", err)
	}

<<<<<<< HEAD
=======
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

>>>>>>> 35dbbdea9b (Add Windows support to integration testing runner (#2941))
	// Create enrollment API key
	createEnrollmentAPIKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policy.ID,
	}

	t.Logf("Creating enrollment API key...")
	enrollmentToken, err := kibClient.CreateEnrollmentAPIKey(context.TODO(), createEnrollmentAPIKeyReq)
	if err != nil {
		return nil, fmt.Errorf("unable to create enrollment API key: %w", err)
	}

	// Get default Fleet Server URL
	fleetServerURL, err := GetDefaultFleetServerURL(kibClient)
	if err != nil {
		return nil, fmt.Errorf("unable to get default Fleet Server URL: %w", err)
	}

	// Enroll agent
	t.Logf("Unpacking and installing Elastic Agent")
	// this is a partial backport of https://github.com/elastic/elastic-agent/pull/3114
	// normally the installOpts are passed as parameter, and we just add URL and Enrollment Token
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
	}
	installOpts.EnrollOpts = atesting.EnrollOpts{
		URL:             fleetServerURL,
		EnrollmentToken: enrollmentToken.APIKey,
	}
	output, err := InstallAgent(ctx, installOpts, agentFixture)
	if err != nil {
		t.Log(string(output))
		return nil, fmt.Errorf("unable to enroll Elastic Agent: %w", err)
	}
	t.Logf(">>> Ran Enroll. Output: %s", output)

	// Wait for Agent to be healthy
	require.Eventually(
		t,
		WaitForAgentStatus(t, kibClient, "online"),
		2*time.Minute,
		10*time.Second,
		"Elastic Agent status is not online",
	)

	return &policy, nil
}
