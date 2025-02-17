// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

func TestEnrollReplaceToken(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
		Sudo:  true,
	})

	ctx := context.Background()
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	fleetServerURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err)

	randId := uuid.Must(uuid.NewV4()).String()
	policyReq := kibana.AgentPolicy{
		Name:        "test-policy-" + randId,
		Namespace:   "default",
		Description: "Test policy " + randId,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policy, err := info.KibanaClient.CreatePolicy(ctx, policyReq)
	require.NoError(t, err)

	enrollmentApiKey, err := tools.CreateEnrollmentToken(t, ctx, info.KibanaClient, policy.ID)
	require.NoError(t, err)

	// use a defined ID and replace token
	agentID := uuid.Must(uuid.NewV4()).String()
	replaceToken := uuid.Must(uuid.NewV4()).String()
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     false,
		EnrollOpts: atesting.EnrollOpts{
			ID:              agentID,
			URL:             fleetServerURL,
			EnrollmentToken: enrollmentApiKey.APIKey,
			ReplaceToken:    replaceToken,
		},
	}

	output, err := fixture.Install(ctx, &installOpts)
	if err != nil {
		t.Log(string(output))
		t.Fatalf("failed installing the agent: %s", err)
	}

	t.Logf(">>> Enroll succeeded. Output: %s", output)

	// Wait for Agent to be healthy
	require.Eventually(
		t,
		check.FleetAgentStatusByAgentID(ctx, t, info.KibanaClient, agentID, "online"),
		10*time.Minute,
		10*time.Second,
		"Elastic Agent status is not online",
	)

	// Force uninstall the Agent (skipping information Fleet)
	output, err = fixture.Uninstall(ctx, &atesting.UninstallOpts{
		Force:          true,
		SkipFleetAudit: true,
	})
	if err != nil {
		t.Log(string(output))
		t.Fatalf("failed uninstalling the agent: %s", err)
	}

	// Wait for Agent to be offline
	require.Eventually(
		t,
		check.FleetAgentStatusByAgentID(ctx, t, info.KibanaClient, agentID, "offline"),
		10*time.Minute,
		10*time.Second,
		"Elastic Agent status didn't go offline",
	)

	// Using a clean fixture to ensure that no previous state is used
	// re-enroll again and ensure that it all works again.
	fixture, err = define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	output, err = fixture.Install(ctx, &installOpts)
	if err != nil {
		t.Log(string(output))
		t.Fatalf("failed installing the agent again: %s", err)
	}

	t.Logf(">>> Enroll succeeded again. Output: %s", output)

	// Wait for Agent to be healthy
	require.Eventually(
		t,
		check.FleetAgentStatusByAgentID(ctx, t, info.KibanaClient, agentID, "online"),
		10*time.Minute,
		10*time.Second,
		"Elastic Agent status is not online again",
	)
}
