// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"testing"
	"time"

	integrationtest "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/testing/fleetservertest"
	"github.com/stretchr/testify/require"
)

func TestActionHandling(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Local: false,
		Sudo:  true,
	})

	// 1. A new actions list is delivered to the agent in the most recent checkin.
	// The agent restarts before the checkin body is processed. The actions should
	// be processed in the following checkin.
	t.Run("agent restarts before processing checkin body", func(t *testing.T) {
		testAgentRestartBeforeProcessingCheckinBody(t, info)
	})
}

func testAgentRestartBeforeProcessingCheckinBody(t *testing.T, info *define.Info) {
	ctx := t.Context()
	t.Log("Setup fake fleet-server")
	apiKey, policy := createBasicFleetPolicyData(t, "http://fleet-server:8220")
	checkinWithAcker := fleetservertest.NewCheckinActionsWithAcker()
	fleet := fleetservertest.NewServerWithHandlers(
		apiKey,
		"enrollmentToken",
		policy.AgentID,
		policy.PolicyID,
		checkinWithAcker.ActionsGenerator(),
		checkinWithAcker.Acker(),
		fleetservertest.WithRequestLog(t.Logf),
	)
	defer fleet.Close()
	policyChangeAction, err := fleetservertest.NewActionPolicyChangeWithFakeComponent("test-policy-change", fleetservertest.TmplPolicy{
		AgentID:    policy.AgentID,
		PolicyID:   policy.PolicyID,
		FleetHosts: []string{fleet.LocalhostURL},
	})
	require.NoError(t, err)
	checkinWithAcker.AddCheckin("token", 0, policyChangeAction)

	t.Log("Enroll agent in fake fleet-server")
	fixture, err := define.NewFixtureFromLocalBuild(t,
		define.Version(),
		integrationtest.WithAllowErrors(),
		integrationtest.WithLogOutput())
	require.NoError(t, err, "SetupTest: NewFixtureFromLocalBuild failed")
	err = fixture.EnsurePrepared(ctx)
	require.NoError(t, err, "SetupTest: fixture.Prepare failed")

	out, err := fixture.Install(
		ctx,
		&integrationtest.InstallOpts{
			Force:          true,
			NonInteractive: true,
			Insecure:       true,
			Privileged:     false,
			EnrollOpts: integrationtest.EnrollOpts{
				URL:             fleet.LocalhostURL,
				EnrollmentToken: "anythingWillDO",
			}})
	require.NoErrorf(t, err, "Error when installing agent, output: %s", out)
	check.ConnectedToFleet(ctx, t, fixture, 5*time.Minute)

	// wait until the agent acknowledges the policy change
	require.Eventually(t, func() bool {
		return checkinWithAcker.Acked(policyChangeAction.ActionID)
	}, time.Minute, time.Second)
}
