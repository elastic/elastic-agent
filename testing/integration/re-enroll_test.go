// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"testing"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

type testCase struct {
	description string
	privileged  bool
	os          []define.OS
	assertion   func(*testing.T, string, error)
}

func TestReEnrollUnprivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Darwin},
			{Type: define.Linux},
		},
	})
	testReEnroll(t, info, false, func(t *testing.T, out string, err error) {
		require.Error(t, err)
		require.Contains(t, string(out), cmd.UserOwnerMismatchError.Error())
	})
}

func TestReEnrollPrivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
		Sudo:  true,
	})
	testReEnroll(t, info, false, func(t *testing.T, _ string, err error) {
		require.NoError(t, err)
	})
}

func testReEnroll(t *testing.T, info *define.Info, privileged bool, assertFunc func(t *testing.T, output string, err error)) {
	ctx := context.Background()
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     privileged,
	}

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

	agentID, err := tools.InstallAgentForPolicyWithToken(ctx, t, installOpts, fixture, info.KibanaClient, enrollmentApiKey)
	require.NoError(t, err)

	_, err = info.KibanaClient.UnEnrollAgent(ctx, kibana.UnEnrollAgentRequest{ID: agentID})
	require.NoError(t, err)

	enrollUrl, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err)

	enrollArgs := []string{"enroll", "--url", enrollUrl, "--enrollment-token", enrollmentApiKey.APIKey, "--force"}

	out, err := fixture.Exec(ctx, enrollArgs)
	assertFunc(t, string(out), err)
}
