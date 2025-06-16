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

func TestRenEnroll(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
		Sudo:  true,
	})

	testCases := []struct {
		description string
		privileged  bool
		assertion   func(*testing.T, string, error)
	}{
		{
			description: "root user is prevented from re-enrolling an unprivileged agent",
			privileged:  false,
			assertion: func(t *testing.T, out string, err error) {
				require.Error(t, err)
				require.Contains(t, string(out), cmd.UserOwnerMismatchError.Error())
			},
		},
		{
			description: "unenrolled privileged agent re-enrolls successfully using root user",
			privileged:  false,
			assertion: func(t *testing.T, _ string, err error) {
				require.NoError(t, err)
			},
		},
	}

	for _, test := range testCases {
		testReEnroll(t, info, test.privileged, test.assertion)
	}
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

// func TestReEnrollUnprivileged(t *testing.T) {
// 	if runtime.GOOS == "windows" {
// 		t.Skip("Skipping test on Windows")
// 	}
//
// 	info := define.Require(t, define.Requirements{
// 		Group: Default,
// 		Stack: &define.Stack{},
// 		Sudo:  true,
// 	})
// 	t.Run("root user is prevented from re-enrolling an unprivileged agent", func(t *testing.T) {
// 		testReEnroll(t, info, false)
// 	})
// }
//
// func TestReEnrollPrivileged(t *testing.T) {
// 	info := define.Require(t, define.Requirements{
// 		Group: Default,
// 		Stack: &define.Stack{},
// 		Sudo:  true,
// 	})
// 	t.Run("unenrolled privileged agent re-enrolls successfully using root user", func(t *testing.T) {
// 		testReEnroll(t, info, true)
// 	})
// }
