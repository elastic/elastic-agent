// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/internal/pkg/agent/cmd"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/testing/integration"
)

type AssertFunc func(*testing.T, *atesting.Fixture, string, error)

type testCase struct {
	description string
	privileged  bool
	os          []define.OS
	assertion   AssertFunc
}

// TestReEnrollUnprivileged verifies that re-enrollment as a privileged user fails
// when the agent was installed unprivileged. This enforces the file ownership check
// on Unix platforms. On Windows, this check is a no-op as of PR #8503, so this test
// is not run for windows. See the discussion in PR #8503 (https://github.com/elastic/elastic-agent/pull/8503)
// and comment (https://github.com/elastic/elastic-agent/pull/8503#discussion_r2152603141) for context.
func TestReEnrollUnprivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Stack: &define.Stack{},
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Darwin},
			{Type: define.Linux},
		},
	})

	ctx := t.Context()

	fixture, enrollArgs := prepareAgentforReEnroll(t, ctx, info, false)

	out, err := fixture.Exec(ctx, enrollArgs)
	require.Error(t, err)
	require.Contains(t, string(out), cmd.UserOwnerMismatchError.Error())

	assert.Eventuallyf(t, func() bool {
		err := fixture.IsHealthy(t.Context())
		return err == nil
	},
		2*time.Minute, time.Second,
		"Elastic-Agent did not report healthy. Agent status error: \"%v\"",
		err,
	)
}

func TestReEnrollPrivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Stack: &define.Stack{},
		Sudo:  true,
	})

	ctx := t.Context()

	fixture, enrollArgs := prepareAgentforReEnroll(t, ctx, info, true)
	_, err := fixture.Exec(ctx, enrollArgs)
	require.NoError(t, err)

	assert.Eventuallyf(t, func() bool {
		err := fixture.IsHealthy(t.Context())
		return err == nil
	},
		2*time.Minute, time.Second,
		"Elastic-Agent did not report healthy. Agent status error: \"%v\"",
		err,
	)
}

func prepareAgentforReEnroll(t *testing.T, ctx context.Context, info *define.Info, privileged bool) (*atesting.Fixture, []string) {
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

	err = tools.InstallAgentForPolicyWithToken(ctx, t, installOpts, fixture, info.KibanaClient, policy.ID, enrollmentApiKey)
	require.NoError(t, err)

	enrollUrl, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err)

	return fixture, []string{"enroll", "--url", enrollUrl, "--enrollment-token", enrollmentApiKey.APIKey, "--force"}
}
