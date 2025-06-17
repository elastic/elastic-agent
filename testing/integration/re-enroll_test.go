// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
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
)

type AssertFunc func(*testing.T, *atesting.Fixture, string, error)

type testCase struct {
	description string
	privileged  bool
	os          []define.OS
	assertion   AssertFunc
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

	testReEnroll(t, info, false, func(t *testing.T, fixture *atesting.Fixture, out string, err error) {
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
	})
}

func TestReEnrollPrivileged(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Stack: &define.Stack{},
		Sudo:  true,
	})
	testReEnroll(t, info, true, func(t *testing.T, fixture *atesting.Fixture, _ string, err error) {
		require.NoError(t, err)
		assert.Eventuallyf(t, func() bool {
			err := fixture.IsHealthy(t.Context())
			return err == nil
		},
			2*time.Minute, time.Second,
			"Elastic-Agent did not report healthy. Agent status error: \"%v\"",
			err,
		)
	})
}

func testReEnroll(t *testing.T, info *define.Info, privileged bool, assertFunc AssertFunc) {
	ctx := t.Context()
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
	assertFunc(t, fixture, string(out), err)
}
