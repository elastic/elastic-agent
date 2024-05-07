// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/check"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
)

func TestDelayEnroll(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS:    []define.OS{{Type: define.Linux}},
	})

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(10*time.Minute))
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// 1. Create a policy in Fleet with monitoring enabled.
	// To ensure there are no conflicts with previous test runs against
	// the same ESS stack, we add the current time at the end of the policy
	// name. This policy does not contain any integration.
	t.Log("Enrolling agent in Fleet with a test policy")
	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-enroll-%s", uuid.New().String()),
		Namespace:   info.Namespace,
		Description: "test policy for agent enrollment",
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		AgentFeatures: []map[string]interface{}{
			{
				"name":    "test_enroll",
				"enabled": true,
			},
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		DelayEnroll:    true,
	}
	// Install the Elastic-Agent with the policy that was just
	// created.
	_, err = tools.InstallAgentWithPolicy(
		ctx,
		t,
		installOpts,
		agentFixture,
		info.KibanaClient,
		createPolicyReq)
	require.NoError(t, err)

	// Start elastic-agent via service, this should do the enrollment
	cmd := exec.Command("/usr/bin/systemctl", "start", "elastic-agent")
	stdErrStdout, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "systemctl start elastic-agent output was %s", stdErrStdout)

	// check to make sure enroll worked
	check.ConnectedToFleet(ctx, t, agentFixture, 5*time.Minute)

}
