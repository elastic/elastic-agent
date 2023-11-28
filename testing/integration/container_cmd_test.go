// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

func TestContainerCMD(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		// This test runs the command we use when executing inside a container
		// which leaves files under /usr/share/elastic-agent. Run it isolated
		// to avoid interfering with other tests and better simulate a container
		// environment we run it in isolation
		Isolate: true,
	})
	ctx := context.Background()

	agentFixture, err := define.NewFixture(t, define.Version())
	require.NoError(t, err)

	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("test-policy-enroll-%d", time.Now().Unix()),
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

	// Create policy
	policy, err := info.KibanaClient.CreatePolicy(ctx, createPolicyReq)
	if err != nil {
		t.Fatalf("could not create Agent Policy: %s", err)
	}

	// Create enrollment API key
	createEnrollmentAPIKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policy.ID,
	}

	t.Logf("Creating enrollment API key...")
	enrollmentToken, err := info.KibanaClient.CreateEnrollmentAPIKey(ctx, createEnrollmentAPIKeyReq)
	if err != nil {
		t.Fatalf("unable to create enrolment API key: %s", err)
	}

	fleetURL, err := fleettools.DefaultURL(info.KibanaClient)
	if err != nil {
		t.Fatalf("could not get Fleet URL: %s", err)
	}

	cmd, err := agentFixture.PrepareAgentCommand(ctx, []string{"container"})
	cmd.Env = append(os.Environ(), []string{
		"FLEET_ENROLL=1",
		"FLEET_URL=" + fleetURL,
		"FLEET_ENROLLMENT_TOKEN=" + enrollmentToken.APIKey,
	}...)

	t.Logf(">> running binary with: %v", cmd.Args)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("error running container cmd: %s", err)
		t.Log("Container command output:")
		t.Log(string(output))
		t.FailNow()
	}

	require.Eventually(t, func() bool {
		healthy, err := agentFixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("error checking agent health, retrying soon. Err: %s", err)
		}
		return healthy
	},
		3*time.Minute, 10*time.Second, "Elastic-Agent did not report healthy",
	)
}
