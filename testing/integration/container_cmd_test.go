// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
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
		OS: []define.OS{
			{Type: define.Linux},
		},
		// This test runs the command we use when executing inside a container
		// which leaves files under /usr/share/elastic-agent. Run it isolated
		// to avoid interfering with other tests and better simulate a container
		// environment we run it in isolation
		Group: "container",
	})
	ctx := context.Background()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

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

	fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	if err != nil {
		t.Fatalf("could not get Fleet URL: %s", err)
	}

	ctx, cancel := context.WithTimeout(ctx, 1*time.Minute)
	defer cancel()
	cmd, err := agentFixture.PrepareAgentCommand(ctx, []string{"container"})
	if err != nil {
		t.Fatalf("could not prepare agent command: %s", err)
	}

	t.Cleanup(func() {
		if cmd.Process != nil {
			t.Log(">> cleaning up: killing the Elastic-Agent process")
			if err := cmd.Process.Kill(); err != nil {
				t.Fatalf("could not kill Elastic-Agent process: %s", err)
			}
			return
		}
		t.Log(">> cleaning up: no process to kill")
	})

	agentOutput := strings.Builder{}
	cmd.Stderr = &agentOutput
	cmd.Stdout = &agentOutput
	cmd.Env = append(os.Environ(),
		"FLEET_ENROLL=1",
		"FLEET_URL="+fleetURL,
		"FLEET_ENROLLMENT_TOKEN="+enrollmentToken.APIKey,
		// As the agent isn't built for a container, it's upgradable, triggering
		// the start of the upgrade watcher. If `STATE_PATH` isn't set, the
		// upgrade watcher will commence from a different path within the
		// container, distinct from the current execution path.
		"STATE_PATH="+agentFixture.WorkDir(),
	)

	t.Logf(">> running binary with: %v", cmd.Args)
	if err := cmd.Start(); err != nil {
		t.Fatalf("error running container cmd: %s", err)
	}

	require.Eventuallyf(t, func() bool {
		// This will return errors until it connects to the agent,
		// they're mostly noise because until the agent starts running
		// we will get connection errors. If the test fails
		// the agent logs will be present in the error message
		// which should help to explain why the agent was not
		// healthy.
		err = agentFixture.IsHealthy(ctx)
		return err == nil
	},
		5*time.Minute, time.Second,
		"Elastic-Agent did not report healthy. Agent status error: \"%v\", Agent logs\n%s",
		err, &agentOutput,
	)
}
