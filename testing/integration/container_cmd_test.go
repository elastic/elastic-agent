// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

func createPolicy(t *testing.T, ctx context.Context, agentFixture *atesting.Fixture, info *define.Info) string {
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

	return enrollmentToken.APIKey
}

func prepareContainerCMD(t *testing.T, ctx context.Context, agentFixture *atesting.Fixture, info *define.Info, env []string) *exec.Cmd {
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

			// Kill does not wait for the process to finish, so we wait here
			state, err := cmd.Process.Wait()
			if err != nil {
				t.Errorf("Elastic-Agent exited with error after kill signal: %s", err)
				t.Errorf("Elastic-Agent exited with status %d", state.ExitCode())
				out, err := cmd.CombinedOutput()
				if err == nil {
					t.Log(string(out))
				}
			}

			return
		}
		t.Log(">> cleaning up: no process to kill")
	})

	agentOutput := strings.Builder{}
	cmd.Stderr = &agentOutput
	cmd.Stdout = &agentOutput
	cmd.Env = append(os.Environ(), env...)
	return cmd
}

func TestContainerCMD(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
		Group: "container",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	if err != nil {
		t.Fatalf("could not get Fleet URL: %s", err)
	}

	enrollmentToken := createPolicy(t, ctx, agentFixture, info)
	env := []string{
		"FLEET_ENROLL=1",
		"FLEET_URL=" + fleetURL,
		"FLEET_ENROLLMENT_TOKEN=" + enrollmentToken,
		// As the agent isn't built for a container, it's upgradable, triggering
		// the start of the upgrade watcher. If `STATE_PATH` isn't set, the
		// upgrade watcher will commence from a different path within the
		// container, distinct from the current execution path.
		"STATE_PATH=" + agentFixture.WorkDir(),
	}

	cmd := prepareContainerCMD(t, ctx, agentFixture, info, env)
	t.Logf(">> running binary with: %v", cmd.Args)
	if err := cmd.Start(); err != nil {
		t.Fatalf("error running container cmd: %s", err)
	}

	agentOutput := cmd.Stderr.(*strings.Builder)

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
		err, agentOutput,
	)
}

func TestContainerCMDWithAVeryLongStatePath(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
		Group: "container",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	if err != nil {
		t.Fatalf("could not get Fleet URL: %s", err)
	}

	// We need a statePath that will make the unix socket path longer than 105 characters
	// so we join the workdir and a 120 characters long string.
	statePath := filepath.Join(agentFixture.WorkDir(), "de9a2a338c4fe10a466ee9fae57ce0c8a5b010dfcd6bd3f41d2c569ef5ed873193fd7d1966a070174f47f93ee667f921616c2d6d29efb6dbcc2b8b33")

	// We know it will use the OS temp folder for the state path, so we try
	// to clean it up at the end of the test.
	t.Cleanup(func() {
		defaultStatePath := "/tmp/elastic-agent"
		if err := os.RemoveAll(defaultStatePath); err != nil {
			t.Errorf("could not remove config path '%s': %s", defaultStatePath, err)
		}
	})

	enrollmentToken := createPolicy(t, ctx, agentFixture, info)
	env := []string{
		"FLEET_ENROLL=1",
		"FLEET_URL=" + fleetURL,
		"FLEET_ENROLLMENT_TOKEN=" + enrollmentToken,
		// As the agent isn't built for a container, it's upgradable, triggering
		// the start of the upgrade watcher. If `STATE_PATH` isn't set, the
		// upgrade watcher will commence from a different path within the
		// container, distinct from the current execution path.
		"STATE_PATH=" + statePath,
	}

	cmd := prepareContainerCMD(t, ctx, agentFixture, info, env)
	t.Logf(">> running binary with: %v", cmd.Args)
	if err := cmd.Start(); err != nil {
		t.Fatalf("error running container cmd: %s", err)
	}

	agentOutput := cmd.Stderr.(*strings.Builder)

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
		err, agentOutput,
	)
}
