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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	if err != nil {
		t.Fatalf("could not get Fleet URL: %s", err)
	}

	testCases := map[string]struct {
		statePath          string
		expectedStatePath  string
		expectedSocketPath string
		expectError        bool
	}{
		"small path": { // Use the set path
			statePath:          filepath.Join(os.TempDir(), "foo", "bar"),
			expectedStatePath:  filepath.Join(os.TempDir(), "foo", "bar"),
			expectedSocketPath: "/tmp/foo/bar/data/smp7BzlzcwgrLK4PUxpu7G1O5UwV4adr.sock",
		},
		"no path set": { // Use the default path
			statePath:          "",
			expectedStatePath:  "/usr/share/elastic-agent/state",
			expectedSocketPath: "/usr/share/elastic-agent/state/data/Td8I7R-Zby36_zF_IOd9QVNlFblNEro3.sock",
		},
		"long path": { // Path too long to create a unix socket, it will use /tmp/elastic-agent
			statePath:          "/tmp/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expectedStatePath:  "/tmp/ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
			expectedSocketPath: "/tmp/elastic-agent/Xegnlbb8QDcqNLPzyf2l8PhVHjWvlQgZ.sock",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
			require.NoError(t, err)

			enrollmentToken := createPolicy(t, ctx, agentFixture, info)
			env := []string{
				"FLEET_ENROLL=1",
				"FLEET_URL=" + fleetURL,
				"FLEET_ENROLLMENT_TOKEN=" + enrollmentToken,
				"STATE_PATH=" + tc.statePath,
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
				1*time.Minute, time.Second,
				"Elastic-Agent did not report healthy. Agent status error: \"%v\", Agent logs\n%s",
				err, agentOutput,
			)

			t.Cleanup(func() {
				_ = os.RemoveAll(tc.expectedStatePath)
			})

			// Now that the Elastic-Agent is healthy, check that the control socket path
			// is the expected one
			if _, err := os.Stat(tc.expectedStatePath); err != nil {
				t.Errorf("cannot stat expected state path ('%s'): %s", tc.expectedStatePath, err)
			}
			if _, err := os.Stat(tc.expectedSocketPath); err != nil {
				t.Errorf("cannot stat expected socket path ('%s'): %s", tc.expectedSocketPath, err)
			}

			if t.Failed() {
				containerPaths, err := os.ReadFile(filepath.Join(agentFixture.WorkDir(), "container-paths.yml"))
				if err != nil {
					t.Fatalf("could not read container-paths.yml: %s", err)
				}

				t.Log("contents of 'container-paths-yml'")
				t.Log(string(containerPaths))
			}
		})
	}
}
