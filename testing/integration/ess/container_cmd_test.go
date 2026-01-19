// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	"github.com/elastic/elastic-agent/pkg/core/process"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/testing/integration"
)

func createPolicy(
	t *testing.T,
	ctx context.Context,
	agentFixture *atesting.Fixture,
	info *define.Info,
	policyName string,
	dataOutputID string,
) (string, string) {
	createPolicyReq := kibana.AgentPolicy{
		Name:        policyName,
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

	if dataOutputID != "" {
		createPolicyReq.DataOutputID = dataOutputID
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

	return policy.ID, enrollmentToken.APIKey
}

func prepareAgentCMD(
	t *testing.T,
	ctx context.Context,
	agentFixture *atesting.Fixture,
	args []string,
	env []string,
) (*exec.Cmd, *strings.Builder) {
	cmd, err := agentFixture.PrepareAgentCommand(ctx, args)
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
	return cmd, &agentOutput
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

	// prepare must be called otherwise `agentFixture.WorkDir()` will be empty
	// and it must be set so the `STATE_PATH` below gets a valid path.
	err = agentFixture.Prepare(ctx)
	require.NoError(t, err)

	fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	if err != nil {
		t.Fatalf("could not get Fleet URL: %s", err)
	}

	_, enrollmentToken := createPolicy(
		t,
		ctx,
		agentFixture,
		info,
		fmt.Sprintf("%s-%s", t.Name(), uuid.Must(uuid.NewV4()).String()),
		"")
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

	cmd, agentOutput := prepareAgentCMD(t, ctx, agentFixture, []string{"container"}, env)
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
		err = agentFixture.IsHealthy(ctx, atesting.WithCmdOptions(withEnv(env)))
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

			_, enrollmentToken := createPolicy(
				t,
				ctx,
				agentFixture,
				info,
				fmt.Sprintf("test-policy-enroll-%s", uuid.Must(uuid.NewV4()).String()),
				"")

			env := []string{
				"FLEET_ENROLL=1",
				"FLEET_URL=" + fleetURL,
				"FLEET_ENROLLMENT_TOKEN=" + enrollmentToken,
				"STATE_PATH=" + tc.statePath,
			}

			cmd, agentOutput := prepareAgentCMD(t, ctx, agentFixture, []string{"container"}, env)
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
				err = agentFixture.IsHealthy(ctx, atesting.WithCmdOptions(withEnv(env)))
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
			containerPaths := filepath.Join(tc.expectedStatePath, "container-paths.yml")
			if _, err := os.Stat(tc.expectedSocketPath); err != nil {
				t.Errorf("cannot stat expected container-paths.yml path ('%s'): %s", containerPaths, err)
			}

			if t.Failed() {
				containerPathsContent, err := os.ReadFile(containerPaths)
				if err != nil {
					t.Fatalf("could not read container-paths.yml: %s", err)
				}

				t.Log("contents of 'container-paths-yml'")
				t.Log(string(containerPathsContent))
			}
		})
	}
}

func withEnv(env []string) process.CmdOption {
	return func(c *exec.Cmd) error {
		c.Env = append(os.Environ(), env...)
		return nil
	}
}

func TestContainerCMDEventToStderr(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
		Group: "container",
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// We call agentFixture.Prepare to set the workdir
	require.NoError(t, agentFixture.Prepare(ctx), "failed preparing agent fixture")

	_, outputID := createMockESOutput(t, info, 0, 0, 100, 0)
	policyID, enrollmentAPIKey := createPolicy(
		t,
		ctx,
		agentFixture,
		info,
		fmt.Sprintf("%s-%s", t.Name(), uuid.Must(uuid.NewV4()).String()),
		outputID)

	fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	if err != nil {
		t.Fatalf("could not get Fleet URL: %s", err)
	}

	env := []string{
		"FLEET_ENROLL=1",
		"FLEET_URL=" + fleetURL,
		"FLEET_ENROLLMENT_TOKEN=" + enrollmentAPIKey,
		"STATE_PATH=" + agentFixture.WorkDir(),
		// That is what we're interested in testing
		"EVENTS_TO_STDERR=true",
	}

	cmd, agentOutput := prepareAgentCMD(t, ctx, agentFixture, []string{"container"}, env)
	addLogIntegration(t, info, policyID, "/tmp/flog.log")
	integration.GenerateLogFile(t, "/tmp/flog.log", time.Second/2, 100)

	t.Logf(">> running binary with: %v", cmd.Args)
	if err := cmd.Start(); err != nil {
		t.Fatalf("error running container cmd: %s", err)
	}

	assert.Eventuallyf(t, func() bool {
		// This will return errors until it connects to the agent,
		// they're mostly noise because until the agent starts running
		// we will get connection errors. If the test fails
		// the agent logs will be present in the error message
		// which should help to explain why the agent was not
		// healthy.
		err := agentFixture.IsHealthy(ctx, atesting.WithCmdOptions(withEnv(env)))
		return err == nil
	},
		2*time.Minute, time.Second,
		"Elastic-Agent did not report healthy. Agent status error: \"%v\", Agent logs\n%s",
		err, agentOutput,
	)

	assert.Eventually(t, func() bool {
		agentOutputStr := agentOutput.String()
		scanner := bufio.NewScanner(strings.NewReader(agentOutputStr))
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "Cannot index event") {
				return true
			}
		}

		return false
	}, 3*time.Minute, 10*time.Second, "cannot find events on stderr")
}

// createMockESOutput creates an output configuration pointing to a mockES
// started in a random port and a cleanup function is registered to close
// the server at the end of the test.
// The server will respond with the passed error probabilities. If they add
// up to zero, all requests are a success.
func createMockESOutput(t *testing.T, info *define.Info, percentDuplicate, percentTooMany, percentNonIndex, percentTooLarge uint) (string, string) {
	mockesURL := integration.StartMockES(t, percentDuplicate, percentTooMany, percentNonIndex, percentTooLarge)
	createOutputBody := `
{
  "id": "mock-es-%[1]s",
  "name": "mock-es-%[1]s",
  "type": "elasticsearch",
  "is_default": false,
  "hosts": [
    "%s"
  ],
  "preset": "latency"
}
`
	// The API will return an error if the output ID/name contains an
	// UUID substring, so we replace the '-' by '_' to keep the API happy.
	outputUUID := strings.ReplaceAll(uuid.Must(uuid.NewV4()).String(), "-", "_")
	bodyStr := fmt.Sprintf(createOutputBody, outputUUID, mockesURL)
	bodyReader := strings.NewReader(bodyStr)
	// THE URL IS MISSING
	status, result, err := info.KibanaClient.Request(http.MethodPost, "/api/fleet/outputs", nil, nil, bodyReader)
	if err != nil {
		t.Fatalf("could execute request to create output: %#v, status: %d, result:\n%s\nBody:\n%s", err, status, string(result), bodyStr)
	}
	if status != http.StatusOK {
		t.Fatalf("creating output failed. Status code %d, response\n:%s", status, string(result))
	}

	outputResp := struct {
		Item struct {
			ID                  string   `json:"id"`
			Name                string   `json:"name"`
			Type                string   `json:"type"`
			IsDefault           bool     `json:"is_default"`
			Hosts               []string `json:"hosts"`
			Preset              string   `json:"preset"`
			IsDefaultMonitoring bool     `json:"is_default_monitoring"`
		} `json:"item"`
	}{}

	if err := json.Unmarshal(result, &outputResp); err != nil {
		t.Errorf("could not decode create output response: %s", err)
		t.Logf("Response:\n%s", string(result))
	}

	return mockesURL, outputResp.Item.ID
}

// TestContainerCMDAgentMonitoringRuntimeExperimental tests that when
// AGENT_MONITORING_RUNTIME_EXPERIMENTAL is set, Elastic Agent uses the
// respective runtime to run the agent.monitoring components from the
// local configuration.
func TestContainerCMDAgentMonitoringRuntimeExperimental(t *testing.T) {
	define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
		Group: "container",
	})

	testCases := []struct {
		name                      string
		agentMonitoringRuntimeEnv string
		expectedRuntimeName       string
	}{
		{
			name:                      "var set to otel",
			agentMonitoringRuntimeEnv: monitoringCfg.OtelRuntimeManager,
			expectedRuntimeName:       string(monitoringCfg.OtelRuntimeManager),
		},
		{
			name:                      "var set to process",
			agentMonitoringRuntimeEnv: monitoringCfg.ProcessRuntimeManager,
			expectedRuntimeName:       string(monitoringCfg.ProcessRuntimeManager),
		},
		{
			name:                      "var set to invalid value",
			agentMonitoringRuntimeEnv: "invalid",
			expectedRuntimeName:       string(monitoringCfg.DefaultRuntimeManager),
		},
		{
			name:                      "var not set",
			agentMonitoringRuntimeEnv: "",
			expectedRuntimeName:       string(monitoringCfg.DefaultRuntimeManager),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
			defer cancel()

			agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
			require.NoError(t, err)

			err = agentFixture.Prepare(ctx)
			require.NoError(t, err)

			mockesURL := integration.StartMockES(t, 0, 0, 0, 0)

			// Create a local agent config file with monitoring enabled
			agentConfig := createSimpleAgentMonitoringConfig(t, agentFixture.WorkDir(), mockesURL)

			env := []string{
				"STATE_PATH=" + agentFixture.WorkDir(),
			}

			// Set environment variable if specified
			if tc.agentMonitoringRuntimeEnv != "" {
				env = append(env, "AGENT_MONITORING_RUNTIME_EXPERIMENTAL="+tc.agentMonitoringRuntimeEnv)
			}

			cmd, agentOutput := prepareAgentCMD(t, ctx, agentFixture, []string{"container", "-c", agentConfig}, env)
			t.Logf(">> running binary with: %v", cmd.Args)
			if err := cmd.Start(); err != nil {
				t.Fatalf("error running container cmd: %s", err)
			}

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				err = agentFixture.IsHealthy(ctx, atesting.WithCmdOptions(withEnv(env)))
				require.NoError(ct, err)
			},
				2*time.Minute, time.Second,
				"Elastic-Agent did not report healthy. Agent status error: \"%v\", Agent logs\n%s",
				err, agentOutput,
			)

			// Verify that components are using the expected runtime
			require.EventuallyWithTf(t, func(ct *assert.CollectT) {
				status, err := agentFixture.ExecStatus(ctx, atesting.WithCmdOptions(withEnv(env)))
				require.NoErrorf(ct, err, "error getting agent status")

				expectedComponentCount := 4

				require.Len(ct, status.Components, expectedComponentCount, "expected right number of components in agent status")

				for _, comp := range status.Components {
					var compRuntime string
					switch comp.VersionInfo.Name {
					case "beats-receiver":
						compRuntime = string(component.OtelRuntimeManager)
					case "beat-v2-client":
						compRuntime = string(component.ProcessRuntimeManager)
					}
					t.Logf("Component ID: %s, version info: %s, runtime: %s", comp.ID, comp.VersionInfo.Name, compRuntime)
					switch comp.ID {
					case "beat/metrics-monitoring", "filestream-monitoring":
						// Monitoring components should use the expected runtime
						assert.Equalf(ct, tc.expectedRuntimeName, compRuntime, "expected correct runtime name for monitoring component %s with id %s", comp.Name, comp.ID)
					case "http/metrics-monitoring":
						// The comp.VersionInfo.Name for this component is empty at times.
						// See https://github.com/elastic/elastic-agent/issues/11162.
					default:
						// Non-monitoring components are not controlled by the env variable
						continue
					}
				}
			}, 1*time.Minute, 1*time.Second,
				"components did not use expected runtime",
			)
		})
	}
}

// TestContainerCMDAgentMonitoringRuntimeExperimentalPolicy tests that when
// AGENT_MONITORING_RUNTIME_EXPERIMENTAL is set, the agent.monitoring
// from the fleet policy takes precedence over the environment variable.
func TestContainerCMDAgentMonitoringRuntimeExperimentalPolicy(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
		Group: "container",
	})

	testCases := []struct {
		name                      string
		agentMonitoringRuntimeEnv string
		expectedRuntimeName       string
	}{
		{
			name:                      "var set to otel",
			agentMonitoringRuntimeEnv: monitoringCfg.OtelRuntimeManager,
			expectedRuntimeName:       string(monitoringCfg.ProcessRuntimeManager), // set by policy
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
			defer cancel()

			agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
			require.NoError(t, err)

			err = agentFixture.Prepare(ctx)
			require.NoError(t, err)

			fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
			if err != nil {
				t.Fatalf("could not get Fleet URL: %s", err)
			}

			policyName := fmt.Sprintf("test-beats-receivers-monitoring-%s-%s", tc.name, uuid.Must(uuid.NewV4()).String())
			policyID, enrollmentToken := createPolicy(
				t,
				ctx,
				agentFixture,
				info,
				policyName,
				"")

			addLogIntegration(t, info, policyID, "/tmp/beats-receivers-test.log")
			integration.GenerateLogFile(t, "/tmp/beats-receivers-test.log", time.Second/2, 50)

			// set monitoring runtime to process via policy
			setAgentMonitoringRuntime(t, info, policyID, policyName, monitoringCfg.ProcessRuntimeManager)

			env := []string{
				"FLEET_ENROLL=1",
				"FLEET_URL=" + fleetURL,
				"FLEET_ENROLLMENT_TOKEN=" + enrollmentToken,
				"STATE_PATH=" + agentFixture.WorkDir(),
			}

			// Set environment variable if specified
			if tc.agentMonitoringRuntimeEnv != "" {
				env = append(env, "AGENT_MONITORING_RUNTIME_EXPERIMENTAL="+tc.agentMonitoringRuntimeEnv)
			}

			cmd, agentOutput := prepareAgentCMD(t, ctx, agentFixture, []string{"container"}, env)
			t.Logf(">> running binary with: %v", cmd.Args)
			if err := cmd.Start(); err != nil {
				t.Fatalf("error running container cmd: %s", err)
			}

			require.EventuallyWithT(t, func(ct *assert.CollectT) {
				err = agentFixture.IsHealthy(ctx, atesting.WithCmdOptions(withEnv(env)))
				require.NoError(ct, err)
			},
				2*time.Minute, time.Second,
				"Elastic-Agent did not report healthy. Agent status error: \"%v\", Agent logs\n%s",
				err, agentOutput,
			)

			// Verify that components are using the expected runtime
			require.EventuallyWithTf(t, func(ct *assert.CollectT) {
				status, err := agentFixture.ExecStatus(ctx, atesting.WithCmdOptions(withEnv(env)))
				require.NoErrorf(ct, err, "error getting agent status")

				expectedComponentCount := 4

				require.Len(ct, status.Components, expectedComponentCount, "expected right number of components in agent status")

				for _, comp := range status.Components {
					var compRuntime string
					switch comp.VersionInfo.Name {
					case "beats-receiver":
						compRuntime = string(component.OtelRuntimeManager)
					case "beat-v2-client":
						compRuntime = string(component.ProcessRuntimeManager)
					}
					t.Logf("Component ID: %s, version info: %s, runtime: %s", comp.ID, comp.VersionInfo.Name, compRuntime)
					switch comp.ID {
					case "beat/metrics-monitoring", "filestream-monitoring", "prometheus/metrics-monitoring":
						// Monitoring components should use the expected runtime
						assert.Equalf(ct, tc.expectedRuntimeName, compRuntime, "unexpected runtime name for monitoring component %s with id %s", comp.Name, comp.ID)
					case "http/metrics-monitoring":
						// The comp.VersionInfo.Name for this component is empty at times.
						// See https://github.com/elastic/elastic-agent/issues/11162.
					default:
						// Non-monitoring components should use the default runtime
						assert.Equalf(ct, string(component.DefaultRuntimeManager), compRuntime, "expected default runtime for non-monitoring component %s with id %s", comp.Name, comp.ID)
					}
				}
			}, 1*time.Minute, 1*time.Second,
				"components did not use expected runtime",
			)
		})
	}
}

func addLogIntegration(t *testing.T, info *define.Info, policyID, logFilePath string) {
	agentPolicyBuilder := strings.Builder{}
	tmpl, err := template.New(t.Name() + "custom-log-policy").Parse(integration.PolicyJSON)
	if err != nil {
		t.Fatalf("cannot parse template: %s", err)
	}

	err = tmpl.Execute(&agentPolicyBuilder, integration.PolicyVars{
		Name:        "Log-Input-" + t.Name() + "-" + time.Now().Format(time.RFC3339),
		PolicyID:    policyID,
		LogFilePath: logFilePath,
		Dataset:     "logs",
		Namespace:   "default",
	})
	if err != nil {
		t.Fatalf("could not render template: %s", err)
	}
	// We keep a copy of the policy for debugging prurposes
	agentPolicy := agentPolicyBuilder.String()

	// Call Kibana to create the policy.
	// Docs: https://www.elastic.co/guide/en/fleet/current/fleet-api-docs.html#create-integration-policy-api
	resp, err := info.KibanaClient.Connection.Send(
		http.MethodPost,
		"/api/fleet/package_policies",
		nil,
		nil,
		bytes.NewBufferString(agentPolicy))
	if err != nil {
		t.Fatalf("could not execute request to Kibana/Fleet: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		// On error dump the whole request response so we can easily spot
		// what went wrong.
		t.Errorf("received a non 200-OK when adding package to policy. "+
			"Status code: %d", resp.StatusCode)
		respDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			t.Fatalf("could not dump error response from Kibana: %s", err)
		}
		// Make debugging as easy as possible
		t.Log("================================================================================")
		t.Log("Kibana error response:")
		t.Log(string(respDump))
		t.Log("================================================================================")
		t.Log("Rendered policy:")
		t.Log(agentPolicy)
		t.Log("================================================================================")
		t.FailNow()
	}
}

// createSimpleAgentMonitoringConfig creates a simple agent configuration file with monitoring enabled
func createSimpleAgentMonitoringConfig(t *testing.T, workDir string, esAddr string) string {
	configTemplate := `
outputs:
  default:
    type: elasticsearch
    hosts:
      - %s

agent:
  logging:
    level: debug
  monitoring:
    enabled: true
    metrics: true
  internal:
    runtime:
      metricbeat:
        system/metrics: process

inputs:
  - id: system-metrics
    type: system/metrics
    use_output: default
    streams:
      - metricsets:
        - cpu
        data_stream.dataset: system.cpu
      - metricsets:
        - memory
        data_stream.dataset: system.memory
`

	config := fmt.Sprintf(configTemplate, esAddr)
	configPath := filepath.Join(workDir, "elastic-agent.yml")
	err := os.WriteFile(configPath, []byte(config), 0o644)
	if err != nil {
		t.Fatalf("failed to write agent config file: %s", err)
	}

	return configPath
}

func setAgentMonitoringRuntime(t *testing.T, info *define.Info, policyID string, policyName string, runtime string) {
	reqBody := fmt.Sprintf(`
{
  "name": "%s",
  "namespace": "default",
  "overrides": {
    "agent": {
      "monitoring": {
        "_runtime_experimental": "%s"
      }
    }
  }
}
`, policyName, runtime)

	status, result, err := info.KibanaClient.Request(
		http.MethodPut,
		fmt.Sprintf("/api/fleet/agent_policies/%s", policyID),
		nil,
		nil,
		bytes.NewBufferString(reqBody))
	if err != nil {
		t.Fatalf("could not execute request to update policy: %s", err)
	}
	if status != http.StatusOK {
		t.Fatalf("updating policy failed. Status code %d, response:\n%s", status, string(result))
	}

	t.Logf("Successfully set monitoring to process runtime for policy %s", policyID)
}

func TestContainerCMDEnrollByPolicyName(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Stack: &define.Stack{},
		Local: false,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux},
		},
		Group: "container",
	})

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	agentFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = agentFixture.Prepare(ctx)
	require.NoError(t, err)

	fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err)

	// Populate fleet with a lot of policies to test retrieval by name
	// Kibana's default page size is 20
	// Include the special characters that must be escapted \():<>"* in KQL in the name
	// See https://www.elastic.co/docs/reference/query-languages/kql
	t.Log("Populate fleet with extra policies")
	policyID := ""
	for i := 0; i < 30; i++ {
		policyID, _ = createPolicy(
			t,
			ctx,
			agentFixture,
			info,
			fmt.Sprintf("%s \\():<>\"* %s", t.Name(), uuid.Must(uuid.NewV4()).String()),
			"")
	}
	// Use the last ID to get the policy, we want the name
	resp, err := info.KibanaClient.GetPolicy(ctx, policyID)
	require.NoError(t, err)

	env := []string{
		"FLEET_ENROLL=1",
		"FLEET_URL=" + fleetURL,
		"KIBANA_FLEET_HOST=" + info.KibanaClient.Connection.URL,
		"FLEET_TOKEN_POLICY_NAME=" + resp.Name,
		"KIBANA_FLEET_USERNAME=" + info.KibanaClient.Connection.Username,
		"KIBANA_FLEET_PASSWORD=" + info.KibanaClient.Connection.Password,
		"STATE_PATH=" + agentFixture.WorkDir(),
	}
	cmd, agentOutput := prepareAgentCMD(t, ctx, agentFixture, []string{"container"}, env)
	t.Logf(">> running binary with: %v", cmd.Args)
	err = cmd.Start()
	require.NoError(t, err)

	require.EventuallyWithTf(t, func(c *assert.CollectT) {
		// This will return errors until it connects to the agent,
		// they're mostly noise because until the agent starts running
		// we will get connection errors. If the test fails
		// the agent logs will be present in the error message
		// which should help to explain why the agent was not
		// healthy.
		status, err := agentFixture.ExecStatus(ctx, atesting.WithCmdOptions(withEnv(env)))
		require.NoError(c, err)
		require.Equal(c, int(cproto.State_HEALTHY), status.State, "agent status is not healthy")
		require.Equal(c, int(cproto.State_HEALTHY), status.FleetState, "fleet state is not healthy")
	},
		5*time.Minute, time.Second,
		"Elastic-Agent did not report healthy. Agent status error: \"%v\", Agent logs\n%s",
		err, agentOutput,
	)
}

func TestContainerCMDDiagnosticsSocket(t *testing.T) {
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

	// prepare must be called otherwise `agentFixture.WorkDir()` will be empty
	// and it must be set so the `STATE_PATH` below gets a valid path.
	err = agentFixture.Prepare(ctx)
	require.NoError(t, err)

	fleetURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	if err != nil {
		t.Fatalf("could not get Fleet URL: %s", err)
	}

	_, enrollmentToken := createPolicy(
		t,
		ctx,
		agentFixture,
		info,
		fmt.Sprintf("%s-%s", t.Name(), uuid.Must(uuid.NewV4()).String()),
		"")

	// create a new state directory, as the tempDir might exceed socket path character limit (104 characters)
	stateDir, err := os.MkdirTemp("/tmp", "state*")
	t.Cleanup(func() {
		_ = os.RemoveAll(stateDir)
	})
	require.NoError(t, err)
	env := []string{
		"FLEET_ENROLL=1",
		"FLEET_URL=" + fleetURL,
		"FLEET_ENROLLMENT_TOKEN=" + enrollmentToken,
		// As the agent isn't built for a container, it's upgradable, triggering
		// the start of the upgrade watcher. If `STATE_PATH` isn't set, the
		// upgrade watcher will commence from a different path within the
		// container, distinct from the current execution path.
		"STATE_PATH=" + stateDir,
	}

	cmd, agentOutput := prepareAgentCMD(t, ctx, agentFixture, []string{"container"}, env)
	t.Logf(">> running binary with: %v", cmd.Args)
	if err := cmd.Start(); err != nil {
		t.Fatalf("error running container cmd: %s", err)
	}

	require.EventuallyWithT(t, func(tt *assert.CollectT) {
		require.Contains(tt, agentOutput.String(), "Diagnostics extension started")
		_, err := os.Stat(filepath.Join(stateDir, "data", "edot-diagnostics-extension.sock"))
		require.NoError(tt, err)
	},
		5*time.Minute, time.Second,
		"Elastic-Agent did not report healthy. Agent status error: \"%v\", Agent logs\n%s",
		err, agentOutput,
	)
}
