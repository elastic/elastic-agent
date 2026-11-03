// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/testing/integration"
)

const (
	completeImageEnv = "ELASTIC_AGENT_COMPLETE_IMAGE"

	// scheduleMissingErr is the Permanent failure message emitted by the OTel
	// heartbeatreceiver when Fleet browser.network / browser.screenshot streams
	// (which have no schedule) are treated as monitors. See elastic-agent#15968.
	scheduleMissingErr = "missing required field accessing 'heartbeat.monitors"
)

type HeartbeatRunner struct {
	suite.Suite
	info          *define.Info
	httpServer    *httptest.Server
	containerName string

	agentID    string
	policyID   string
	policyName string
}

func TestHeartbeatHTTPMonitor(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.HeartbeatComplete,
		Stack: &define.Stack{},
		Local: false, // requires elastic-agent-complete Docker image
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Linux, Arch: define.AMD64},
		},
	})

	suite.Run(t, &HeartbeatRunner{info: info})
}

func (runner *HeartbeatRunner) SetupSuite() {
	t := runner.T()

	completeImage := strings.TrimSpace(os.Getenv(completeImageEnv))
	require.NotEmpty(t, completeImage, "%s must be set", completeImageEnv)

	// Start a local HTTP server that always returns 200. Heartbeat will poll this.
	runner.httpServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	}))
	t.Cleanup(runner.httpServer.Close)

	policyUUID := uuid.Must(uuid.NewV4()).String()
	basePolicy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   runner.info.Namespace,
		Description: "Test policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}

	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Minute)
	defer cancel()

	// Exporter requests retain output parameters, but the Beatsauth endpoint used
	// by Heartbeat's monitor-state client must not include them.
	require.NoError(t, fleettools.UpdateESOutput(
		ctx,
		runner.info.KibanaClient,
		fleettools.DefaultFleetOutputID,
		fleettools.ElasticsearchOutputUpdate{
			Preset: fleettools.OutputPresetLatency,
			ConfigYAML: `parameters:
  pretty: "true"
`,
		},
	), "configuring the Fleet Elasticsearch output with query parameters")

	policyResp, err := runner.info.KibanaClient.CreatePolicy(ctx, basePolicy)
	require.NoError(t, err, "creating Fleet agent policy")

	enrollmentToken, err := tools.CreateEnrollmentToken(t, ctx, runner.info.KibanaClient, policyResp.ID)
	require.NoError(t, err, "creating Fleet enrollment token")

	fleetServerURL, err := fleettools.DefaultURL(ctx, runner.info.KibanaClient)
	require.NoError(t, err, "getting default Fleet Server URL")

	runner.policyID = policyResp.ID
	runner.policyName = policyResp.Name
	runner.startCompleteContainer(ctx, t, completeImage, fleetServerURL, enrollmentToken.APIKey, policyUUID)

	// Ensure Fleet observes the enrolled agent as online with complete=true metadata
	// before creating the Synthetics private location and monitors.
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		agent, getErr := getFleetAgent(ctx, runner.info.KibanaClient, runner.agentID)
		require.NoError(collect, getErr, "getting enrolled agent from Fleet")
		assert.True(collect, agent.Active, "expected Fleet agent to be active")
		assert.True(collect, agent.LocalMetadata.Elastic.Agent.Complete,
			"expected Fleet agent local_metadata.elastic.agent.complete to be true")
	}, 6*time.Minute, 5*time.Second, "Fleet did not observe complete metadata for enrolled agent")

	// Create a Synthetics private location backed by the Fleet policy so that
	// Kibana can push heartbeat monitors to the agent via Fleet.
	locationLabel := fmt.Sprintf("test-location-%s", policyUUID)
	locationID, err := createSyntheticsPrivateLocation(ctx, runner.info.KibanaClient, locationLabel, policyResp.ID)
	require.NoError(t, err, "creating Synthetics private location")

	tcpHost, err := hostPortFromURL(runner.httpServer.URL)
	require.NoError(t, err, "parsing host:port from test HTTP server URL")

	// Push HTTP, TCP, ICMP, and browser monitors via the UI API.
	// The project API (_bulk_update) is only available in certain Kibana
	// configurations; the UI API works on all stateful deployments.
	monitors := []map[string]any{
		{
			"type":              "http",
			"name":              "heartbeat-http-monitor-" + policyUUID,
			"enabled":           true,
			"private_locations": []string{locationID},
			"schedule":          1,
			"url":               runner.httpServer.URL,
		},
		{
			"type":              "tcp",
			"name":              "heartbeat-tcp-monitor-" + policyUUID,
			"enabled":           true,
			"private_locations": []string{locationID},
			"schedule":          1,
			"host":              tcpHost,
		},
		{
			"type":              "icmp",
			"name":              "heartbeat-icmp-monitor-" + policyUUID,
			"enabled":           true,
			"private_locations": []string{locationID},
			"schedule":          1,
			"host":              "127.0.0.1",
		},
		{
			"type":              "browser",
			"name":              "heartbeat-browser-monitor-" + policyUUID,
			"enabled":           true,
			"private_locations": []string{locationID},
			"schedule":          10,
			"inline_script":     `step("noop", async () => {});`,
		},
	}
	for _, monitor := range monitors {
		require.NoError(t, createSyntheticsUIMonitor(ctx, runner.info.KibanaClient, monitor),
			"creating %s monitor", monitor["type"])
	}
}

// validateHeartbeatEvents polls Elasticsearch until at least one heartbeat HTTP
// summary document with monitor state appears for the given agent, filtered to
// events after `since`. It returns the newest matching document.
func (runner *HeartbeatRunner) validateHeartbeatEvents(t *testing.T, ctx context.Context, agentID string, since time.Time) mapstr.M {
	now := time.Now()
	var query map[string]any
	var doc mapstr.M

	defer func() {
		if t.Failed() {
			bs, err := json.Marshal(query)
			if err != nil {
				t.Errorf("executed at %s: %v", now.Format(time.RFC3339Nano), query)
				return
			}
			t.Errorf("executed at %s: query: %s", now.Format(time.RFC3339Nano), string(bs))
		}
	}()

	t.Logf("querying ES for heartbeat events at %s", now.Format(time.RFC3339Nano))
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		query = genESQuery(agentID, [][]string{
			{"exists", "field", "monitor.status"},
			{"exists", "field", "state.id"},
			{"exists", "field", "state.started_at"},
			{"exists", "field", "state.checks"},
		})
		query["query"].(map[string]interface{})["bool"].(map[string]interface{})["filter"] = map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{"gte": since.UTC().Format("2006-01-02T15:04:05.000Z")},
			},
		}
		query["sort"] = []any{map[string]any{"@timestamp": map[string]any{"order": "desc"}}}
		now = time.Now()
		res, err := estools.PerformQueryForRawQuery(ctx, query, "synthetics-http*", runner.info.ESClient)
		require.NoError(collect, err)
		require.NotEmpty(collect, res.Hits.Hits)
		doc = res.Hits.Hits[0].Source
	}, 10*time.Minute, 10*time.Second, "could not fetch heartbeat HTTP events")
	return doc
}

func (runner *HeartbeatRunner) TestBeatsMetrics() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Minute)
	defer cancel()

	agentStatus, err := runner.execStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	testStart := time.Now()

	// Validate process mode
	var processDoc mapstr.M
	t.Run("process", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, statusErr := runner.execStatus(ctx)
			require.NoError(collect, statusErr)
			var foundProcess bool
			for _, comp := range status.Components {
				if strings.HasPrefix(comp.ID, "synthetics/http") &&
					comp.VersionInfo.Name == componentVersionInfoNameForRuntime(component.ProcessRuntimeManager) {
					assert.Equal(collect, int(cproto.State_HEALTHY), comp.State,
						"expected synthetics/http component to be healthy, got %s", cproto.State(comp.State)) //nolint:gosec // G115 always under 32-bit
					foundProcess = true
					break
				}
			}
			assert.True(collect, foundProcess, "expected a synthetics/http component to be running as a process")
		}, 2*time.Minute, 5*time.Second, "heartbeat component should be running as a process")

		processDoc = runner.validateHeartbeatEvents(t, ctx, agentStatus.Info.ID, testStart)

		t.Run("restores monitor state from Elasticsearch after restart", func(t *testing.T) {
			runner.validateMonitorStateAfterRestart(t, ctx, agentStatus.Info.ID, processDoc)
		})
	})

	// Switch to OTel runtime and validate the same data
	var otelDoc mapstr.M
	t.Run("otel", func(t *testing.T) {
		otelSince := time.Now()
		policyRevision := switchPolicyToOtelRuntime(ctx, t, runner.info.KibanaClient, runner.policyID, runner.policyName, runner.info.Namespace)

		// Wait for the agent to apply the new policy revision
		require.Eventually(t, tools.IsPolicyRevision(ctx, t, runner.info.KibanaClient, runner.agentID, policyRevision),
			5*time.Minute, time.Second)

		// Verify that every Synthetics monitor type pushed via Fleet (http, tcp,
		// icmp, browser) runs as a healthy OTel beats receiver and does not fail
		// for missing schedule (#15968).
		otelName := componentVersionInfoNameForRuntime(component.OtelRuntimeManager)
		for _, monitorType := range []string{"http", "tcp", "icmp", "browser"} {
			t.Run(monitorType, func(t *testing.T) {
				componentPrefix := "synthetics/" + monitorType
				require.EventuallyWithT(t, func(collect *assert.CollectT) {
					status, statusErr := runner.execStatus(ctx)
					require.NoError(collect, statusErr)

					var found bool
					for _, comp := range status.Components {
						if !strings.HasPrefix(comp.ID, componentPrefix) {
							continue
						}
						found = true

						assert.Equal(collect, otelName, comp.VersionInfo.Name,
							"expected %s to run as beats receiver (OTel), got %q; message=%q",
							componentPrefix, comp.VersionInfo.Name, comp.Message)
						assert.NotContains(collect, comp.Message, scheduleMissingErr,
							"OTel heartbeatreceiver must not fail for missing schedule (#15968); component=%s message=%q",
							comp.ID, comp.Message)
						for _, unit := range comp.Units {
							assert.NotContains(collect, unit.Message, scheduleMissingErr,
								"unit %s must not fail for missing schedule (#15968); message=%q",
								unit.UnitID, unit.Message)
						}
						assert.Equal(collect, int(cproto.State_HEALTHY), comp.State,
							"expected %s component to be healthy under OTel, got %s; message=%q",
							componentPrefix, cproto.State(comp.State), comp.Message) //nolint:gosec // G115 always under 32-bit
						break
					}
					assert.True(collect, found,
						"expected a %s component after creating a %s PL monitor", componentPrefix, monitorType)
				}, 5*time.Minute, 5*time.Second, "%s should be HEALTHY under OTel heartbeat", componentPrefix)
			})
		}

		otelDoc = runner.validateHeartbeatEvents(t, ctx, agentStatus.Info.ID, otelSince)

		t.Run("restores monitor state from Elasticsearch after restart", func(t *testing.T) {
			runner.validateMonitorStateAfterRestart(t, ctx, agentStatus.Info.ID, otelDoc)
		})
	})

	t.Run("compare", func(t *testing.T) {
		if processDoc == nil || otelDoc == nil {
			t.Skip("skipping comparison because a previous subtest failed")
		}
		AssertMapstrKeysEqual(t, processDoc, otelDoc, RuntimeComparisonIgnoredFields,
			"expected heartbeat document keys to be equal between process and otel modes")
	})
}

func (runner *HeartbeatRunner) validateMonitorStateAfterRestart(
	t *testing.T,
	ctx context.Context,
	agentID string,
	beforeRestartDoc mapstr.M,
) {
	t.Helper()

	stateIDBefore := heartbeatStateField(t, beforeRestartDoc, "state.id")
	stateStartedAtBefore := heartbeatStateField(t, beforeRestartDoc, "state.started_at")
	stateChecksBefore := heartbeatStateChecks(t, beforeRestartDoc)

	require.NoError(t, runner.restartAgent(ctx), "could not restart agent")
	restartedAt := time.Now()
	require.EventuallyWithT(
		t,
		func(collect *assert.CollectT) {
			assert.NoError(collect, runner.isAgentHealthy(ctx))
		},
		2*time.Minute, 5*time.Second, "agent did not become healthy after restart")

	afterRestartDoc := runner.validateHeartbeatEvents(t, ctx, agentID, restartedAt)

	assert.Equal(
		t,
		stateIDBefore,
		heartbeatStateField(t, afterRestartDoc, "state.id"),
		"Heartbeat should continue the monitor state loaded from Elasticsearch",
	)
	assert.Equal(
		t,
		stateStartedAtBefore,
		heartbeatStateField(t, afterRestartDoc, "state.started_at"),
		"Heartbeat should preserve the monitor state start time loaded from Elasticsearch",
	)
	assert.Greater(
		t,
		heartbeatStateChecks(t, afterRestartDoc),
		stateChecksBefore,
		"Heartbeat should continue incrementing the restored monitor state checks",
	)
}

func (runner *HeartbeatRunner) startCompleteContainer(
	ctx context.Context,
	t *testing.T,
	image string,
	fleetServerURL string,
	enrollmentToken string,
	policyUUID string,
) {
	t.Helper()

	containerName := "heartbeat-complete-" + policyUUID
	runner.containerName = containerName

	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.WithoutCancel(t.Context()), 2*time.Minute)
		defer cleanupCancel()

		collectDiagnostics, _ := strconv.ParseBool(os.Getenv("AGENT_COLLECT_DIAG"))
		if t.Failed() || collectDiagnostics {
			runner.collectContainerDiagnostics(cleanupCtx, t)
		}
		if out, err := dockerOutput(cleanupCtx, "rm", "-f", "-v", containerName); err != nil {
			t.Logf("failed removing container %s: %v\n%s", containerName, err, out)
		}
		if runner.agentID != "" {
			if err := fleettools.UnEnrollAgent(cleanupCtx, runner.info.KibanaClient, runner.agentID); err != nil {
				t.Logf("failed unenrolling agent %s: %v", runner.agentID, err)
			}
		}
	})

	// Run with host networking so localhost HTTP/TCP/ICMP targets and Fleet are
	// reachable, and preserve the image's default non-root user (browser monitors
	// refuse to run as root).
	out, err := dockerOutput(
		ctx,
		"run",
		"--detach",
		"--name", containerName,
		"--network", "host",
		"-e", "FLEET_ENROLL=1",
		"-e", "FLEET_URL="+fleetServerURL,
		"-e", "FLEET_ENROLLMENT_TOKEN="+enrollmentToken,
		image,
	)
	require.NoError(t, err, "starting elastic-agent-complete container: %s", out)

	var agentID string
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		status, statusErr := runner.execStatus(ctx)
		require.NoError(collect, statusErr, "getting container agent status")
		assert.Equal(collect, cproto.State_HEALTHY, cproto.State(status.FleetState), //nolint:gosec // G115 always under 32-bit
			"expected Fleet state to be HEALTHY, got %s (message=%q)", cproto.State(status.FleetState), status.FleetMessage) //nolint:gosec // G115 always under 32-bit
		assert.Equal(collect, cproto.State_HEALTHY, cproto.State(status.State), //nolint:gosec // G115 always under 32-bit
			"expected agent state to be HEALTHY, got %s (message=%q)", cproto.State(status.State), status.Message) //nolint:gosec // G115 always under 32-bit
		assert.NotEmpty(collect, status.Info.ID, "expected enrolled agent ID to be non-empty")
		agentID = status.Info.ID
	}, 5*time.Minute, 5*time.Second, "timed out waiting for container agent to enroll and become healthy")

	runner.agentID = agentID
	t.Logf("enrolled complete container agent ID: %s (container: %s)", agentID, containerName)
}

func (runner *HeartbeatRunner) execStatus(ctx context.Context) (atesting.AgentStatusOutput, error) {
	retryCtx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	var lastErr error
	for {
		if retryCtx.Err() != nil {
			if errors.Is(retryCtx.Err(), context.DeadlineExceeded) && lastErr != nil {
				return atesting.AgentStatusOutput{}, fmt.Errorf("agent status returned an error: %w", lastErr)
			}
			return atesting.AgentStatusOutput{}, fmt.Errorf("agent status failed: %w", retryCtx.Err())
		}

		cmd := exec.CommandContext(retryCtx, "docker", "exec", runner.containerName, "elastic-agent", "status", "--output", "json") //nolint:gosec // containerName is test-controlled
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		err := cmd.Run()

		var status atesting.AgentStatusOutput
		if uerr := json.Unmarshal(stdout.Bytes(), &status); uerr != nil {
			lastErr = fmt.Errorf("could not unmarshal agent status output: %w (stdout=%q stderr=%q)",
				errors.Join(uerr, err), stdout.String(), stderr.String())
		} else if status.IsZero() {
			lastErr = fmt.Errorf("agent status output is empty: %w (stderr=%q)", err, stderr.String())
		} else {
			return status, nil
		}

		select {
		case <-retryCtx.Done():
		case <-time.After(time.Second):
		}
	}
}

func (runner *HeartbeatRunner) restartAgent(ctx context.Context) error {
	out, err := dockerOutput(ctx, "restart", runner.containerName)
	if err != nil {
		return fmt.Errorf("restarting container %s: %w\n%s", runner.containerName, err, out)
	}
	return nil
}

func (runner *HeartbeatRunner) isAgentHealthy(ctx context.Context) error {
	status, err := runner.execStatus(ctx)
	if err != nil {
		return fmt.Errorf("agent status returned an error: %w", err)
	}
	if status.State != int(cproto.State_HEALTHY) {
		return fmt.Errorf("agent isn't healthy, current state: %s, full status: %+v",
			cproto.State(status.State), status) //nolint:gosec // G115 always under 32-bit
	}
	return nil
}

func (runner *HeartbeatRunner) collectContainerDiagnostics(ctx context.Context, t *testing.T) {
	t.Helper()

	diagnosticsDir, err := heartbeatDiagnosticsDir()
	if err != nil {
		t.Logf("failed preparing container diagnostics directory: %v", err)
		return
	}

	prefix := runner.containerName
	containerDiagnosticsPath := "/tmp/" + prefix + "-diagnostics.zip"
	diagnosticsCtx, diagnosticsCancel := context.WithTimeout(ctx, time.Minute)
	diagnosticsOutput, diagnosticsErr := dockerOutput(
		diagnosticsCtx,
		"exec", runner.containerName,
		"elastic-agent", "diagnostics", "-f", containerDiagnosticsPath,
	)
	diagnosticsCancel()
	writeDiagnosticOutput(
		t,
		filepath.Join(diagnosticsDir, prefix+"-diagnostics-command.log"),
		diagnosticsOutput,
		diagnosticsErr,
	)
	if diagnosticsErr == nil {
		hostDiagnosticsPath := filepath.Join(diagnosticsDir, prefix+"-diagnostics.zip")
		copyOutput, copyErr := dockerOutput(
			ctx,
			"cp", runner.containerName+":"+containerDiagnosticsPath, hostDiagnosticsPath,
		)
		if copyErr != nil {
			writeDiagnosticOutput(
				t,
				filepath.Join(diagnosticsDir, prefix+"-diagnostics-copy.log"),
				copyOutput,
				copyErr,
			)
		} else if err := os.Chmod(hostDiagnosticsPath, 0o644); err != nil {
			t.Logf("failed setting permissions on %s: %v", hostDiagnosticsPath, err)
		}
	}

	writeDockerCommandDiagnostic(ctx, t, filepath.Join(diagnosticsDir, prefix+"-docker-inspect.json"),
		"inspect", runner.containerName)
	writeDockerCommandDiagnostic(ctx, t, filepath.Join(diagnosticsDir, prefix+"-agent-status.log"),
		"exec", runner.containerName, "elastic-agent", "status", "--output", "full")
	writeDockerCommandDiagnostic(ctx, t, filepath.Join(diagnosticsDir, prefix+"-docker.log"),
		"logs", "--timestamps", runner.containerName)
}

func heartbeatDiagnosticsDir() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getting working directory: %w", err)
	}

	for {
		goModPath := filepath.Join(dir, "go.mod")
		info, statErr := os.Stat(goModPath)
		if statErr == nil && !info.IsDir() {
			diagnosticsDir := filepath.Join(dir, "build", "diagnostics")
			if err := os.MkdirAll(diagnosticsDir, 0o777); err != nil {
				return "", fmt.Errorf("creating diagnostics directory %s: %w", diagnosticsDir, err)
			}
			return diagnosticsDir, nil
		}
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return "", fmt.Errorf("checking project root at %s: %w", goModPath, statErr)
		}

		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("could not find project root containing go.mod")
		}
		dir = parent
	}
}

func writeDockerCommandDiagnostic(ctx context.Context, t *testing.T, path string, args ...string) {
	t.Helper()
	output, err := dockerOutput(ctx, args...)
	if filepath.Ext(path) == ".json" && err == nil {
		output = redactDockerInspect(output)
	}
	writeDiagnosticOutput(t, path, output, err)
}

func writeDiagnosticOutput(t *testing.T, path string, output []byte, commandErr error) {
	t.Helper()

	var contents bytes.Buffer
	if commandErr != nil {
		contents.WriteString("command error: " + commandErr.Error() + "\n")
	}
	contents.Write(output)
	if contents.Len() > 0 && contents.Bytes()[contents.Len()-1] != '\n' {
		contents.WriteByte('\n')
	}
	if err := os.WriteFile(path, contents.Bytes(), 0o644); err != nil {
		t.Logf("failed writing diagnostic artifact %s: %v", path, err)
	}
}

func redactDockerInspect(output []byte) []byte {
	var inspect []map[string]any
	if err := json.Unmarshal(output, &inspect); err != nil {
		return []byte("docker inspect output omitted because it could not be safely redacted\n")
	}

	for _, container := range inspect {
		config, ok := container["Config"].(map[string]any)
		if !ok {
			continue
		}
		env, ok := config["Env"].([]any)
		if !ok {
			continue
		}
		for i, value := range env {
			entry, ok := value.(string)
			if !ok {
				continue
			}
			name, _, found := strings.Cut(entry, "=")
			if found && isSensitiveEnvironmentVariable(name) {
				env[i] = name + "=<redacted>"
			}
		}
	}
	redacted, err := json.MarshalIndent(inspect, "", "  ")
	if err != nil {
		return []byte("docker inspect output omitted because it could not be safely redacted\n")
	}
	return append(redacted, '\n')
}

func isSensitiveEnvironmentVariable(name string) bool {
	upperName := strings.ToUpper(name)
	for _, marker := range []string{"API_KEY", "CREDENTIAL", "PASSWORD", "SECRET", "TOKEN"} {
		if strings.Contains(upperName, marker) {
			return true
		}
	}
	return false
}

func dockerOutput(ctx context.Context, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "docker", args...) //nolint:gosec // args are test-controlled docker subcommands
	return cmd.CombinedOutput()
}

type fleetAgentItem struct {
	Active        bool   `json:"active"`
	Status        string `json:"status"`
	LocalMetadata struct {
		Elastic struct {
			Agent struct {
				Complete bool `json:"complete"`
			} `json:"agent"`
		} `json:"elastic"`
	} `json:"local_metadata"`
}

func getFleetAgent(ctx context.Context, client *kibana.Client, agentID string) (fleetAgentItem, error) {
	resp, err := client.SendWithContext(ctx, http.MethodGet, "/api/fleet/agents/"+agentID, nil, nil, nil)
	if err != nil {
		return fleetAgentItem{}, fmt.Errorf("sending Fleet agent request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fleetAgentItem{}, fmt.Errorf("reading Fleet agent response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fleetAgentItem{}, fmt.Errorf("Fleet agent API returned %d: %s", resp.StatusCode, body)
	}

	var payload struct {
		Item fleetAgentItem `json:"item"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return fleetAgentItem{}, fmt.Errorf("decoding Fleet agent response: %w", err)
	}
	return payload.Item, nil
}

func heartbeatStateField(t *testing.T, doc mapstr.M, field string) interface{} {
	t.Helper()
	value, err := doc.GetValue(field)
	require.NoError(t, err, "heartbeat event is missing %s", field)
	return value
}

func heartbeatStateChecks(t *testing.T, doc mapstr.M) int {
	t.Helper()
	value := heartbeatStateField(t, doc, "state.checks")
	checks, ok := value.(float64)
	require.True(t, ok, "heartbeat state.checks has type %T, expected float64", value)
	return int(checks)
}

// createSyntheticsUIMonitor creates a monitor via the public Synthetics API.
// Kibana then installs/updates the synthetics Fleet package policy on the
// private location's agent policy so Elastic Agent runs heartbeat.
func createSyntheticsUIMonitor(ctx context.Context, client *kibana.Client, monitor map[string]any) error {
	body, err := json.Marshal(monitor)
	if err != nil {
		return fmt.Errorf("marshaling synthetics monitor request: %w", err)
	}

	headers := http.Header{"Content-Type": []string{"application/json"}}
	resp, err := client.SendWithContext(ctx, http.MethodPost, "/api/synthetics/monitors", nil, headers, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending synthetics monitor request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading synthetics monitor response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("synthetics monitor API returned %d: %s", resp.StatusCode, respBody)
	}
	return nil
}

func hostPortFromURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	host := u.Host
	if _, _, splitErr := net.SplitHostPort(host); splitErr != nil {
		// url.Host may omit the port for scheme defaults; httptest always includes one.
		return "", fmt.Errorf("expected host:port in %q: %w", raw, splitErr)
	}
	return host, nil
}
