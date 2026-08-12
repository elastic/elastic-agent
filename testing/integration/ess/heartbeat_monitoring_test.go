// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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

type HeartbeatRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture
	httpServer   *httptest.Server

	agentID    string
	policyID   string
	policyName string
}

func TestHeartbeatHTTPMonitor(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
		},
	})

	suite.Run(t, &HeartbeatRunner{info: info})
}

func (runner *HeartbeatRunner) SetupSuite() {
	t := runner.T()

	// Start a local HTTP server that always returns 200. Heartbeat will poll this.
	runner.httpServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	}))
	t.Cleanup(runner.httpServer.Close)

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	runner.agentFixture = fixture

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

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	require.NoError(t, fleettools.UpdateESOutputPreset(ctx, runner.info.KibanaClient, fleettools.DefaultFleetOutputID, fleettools.OutputPresetLatency))
	policyResp, agentID, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(t, err)

	runner.agentID = agentID
	runner.policyID = policyResp.ID
	runner.policyName = policyResp.Name

	// Create a Synthetics private location backed by the Fleet policy so that
	// Kibana can push a heartbeat monitor to the agent via Fleet.
	locationLabel := fmt.Sprintf("test-location-%s", policyUUID)
	_, err = createSyntheticsPrivateLocation(ctx, runner.info.KibanaClient, locationLabel, policyResp.ID)
	require.NoError(t, err)

	// Push one HTTP monitor targeting the local test server.
	monitors := []syntheticsMonitorSchema{
		{
			ID:               "heartbeat-http-monitor-" + policyUUID,
			Type:             "http",
			Name:             "Test HTTP Monitor",
			Enabled:          true,
			Schedule:         1, // 1-minute polling interval
			PrivateLocations: []string{locationLabel},
			URLs:             runner.httpServer.URL,
		},
	}
	projectName := fmt.Sprintf("heartbeat-test-%s", policyUUID)
	require.NoError(t, bulkPushSyntheticsMonitors(ctx, t, runner.info.KibanaClient, projectName, monitors))
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

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	testStart := time.Now()

	// Validate process mode
	var processDoc mapstr.M
	t.Run("process", func(t *testing.T) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, statusErr := runner.agentFixture.ExecStatus(ctx)
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
			stateIDBefore := heartbeatStateField(t, processDoc, "state.id")
			stateStartedAtBefore := heartbeatStateField(t, processDoc, "state.started_at")

			require.NoError(t, runner.agentFixture.ExecRestart(ctx), "could not restart agent")
			restartedAt := time.Now()
			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				assert.NoError(collect, runner.agentFixture.IsHealthy(ctx))
			}, 2*time.Minute, 5*time.Second, "agent did not become healthy after restart")

			afterRestartDoc := runner.validateHeartbeatEvents(t, ctx, agentStatus.Info.ID, restartedAt)
			assert.Equal(t, stateIDBefore, heartbeatStateField(t, afterRestartDoc, "state.id"),
				"Heartbeat should continue the monitor state loaded from Elasticsearch")
			assert.Equal(t, stateStartedAtBefore, heartbeatStateField(t, afterRestartDoc, "state.started_at"),
				"Heartbeat should preserve the monitor state start time loaded from Elasticsearch")
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

		// Verify that a synthetics/http component is running as a beats receiver.
		// The component may not appear immediately after the policy switch, so we
		// look for it inside the loop rather than capturing its ID up front.
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, statusErr := runner.agentFixture.ExecStatus(ctx)
			require.NoError(collect, statusErr)
			var foundReceiver bool
			for _, comp := range status.Components {
				if strings.HasPrefix(comp.ID, "synthetics/http") &&
					comp.VersionInfo.Name == componentVersionInfoNameForRuntime(component.OtelRuntimeManager) {
					assert.Equal(collect, int(cproto.State_HEALTHY), comp.State,
						"expected synthetics/http component to be healthy, got %s", cproto.State(comp.State)) //nolint:gosec // G115 always under 32-bit
					foundReceiver = true
					break
				}
			}
			assert.True(collect, foundReceiver, "expected a synthetics/http component to be running as beats receiver")
		}, 2*time.Minute, 5*time.Second, "heartbeat component should be running as beats receiver")

		otelDoc = runner.validateHeartbeatEvents(t, ctx, agentStatus.Info.ID, otelSince)
	})

	t.Run("compare", func(t *testing.T) {
		if processDoc == nil || otelDoc == nil {
			t.Skip("skipping comparison because a previous subtest failed")
		}
		AssertMapstrKeysEqual(t, processDoc, otelDoc, RuntimeComparisonIgnoredFields,
			"expected heartbeat document keys to be equal between process and otel modes")
	})
}

func heartbeatStateField(t *testing.T, doc mapstr.M, field string) interface{} {
	t.Helper()
	value, err := doc.GetValue(field)
	require.NoError(t, err, "heartbeat event is missing %s", field)
	return value
}

// scheduleMissingErr is the Permanent failure message emitted by the OTel
// heartbeatreceiver when Fleet browser.network / browser.screenshot streams
// (which have no schedule) are treated as monitors. See elastic-agent#15968.
const scheduleMissingErr = "missing required field accessing 'heartbeat.monitors"

// browserOutsideDockerErr is heartbeat's hard gate for browser monitors on
// non-complete installs (ESS Fleet integration uses a tarball, not the
// complete docker image). With #15968 fixed the component still lands here —
// proving schedule translation worked — rather than the schedule-missing
// Permanent failure.
const browserOutsideDockerErr = "browser monitors cannot be created outside the official elastic docker image"

type HeartbeatOTelRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture
	httpServer   *httptest.Server

	agentID  string
	policyID string
}

// TestHeartbeatOTelMonitors verifies that Synthetics monitors on a Fleet
// private location stay under the OTel heartbeat runtime for every monitor
// type Kibana can push via Fleet (http, tcp, icmp, browser).
//
// Browser is the #15968 regression case: it compiles to three Fleet streams
// (browser + browser.network + browser.screenshot), and only the primary
// stream carries schedule. On ESS Fleet (tarball install) browser cannot be
// HEALTHY — we assert it fails on the docker-image gate instead of the
// schedule-missing Permanent failure. Lightweight types must be HEALTHY.
func TestHeartbeatOTelMonitors(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
		},
	})

	suite.Run(t, &HeartbeatOTelRunner{info: info})
}

func (runner *HeartbeatOTelRunner) SetupSuite() {
	t := runner.T()

	runner.httpServer = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = fmt.Fprint(w, "OK")
	}))
	t.Cleanup(runner.httpServer.Close)

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	runner.agentFixture = fixture

	policyUUID := uuid.Must(uuid.NewV4()).String()
	basePolicy := kibana.AgentPolicy{
		Name:        "test-otel-heartbeat-policy-" + policyUUID,
		Namespace:   runner.info.Namespace,
		Description: "OTel heartbeat PL monitor coverage policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		// Force OTel so this suite always exercises the beats-receiver path,
		// even if the product default for heartbeat ever changes.
		Overrides: heartbeatOtelRuntimeOverride(),
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Force:          true,
		Privileged:     true,
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()

	require.NoError(t, fleettools.UpdateESOutputPreset(ctx, runner.info.KibanaClient, fleettools.DefaultFleetOutputID, fleettools.OutputPresetLatency))
	policyResp, agentID, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(t, err)

	runner.agentID = agentID
	runner.policyID = policyResp.ID

	locationLabel := fmt.Sprintf("test-otel-location-%s", policyUUID)
	locationID, err := createSyntheticsPrivateLocation(ctx, runner.info.KibanaClient, locationLabel, policyResp.ID)
	require.NoError(t, err)

	tcpHost, err := hostPortFromURL(runner.httpServer.URL)
	require.NoError(t, err)

	monitors := []map[string]any{
		{
			"type":              "http",
			"name":              fmt.Sprintf("http-otel-%s", policyUUID),
			"private_locations": []string{locationID},
			"schedule":          1,
			"url":               runner.httpServer.URL,
		},
		{
			"type":              "tcp",
			"name":              fmt.Sprintf("tcp-otel-%s", policyUUID),
			"private_locations": []string{locationID},
			"schedule":          1,
			"host":              tcpHost,
		},
		{
			"type":              "icmp",
			"name":              fmt.Sprintf("icmp-otel-%s", policyUUID),
			"private_locations": []string{locationID},
			"schedule":          1,
			"host":              "127.0.0.1",
		},
		{
			"type":              "browser",
			"name":              fmt.Sprintf("browser-otel-%s", policyUUID),
			"private_locations": []string{locationID},
			"schedule":          10,
			// Minimal noop journey — assert #15968 schedule translation under
			// OTel. ESS Fleet uses a tarball (not complete docker), so the
			// component will not stay HEALTHY; we assert it fails on the
			// docker-image gate instead of the schedule-missing error.
			"inline_script": `step("noop", async () => {});`,
		},
	}
	for _, monitor := range monitors {
		require.NoError(t, createSyntheticsUIMonitor(ctx, runner.info.KibanaClient, monitor),
			"creating %s monitor", monitor["type"])
	}
}

func (runner *HeartbeatOTelRunner) TestOTelComponentsHealthy() {
	t := runner.T()

	// Each monitor type below gets its own 5-minute Eventually and they run
	// serially, so the overall deadline must comfortably exceed 4 x 5 minutes.
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Minute)
	defer cancel()

	otelName := componentVersionInfoNameForRuntime(component.OtelRuntimeManager)
	monitorTypes := []string{"http", "tcp", "icmp", "browser"}

	for _, monitorType := range monitorTypes {
		t.Run(monitorType, func(t *testing.T) {
			componentPrefix := "synthetics/" + monitorType
			require.EventuallyWithT(t, func(collect *assert.CollectT) {
				status, statusErr := runner.agentFixture.ExecStatus(ctx)
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
					if monitorType == "browser" {
						// ESS Fleet installs a tarball, so browser cannot be HEALTHY
						// here; accept the docker-image gate as success for #15968.
						if comp.State != int(cproto.State_HEALTHY) {
							assert.Equal(collect, int(cproto.State_FAILED), comp.State,
								"expected browser component HEALTHY or FAILED (docker gate), got %s; message=%q",
								cproto.State(comp.State), comp.Message) //nolint:gosec // G115 always under 32-bit
							assert.Contains(collect, comp.Message, browserOutsideDockerErr,
								"browser FAILED for an unexpected reason; message=%q", comp.Message)
						}
					} else {
						assert.Equal(collect, int(cproto.State_HEALTHY), comp.State,
							"expected %s component to be healthy under OTel, got %s; message=%q",
							componentPrefix, cproto.State(comp.State), comp.Message) //nolint:gosec // G115 always under 32-bit
					}
					break
				}
				assert.True(collect, found,
					"expected a %s component after creating a %s PL monitor", componentPrefix, monitorType)
			}, 5*time.Minute, 5*time.Second, "%s should be HEALTHY under OTel heartbeat", componentPrefix)
		})
	}
}

// heartbeatOtelRuntimeOverride forces heartbeat into the OTel beats-receiver
// runtime, regardless of the product default.
func heartbeatOtelRuntimeOverride() map[string]interface{} {
	return map[string]interface{}{
		"agent": map[string]interface{}{
			"internal": map[string]interface{}{
				"runtime": map[string]interface{}{
					"heartbeat": map[string]interface{}{
						"default": "otel",
					},
				},
			},
		},
	}
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
