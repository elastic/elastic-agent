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
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/testing/integration"
)

// scheduleMissingErr is the Permanent failure message emitted by the OTel
// heartbeatreceiver when Fleet browser.network / browser.screenshot streams
// (which have no schedule) are treated as monitors. See elastic-agent#15968.
const scheduleMissingErr = "missing required field accessing 'heartbeat.monitors"

type HeartbeatOTelRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture
	httpServer   *httptest.Server

	agentID  string
	policyID string
}

// TestHeartbeatOTelMonitors verifies that Synthetics monitors on a Fleet
// private location stay HEALTHY under the OTel heartbeat runtime for every
// monitor type Kibana can push via Fleet (http, tcp, icmp, browser).
//
// Browser is the #15968 regression case: it compiles to three Fleet streams
// (browser + browser.network + browser.screenshot), and only the primary
// stream carries schedule. Lightweight types are included so OTel coverage
// stays aligned across the full synthetics/heartbeat surface.
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
			// Minimal noop journey — assert agent/component health for the
			// schedule translation bug, not journey success / Chromium.
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

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
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
}

// heartbeatOtelRuntimeOverride forces heartbeat into the OTel beats-receiver
// runtime (the product default since elastic-agent#15325).
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
