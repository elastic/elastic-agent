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
	"net/http"
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

type HeartbeatBrowserRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture

	agentID    string
	policyID   string
	policyName string
}

// TestHeartbeatBrowserMonitor verifies that a Synthetics browser monitor on a
// Fleet private location stays HEALTHY under the OTel heartbeat runtime.
//
// Browser monitors compile to three Fleet streams (browser + browser.network +
// browser.screenshot). Only the primary stream carries schedule; the OTel
// heartbeatreceiver used to treat the auxiliaries as monitors and fail with
// scheduleMissingErr (elastic-agent#15968).
func TestHeartbeatBrowserMonitor(t *testing.T) {
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

	suite.Run(t, &HeartbeatBrowserRunner{info: info})
}

func (runner *HeartbeatBrowserRunner) SetupSuite() {
	t := runner.T()

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	runner.agentFixture = fixture

	policyUUID := uuid.Must(uuid.NewV4()).String()
	basePolicy := kibana.AgentPolicy{
		Name:        "test-browser-policy-" + policyUUID,
		Namespace:   runner.info.Namespace,
		Description: "Browser heartbeat OTel regression policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		// Force OTel so this suite always exercises the #15968 path, even if
		// the product default for heartbeat ever changes.
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
	runner.policyName = policyResp.Name

	locationLabel := fmt.Sprintf("test-browser-location-%s", policyUUID)
	locationID, err := createSyntheticsPrivateLocation(ctx, runner.info.KibanaClient, locationLabel, policyResp.ID)
	require.NoError(t, err)

	require.NoError(t, createSyntheticsBrowserMonitor(ctx, runner.info.KibanaClient,
		fmt.Sprintf("browser-otel-%s", policyUUID), locationID))
}

func (runner *HeartbeatBrowserRunner) TestOTelBrowserComponentHealthy() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Minute)
	defer cancel()

	otelName := componentVersionInfoNameForRuntime(component.OtelRuntimeManager)

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		status, statusErr := runner.agentFixture.ExecStatus(ctx)
		require.NoError(collect, statusErr)

		var found bool
		for _, comp := range status.Components {
			if !strings.HasPrefix(comp.ID, "synthetics/browser") {
				continue
			}
			found = true

			assert.Equal(collect, otelName, comp.VersionInfo.Name,
				"expected synthetics/browser to run as beats receiver (OTel), got %q; message=%q",
				comp.VersionInfo.Name, comp.Message)
			assert.NotContains(collect, comp.Message, scheduleMissingErr,
				"OTel heartbeatreceiver must ignore schedule-less browser.network/screenshot streams (#15968); component message=%q",
				comp.Message)
			for _, unit := range comp.Units {
				assert.NotContains(collect, unit.Message, scheduleMissingErr,
					"unit %s must not fail for missing schedule (#15968); message=%q",
					unit.UnitID, unit.Message)
			}
			assert.Equal(collect, int(cproto.State_HEALTHY), comp.State,
				"expected synthetics/browser component to be healthy under OTel, got %s; message=%q",
				cproto.State(comp.State), comp.Message) //nolint:gosec // G115 always under 32-bit
			break
		}
		assert.True(collect, found, "expected a synthetics/browser component after creating a browser PL monitor")
	}, 5*time.Minute, 5*time.Second, "synthetics/browser should be HEALTHY under OTel heartbeat")
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

// createSyntheticsBrowserMonitor creates an inline-script browser monitor on the
// given private location via the public Synthetics API. The resulting Fleet
// package policy includes browser + browser.network + browser.screenshot streams.
func createSyntheticsBrowserMonitor(ctx context.Context, client *kibana.Client, name, privateLocationID string) error {
	body, err := json.Marshal(map[string]any{
		"type":              "browser",
		"name":              name,
		"private_locations": []string{privateLocationID},
		"schedule":          10,
		// Minimal noop journey — this suite asserts agent/component health for
		// the schedule translation bug, not journey success / Chromium.
		"inline_script": `step("noop", async () => {});`,
	})
	if err != nil {
		return fmt.Errorf("marshaling browser monitor request: %w", err)
	}

	headers := http.Header{"Content-Type": []string{"application/json"}}
	resp, err := client.SendWithContext(ctx, http.MethodPost, "/api/synthetics/monitors", nil, headers, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("sending browser monitor request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading browser monitor response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("browser monitor API returned %d: %s", resp.StatusCode, respBody)
	}
	return nil
}
