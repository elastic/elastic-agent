// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
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

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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
// summary document appears for the given agent, filtered to events after `since`.
// It returns the first matching document.
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
		})
		query["query"].(map[string]interface{})["bool"].(map[string]interface{})["filter"] = map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{"gte": since.UTC().Format("2006-01-02T15:04:05.000Z")},
			},
		}
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

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	testStart := time.Now()

	// Validate process mode
	var processDoc mapstr.M
	t.Run("process", func(t *testing.T) {
		processDoc = runner.validateHeartbeatEvents(t, ctx, agentStatus.Info.ID, testStart)
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
						"expected synthetics/http component to be healthy, got %s", cproto.State(comp.State))
					foundReceiver = true
					break
				}
			}
			assert.True(collect, foundReceiver, "expected a synthetics/http component to be running as beats receiver")
		}, 2*time.Minute, 5*time.Second, "heartbeat component should be running as beats receiver")

		otelDoc = runner.validateHeartbeatEvents(t, ctx, agentStatus.Info.ID, otelSince)
	})

	// Compare that documents produced by process and OTel modes have the same keys.
	// host.* fields are excluded: the OTel collector's resource detection processor
	// adds host metadata that heartbeat doesn't emit in process mode.
	heartbeatIgnoredFields := append(RuntimeComparisonIgnoredFields, "host")
	t.Run("compare", func(t *testing.T) {
		if processDoc == nil || otelDoc == nil {
			t.Skip("skipping comparison because a previous subtest failed")
		}
		AssertMapstrKeysEqual(t, processDoc, otelDoc, heartbeatIgnoredFields,
			"expected heartbeat document keys to be equal between process and otel modes")
	})
}
