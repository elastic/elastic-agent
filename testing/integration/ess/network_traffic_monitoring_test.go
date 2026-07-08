// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/url"
	"os"
	"path/filepath"
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

type NetworkTrafficRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture

	ESHost     string
	agentID    string
	policyID   string
	policyName string
}

func TestNetworkTraffic(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Windows},
		},
		// The network_traffic Fleet integration relies on packetbeat, which
		// has no windows/arm64 build, so the agent component never reaches
		// HEALTHY on this combination.
		SkipOS: []define.OS{{Type: define.Windows, Arch: define.ARM64}},
	})

	suite.Run(t, &NetworkTrafficRunner{info: info})
}

func (runner *NetworkTrafficRunner) SetupSuite() {
	fixture, err := define.NewFixtureFromLocalBuild(runner.T(), define.Version())
	require.NoError(runner.T(), err)
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

	// 5 minutes: agent install can take 2+ minutes on slow machines, leaving
	// insufficient time for the subsequent package install with a 3-minute budget.
	ctx, cancel := context.WithTimeout(runner.T().Context(), 5*time.Minute)
	defer cancel()

	require.NoError(runner.T(), fleettools.UpdateESOutputPreset(ctx, runner.info.KibanaClient, fleettools.DefaultFleetOutputID, fleettools.OutputPresetLatency))
	policyResp, agentID, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	runner.agentID = agentID
	runner.policyID = policyResp.ID
	runner.policyName = policyResp.Name

	packageFile := filepath.Join("testdata", "network_traffic_package.json")
	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "network_traffic",
		integration.PreinstalledPackages["network_traffic"], packageFile, uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)

}

// validateNetworkTrafficEvents generates TLS traffic to serverName and returns
// the captured event for it. Traffic is generated on every poll so a missed
// capture is retried rather than failing the test.
func (runner *NetworkTrafficRunner) validateNetworkTrafficEvents(t *testing.T, ctx context.Context, agentID, serverName string, since time.Time) mapstr.M {
	now := time.Now()
	var query map[string]any
	var doc mapstr.M
	defer func() {
		if t.Failed() {
			bs, err := json.Marshal(query)
			if err != nil {
				t.Errorf("executed at %s: %v",
					now.Format(time.RFC3339Nano), query)
				return
			}
			t.Errorf("executed at %s: query: %s",
				now.Format(time.RFC3339Nano), string(bs))
		}
	}()

	t.Logf("starting to query ES for network traffic events at %s", now.Format(time.RFC3339Nano))
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		dialTLS(t, serverName)

		query = genESQuery(agentID,
			[][]string{
				{"match", "tls.client.server_name", serverName},
			})
		query["query"].(map[string]interface{})["bool"].(map[string]interface{})["filter"] = map[string]any{
			"range": map[string]any{
				"@timestamp": map[string]any{"gte": since.UTC().Format("2006-01-02T15:04:05.000Z")},
			},
		}
		query["sort"] = []map[string]any{{"@timestamp": map[string]any{"order": "asc"}}}
		now = time.Now()
		res, err := estools.PerformQueryForRawQuery(ctx, query, "logs-network_traffic.tls*", runner.info.ESClient)
		require.NoError(collect, err)
		require.NotEmpty(collect, res.Hits.Hits)
		doc = mapstr.M(res.Hits.Hits[0].Source)
	}, time.Minute*10, time.Second*10, "could not fetch events for network_traffic to %s", serverName)
	return doc
}

// esServerName returns the Elasticsearch hostname, used as the TLS SNI.
func esServerName(t *testing.T) string {
	raw := os.Getenv("ELASTICSEARCH_HOST")
	require.NotEmpty(t, raw, "ELASTICSEARCH_HOST must be set")
	u, err := url.Parse(raw)
	require.NoError(t, err, "parsing ELASTICSEARCH_HOST")
	require.NotEmpty(t, u.Hostname(), "ELASTICSEARCH_HOST has no hostname")
	return u.Hostname()
}

// dialTLS triggers a TLS handshake to host:443 for the packet component to
// capture. A dial error is fine: the SNI is sent before cert verification.
func dialTLS(t *testing.T, host string) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		net.JoinHostPort(host, "443"),
		&tls.Config{ServerName: host},
	)
	if err != nil {
		t.Logf("TLS dial to %s returned %v (handshake still captured)", host, err)
		return
	}
	_ = conn.Close()
}

func (runner *NetworkTrafficRunner) TestBeatsMetrics() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(t.Context(), time.Minute*20)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	// Use one fixed destination for both runtimes so the captured handshakes are
	// directly comparable.
	serverName := esServerName(t)

	var processDoc mapstr.M
	t.Run("process", func(t *testing.T) {
		processDoc = runner.validateNetworkTrafficEvents(t, ctx, agentStatus.Info.ID, serverName, time.Now())
	})

	var otelDoc mapstr.M
	t.Run("otel", func(t *testing.T) {
		otelSince := time.Now()
		policyRevision := switchPolicyToOtelRuntime(ctx, t, runner.info.KibanaClient, runner.policyID, runner.policyName, runner.info.Namespace)

		require.Eventually(t, tools.IsPolicyRevision(ctx, t, runner.info.KibanaClient, runner.agentID, policyRevision),
			5*time.Minute, time.Second)

		// The packet component may take a moment to appear after the policy switch.
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, statusErr := runner.agentFixture.ExecStatus(ctx)
			require.NoError(collect, statusErr)
			var foundReceiver bool
			for _, comp := range status.Components {
				if strings.HasPrefix(comp.ID, "packet") &&
					comp.VersionInfo.Name == componentVersionInfoNameForRuntime(component.OtelRuntimeManager) {
					assert.Equal(collect, int(cproto.State_HEALTHY), comp.State,
						"expected packet component to be healthy, got %s", cproto.State(comp.State))
					foundReceiver = true
					break
				}
			}
			assert.True(collect, foundReceiver, "expected a packet (network_traffic) component to be running as beats receiver")
		}, 2*time.Minute, 5*time.Second, "beat component should be running as beats receiver")

		otelDoc = runner.validateNetworkTrafficEvents(t, ctx, agentStatus.Info.ID, serverName, otelSince)
	})

	t.Run("compare", func(t *testing.T) {
		require.NotNil(t, processDoc, "process subtest did not produce a document")
		require.NotNil(t, otelDoc, "otel subtest did not produce a document")
		AssertMapstrKeysEqual(t, processDoc, otelDoc, RuntimeComparisonIgnoredFields,
			"expected network_traffic document keys to be equal between process and otel modes")
	})
}
