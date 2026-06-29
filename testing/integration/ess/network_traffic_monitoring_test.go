// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"encoding/json"
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
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
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

// validateNetworkTrafficEvents waits for TLS events in ES and returns one
// document per destination hostname (SNI).
func (runner *NetworkTrafficRunner) validateNetworkTrafficEvents(t *testing.T, ctx context.Context, agentID string, since time.Time) map[string]mapstr.M {
	now := time.Now()
	var query map[string]any
	var docsByHost map[string]mapstr.M
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
		query = genESQuery(agentID,
			[][]string{
				{"exists", "field", "tls.client.server_name"},
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
		docs := make(map[string]mapstr.M)
		for _, hit := range res.Hits.Hits {
			source := mapstr.M(hit.Source)
			sn, _ := source.Flatten()["tls.client.server_name"].(string)
			if sn == "" {
				continue
			}
			if _, exists := docs[sn]; !exists {
				docs[sn] = source
			}
		}
		require.NotEmpty(collect, docs)
		docsByHost = docs
	}, time.Minute*10, time.Second*10, "could not fetch events for network_traffic")
	return docsByHost
}

func (runner *NetworkTrafficRunner) TestBeatsMetrics() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	testStart := time.Now()

	var processDocs map[string]mapstr.M
	t.Run("process", func(t *testing.T) {
		processDocs = runner.validateNetworkTrafficEvents(t, ctx, agentStatus.Info.ID, testStart)
	})

	var otelDocs map[string]mapstr.M
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

		otelDocs = runner.validateNetworkTrafficEvents(t, ctx, agentStatus.Info.ID, otelSince)
	})

	// Compare per host: for the same destination the two modes must produce identical fields.
	t.Run("compare", func(t *testing.T) {
		require.NotNil(t, processDocs, "process subtest did not produce documents")
		require.NotNil(t, otelDocs, "otel subtest did not produce documents")
		var commonHosts []string
		for host := range processDocs {
			if _, ok := otelDocs[host]; ok {
				commonHosts = append(commonHosts, host)
			}
		}
		require.NotEmpty(t, commonHosts,
			"no common tls.client.server_name found between process and otel phases; process=%v otel=%v",
			hostKeys(processDocs), hostKeys(otelDocs))
		for _, host := range commonHosts {
			host := host
			t.Run(host, func(t *testing.T) {
				AssertMapstrKeysEqual(t, processDocs[host], otelDocs[host], RuntimeComparisonIgnoredFields,
					"expected network_traffic document keys to be equal between process and otel modes")
			})
		}
	})
}

// hostKeys returns the hostnames from a per-host document map, for use in error messages.
func hostKeys(m map[string]mapstr.M) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
