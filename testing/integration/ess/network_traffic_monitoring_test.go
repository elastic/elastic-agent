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
	"net/http"
	"net/http/httputil"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/testing/integration"
)

type NetworkTrafficRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture

	ESHost     string
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

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	policyResp, _, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	runner.policyID = policyResp.ID
	runner.policyName = policyResp.Name

	packageFile := filepath.Join("testdata", "network_traffic_package.json")
	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "network_traffic",
		integration.PreinstalledPackages["network_traffic"], packageFile, uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)

}

func (runner *NetworkTrafficRunner) switchToOtelRuntime() {
	body := fmt.Sprintf(`
{
  "name": "%s",
  "namespace": "%s",
  "overrides": {
    "agent": {
      "internal": {
        "runtime": {
          "default": "otel"
        }
      }
    }
  }
}
`, runner.policyName, runner.info.Namespace)
	resp, err := runner.info.KibanaClient.Send(
		http.MethodPut,
		fmt.Sprintf("/api/fleet/agent_policies/%s", runner.policyID),
		nil,
		nil,
		bytes.NewBufferString(body),
	)
	if err != nil {
		runner.T().Fatalf("could not execute request to Kibana/Fleet: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		runner.T().Errorf("received a non 200-OK when adding overwrite to policy. "+
			"Status code: %d", resp.StatusCode)
		respDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			runner.T().Fatalf("could not dump error response from Kibana: %s", err)
		}
		runner.T().Log("================================================================================")
		runner.T().Log("Kibana error response:")
		runner.T().Log(string(respDump))
		runner.T().FailNow()
	}
}

func (runner *NetworkTrafficRunner) validateNetworkTrafficEvents(ctx context.Context, agentID string) mapstr.M {
	t := runner.T()

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
	require.Eventually(t, func() bool {
		query = genESQuery(agentID,
			[][]string{
				{"exists", "field", "tls.client.server_name"},
			})
		now = time.Now()
		res, err := estools.PerformQueryForRawQuery(ctx, query, "logs-network_traffic.tls*", runner.info.ESClient)
		require.NoError(t, err)
		if res.Hits.Total.Value < 1 {
			return false
		}
		doc = res.Hits.Hits[0].Source
		return true
	}, time.Minute*10, time.Second*10, "could not fetch events for network_traffic")
	return doc
}

func (runner *NetworkTrafficRunner) TestBeatsMetrics() {
	t := runner.T()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not get agent status")

	// Validate process mode
	var processDoc mapstr.M
	t.Run("process", func(t *testing.T) {
		processDoc = runner.validateNetworkTrafficEvents(ctx, agentStatus.Info.ID)
	})

	// Switch to OTel runtime and validate the same data
	var otelDoc mapstr.M
	t.Run("otel", func(t *testing.T) {
		runner.switchToOtelRuntime()

		// Wait for the agent to pick up the new policy and become healthy
		require.Eventually(t, func() bool {
			err := runner.agentFixture.IsHealthy(ctx)
			if err != nil {
				t.Logf("waiting for agent healthy after otel switch: %s", err.Error())
				return false
			}
			return true
		}, 2*time.Minute, 5*time.Second)

		otelDoc = runner.validateNetworkTrafficEvents(ctx, agentStatus.Info.ID)
	})

	// Compare documents from process and otel modes have the same keys
	t.Run("compare", func(t *testing.T) {
		if processDoc == nil || otelDoc == nil {
			t.Skip("skipping comparison because a previous subtest failed")
		}
		AssertMapstrKeysEqual(t, processDoc, otelDoc, RuntimeComparisonIgnoredFields, "expected network_traffic document keys to be equal between process and otel modes")
	})
}
