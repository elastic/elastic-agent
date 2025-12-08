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
	"runtime"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-system-metrics/metric/system/process"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	otelMonitoring "github.com/elastic/elastic-agent/internal/pkg/otel/monitoring"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/testing/integration"
)

type MetricsRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture
	policyID     string
	policyName   string
	ESHost       string
}

func TestMetricsMonitoringCorrectBinaries(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Windows},
		},
	})

	suite.Run(t, &MetricsRunner{info: info})
}

func (runner *MetricsRunner) SetupSuite() {
	fixture, err := define.NewFixtureFromLocalBuild(runner.T(), define.Version())
	require.NoError(runner.T(), err)
	runner.agentFixture = fixture

	policyUUID := uuid.Must(uuid.NewV4()).String()
	basePolicy := kibana.AgentPolicy{
		Name:        "test-policy-" + policyUUID,
		Namespace:   "default",
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

	runner.policyName = policyResp.Name
	runner.policyID = policyResp.ID

	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "system",
		integration.PreinstalledPackages["system"], "testdata/system_integration_setup.json", uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)

}

func (runner *MetricsRunner) addMonitoringToOtelRuntimeOverwrite() {
	addMonitoringOverwriteBody := fmt.Sprintf(`
{
  "name": "%s",
  "namespace": "default",
  "overrides": {
    "agent": {
      "monitoring": {
        "_runtime_experimental": "otel"
      }
    }
  }
}
`, runner.policyName)
	resp, err := runner.info.KibanaClient.Send(
		http.MethodPut,
		fmt.Sprintf("/api/fleet/agent_policies/%s", runner.policyID),
		nil,
		nil,
		bytes.NewBufferString(addMonitoringOverwriteBody),
	)
	if err != nil {
		runner.T().Fatalf("could not execute request to Kibana/Fleet: %s", err)
	}
	if resp.StatusCode != http.StatusOK {
		// On error dump the whole request response so we can easily spot
		// what went wrong.
		runner.T().Errorf("received a non 200-OK when adding overwrite to policy. "+
			"Status code: %d", resp.StatusCode)
		respDump, err := httputil.DumpResponse(resp, true)
		if err != nil {
			runner.T().Fatalf("could not dump error response from Kibana: %s", err)
		}
		// Make debugging as easy as possible
		runner.T().Log("================================================================================")
		runner.T().Log("Kibana error response:")
		runner.T().Log(string(respDump))
		runner.T().FailNow()
	}
}

func (runner *MetricsRunner) TestBeatsMetrics() {
	t := runner.T()

	UnitOutputName := "default"
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*20)
	defer cancel()

	agentStatus, err := runner.agentFixture.ExecStatus(ctx)
	require.NoError(t, err, "could not to get agent status")

	componentIds := []string{
		fmt.Sprintf("system/metrics-%s", UnitOutputName),
		fmt.Sprintf("log-%s", UnitOutputName),
		"beat/metrics-monitoring",
		"elastic-agent",
		"http/metrics-monitoring",
		"filestream-monitoring",
	}

	now := time.Now()
	var query map[string]any
	defer func() {
		if t.Failed() {
			bs, err := json.Marshal(query)
			if err != nil {
				// nothing we can do, just log the map
				t.Errorf("executed at %s: %v",
					now.Format(time.RFC3339Nano), query)
				return
			}
			t.Errorf("executed at %s: query: %s",
				now.Format(time.RFC3339Nano), string(bs))
		}
	}()

	t.Logf("starting to ES for metrics at %s", now.Format(time.RFC3339Nano))
	require.Eventually(t, func() bool {
		for _, cid := range componentIds {
			query = genESQuery(agentStatus.Info.ID,
				[][]string{
					{"match", "component.id", cid},
					{"match", "agent.type", "metricbeat"},
				})
			now = time.Now()
			res, err := estools.PerformQueryForRawQuery(ctx, query, "metrics-elastic_agent*", runner.info.ESClient)
			require.NoError(t, err)
			t.Logf("Fetched metrics for %s, got %d hits", cid, res.Hits.Total.Value)
			if res.Hits.Total.Value < 1 {
				return false
			}
		}
		return true
	}, time.Minute*10, time.Second*10, "could not fetch metrics for all known components in default install: %v", componentIds)

	// Add a policy overwrite to change the agent monitoring to use Otel runtime
	runner.addMonitoringToOtelRuntimeOverwrite()

	// since the default execution mode of Otel runtime is sub-process we should see resource
	// metrics for elastic-agent/collector component.
	edotCollectorComponentID := otelMonitoring.EDOTComponentID
	query = genESQuery(agentStatus.Info.ID,
		[][]string{
			{"match", "component.id", edotCollectorComponentID},
			{"exists", "field", "system.process.cpu.total.value"},
			{"exists", "field", "system.process.memory.size"},
		})

	require.Eventually(t, func() bool {
		now = time.Now()
		res, err := estools.PerformQueryForRawQuery(ctx, query, "metrics-elastic_agent*", runner.info.ESClient)
		require.NoError(t, err)
		t.Logf("Fetched metrics for %s, got %d hits", edotCollectorComponentID, res.Hits.Total.Value)
		if res.Hits.Total.Value < 1 {
			return false
		}
		return true
	}, time.Minute*10, time.Second*10, "could not fetch metrics for edot collector")

	if runtime.GOOS == "windows" {
		return
	}

	// restart the agent to validate that this does not result in any agent-spawned subprocess
	// becoming defunct
	err = runner.agentFixture.ExecRestart(ctx)
	require.NoError(t, err, "could not restart agent")

	require.Eventually(t, func() bool {
		err = runner.agentFixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return true
	}, 1*time.Minute, 1*time.Second)

	procStats := process.Stats{
		// filtering with '.*elastic-agent' or '^.*elastic-agent$' doesn't
		// seem to work as expected
		Procs: []string{".*"},
	}
	err = procStats.Init()
	require.NoError(t, err, "could not initialize process.Stats")

	pidMap, _, err := procStats.FetchPids()
	require.NoError(t, err, "could not fetch pids")

	for _, state := range pidMap {
		assert.NotEqualValuesf(t, process.Zombie, state.State, "process %d is in zombie state", state.Pid.ValueOr(0))
	}
}

func genESQuery(agentID string, requiredFields [][]string) map[string]interface{} {
	fieldsQ := make([]map[string]interface{}, 0, 2+len(requiredFields))
	fieldsQ = append(fieldsQ, map[string]interface{}{
		"match": map[string]interface{}{
			"agent.id": agentID,
		},
	})
	for _, f := range requiredFields {
		if len(f) != 3 {
			continue
		}
		fieldsQ = append(fieldsQ,
			map[string]interface{}{
				f[0]: map[string]interface{}{
					f[1]: f[2],
				},
			})
	}

	// see https://github.com/elastic/kibana/blob/main/x-pack/plugins/fleet/server/services/agents/agent_metrics.ts
	queryRaw := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": fieldsQ,
			},
		},
	}

	return queryRaw
}
