// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/testing/integration"
)

var defaultTextCfg = `
outputs:
  default:
    type: elasticsearch
    hosts: [127.0.0.1:9200]
    api_key: "example-key"
    preset: balanced
    allow_older_versions: true
    status_reporting:
      enabled: false

inputs:
  - type: system/metrics
    id: unique-system-metrics-input
    data_stream.namespace: default
    use_output: default
    streams:
      - metricsets:
        - cpu
        data_stream.dataset: system.cpu
      - metricsets:
        - memory
        data_stream.dataset: system.memory
      - metricsets:
        - network
        data_stream.dataset: system.network
      - metricsets:
        - filesystem
        data_stream.dataset: system.filesystem
agent.monitoring:
  metrics_period: 1s
  http:
    enabled: true
    port: 6791
agent.logging.level: debug
agent.logging.to_stderr: true
`

type MonitoringTextRunner struct {
	suite.Suite
	info         *define.Info
	agentFixture *atesting.Fixture
	agentID      string

	ESHost string

	healthCheckTime        time.Duration
	healthCheckRefreshTime time.Duration

	policyID   string
	policyName string
}

func TestMonitoringPreserveTextConfig(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: "fleet",
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Windows},
		},
	})

	suite.Run(t, &MonitoringTextRunner{info: info, healthCheckTime: time.Minute * 5, healthCheckRefreshTime: time.Second * 5})
}

func (runner *MonitoringTextRunner) SetupSuite() {
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

	// write a default config file that enables monitoring
	err = runner.agentFixture.WriteFileToWorkDir(ctx, defaultTextCfg, "elastic-agent.yml")
	require.NoError(runner.T(), err)

	policyResp, agentID, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	runner.policyID = policyResp.ID
	runner.policyName = basePolicy.Name
	runner.agentID = agentID

	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "system",
		integration.PreinstalledPackages["system"], "testdata/system_integration_setup.json", uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)
}

func (runner *MonitoringTextRunner) TestMonitoringLiveness() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
	defer cancel()

	runner.AllComponentsHealthy(ctx)

	client := http.Client{Timeout: time.Second * 4}
	endpoint := "http://localhost:6791/processes"
	// first stage: ensure the HTTP config has remained up post-install
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	require.NoError(runner.T(), err)

	initResp, err := client.Do(req)
	require.NoError(runner.T(), err)
	require.Equal(runner.T(), http.StatusOK, initResp.StatusCode)

	// use the fleet override API to change the port that we're running on.
	overrideUpdateRequest := kibana.AgentPolicyUpdateRequest{
		Name:      runner.policyName,
		Namespace: "default",
		Overrides: map[string]interface{}{
			"agent": map[string]interface{}{
				"monitoring": map[string]interface{}{
					"http": map[string]interface{}{
						"enabled": true,
						"host":    "localhost",
						"port":    6792,
					},
				},
			},
		},
	}

	policyResponse, err := runner.info.KibanaClient.UpdatePolicy(ctx, runner.policyID, overrideUpdateRequest)
	require.NoError(runner.T(), err)

	// verify the new policy revision was applied
	require.Eventually(
		runner.T(),
		tools.IsPolicyRevision(ctx, runner.T(), runner.info.KibanaClient, runner.agentID, policyResponse.Revision),
		5*time.Minute, time.Second)

	runner.AllComponentsHealthy(ctx)

	updatedEndpoint := "http://localhost:6792/processes"
	// second stage: ensure the HTTP config has updated
	require.EventuallyWithT(runner.T(), func(collect *assert.CollectT) {
		req, err = http.NewRequestWithContext(ctx, "GET", updatedEndpoint, nil)
		require.NoError(collect, err)
	}, time.Minute, time.Second)

	initResp, err = client.Do(req)
	require.NoError(runner.T(), err)
	require.Equal(runner.T(), http.StatusOK, initResp.StatusCode)
}

// AllComponentsHealthy ensures all the beats and agent are healthy and working before we continue
func (runner *MonitoringTextRunner) AllComponentsHealthy(ctx context.Context) {
	compDebugName := ""
	require.Eventually(runner.T(), func() bool {
		allHealthy := true
		status, err := runner.agentFixture.ExecStatus(ctx)
		if err != nil {
			runner.T().Logf("agent status returned an error: %v", err)
			return false
		}

		for _, comp := range status.Components {
			runner.T().Logf("component state: %s", comp.Message)
			if comp.State != int(cproto.State_HEALTHY) {
				compDebugName = comp.Name
				allHealthy = false
			}
		}
		return allHealthy
	}, runner.healthCheckTime, runner.healthCheckRefreshTime, "install never became healthy: components did not return a healthy state: %s", compDebugName)
}
