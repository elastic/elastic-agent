// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build integration

package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"

	"github.com/elastic/elastic-agent-libs/kibana"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/estools"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
)

type EndpointMetricsMonRunner struct {
	suite.Suite
	info    *define.Info
	fixture *atesting.Fixture
}

func TestEndpointAgentServiceMonitoring(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		Local: false, // requires Agent installation
		Sudo:  true,  // requires Agent installation
		OS: []define.OS{
			{Type: define.Linux},
		},
	})

	// Get path to agent executable.
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err, "could not create agent fixture")

	runner := &EndpointMetricsMonRunner{
		info:    info,
		fixture: fixture,
	}

	suite.Run(t, runner)
}

func (runner *EndpointMetricsMonRunner) SetupSuite() {
	deadline := time.Now().Add(10 * time.Minute)
	ctx, cancel := testcontext.WithDeadline(runner.T(), context.Background(), deadline)
	defer cancel()

	runner.T().Log("Enrolling the agent in Fleet")
	policyUUID := uuid.New().String()

	createPolicyReq := kibana.AgentPolicy{
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

	policy, err := tools.InstallAgentWithPolicy(ctx, runner.T(),
		installOpts, runner.fixture, runner.info.KibanaClient, createPolicyReq)
	require.NoError(runner.T(), err, "failed to install agent with policy")

	runner.T().Log("Installing Elastic Defend")
	pkgPolicyResp, err := installElasticDefendPackage(runner.T(), runner.info, policy.ID)
	require.NoErrorf(runner.T(), err, "Policy Response was: %v", pkgPolicyResp)

	runner.T().Log("Polling for endpoint-security to become Healthy")
	ctx, cancel = context.WithTimeout(ctx, time.Minute*3)
	defer cancel()

	agentClient := runner.fixture.Client()
	err = agentClient.Connect(ctx)
	require.NoError(runner.T(), err, "could not connect to local agent")

	require.Eventually(runner.T(),
		func() bool { return agentAndEndpointAreHealthy(runner.T(), ctx, agentClient) },
		time.Minute*3,
		time.Second,
		"Endpoint component or units are not healthy.",
	)
}

func (runner *EndpointMetricsMonRunner) TestEndpointMetrics() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*15)
	defer cancel()

	agentStatus, err := runner.fixture.ExecStatus(ctx)
	require.NoError(runner.T(), err)

	endpointID := "endpoint-default"
	require.Eventually(runner.T(), func() bool {

		query := genESQueryByBinary(agentStatus.Info.ID, endpointID)
		res, err := estools.PerformQueryForRawQuery(ctx, query, "metrics-elastic_agent*", runner.info.ESClient)
		require.NoError(runner.T(), err)
		runner.T().Logf("Fetched metrics for %s, got %d hits", endpointID, res.Hits.Total.Value)
		return res.Hits.Total.Value >= 1
	}, time.Minute*10, time.Second*10, "could not fetch component metricsets for endpoint with ID %s and agent ID %s", endpointID, agentStatus.Info.ID)
}

// TODO: move to helpers.go
func genESQueryByBinary(agentID string, componentID string) map[string]interface{} {
	// see https://github.com/elastic/kibana/blob/main/x-pack/plugins/fleet/server/services/agents/agent_metrics.ts
	queryRaw := map[string]interface{}{
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"must": []map[string]interface{}{
					{
						"match": map[string]interface{}{
							"agent.id": agentID,
						},
					},
					{
						"match": map[string]interface{}{
							"component.id": componentID,
						},
					},
					{
						"exists": map[string]interface{}{
							"field": "system.process.cpu.total.value",
						},
					},
					{
						"exists": map[string]interface{}{
							"field": "system.process.memory.size",
						},
					},
				},
			},
		},
	}

	return queryRaw
}
