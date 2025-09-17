// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"fmt"
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

type MonitoringRunner struct {
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

func TestMonitoringLivenessReloadable(t *testing.T) {
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

	suite.Run(t, &MonitoringRunner{info: info, healthCheckTime: time.Minute * 5, healthCheckRefreshTime: time.Second * 5})
}

func (runner *MonitoringRunner) SetupSuite() {
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

	policyResp, agentID, err := tools.InstallAgentWithPolicy(ctx, runner.T(), installOpts, runner.agentFixture, runner.info.KibanaClient, basePolicy)
	require.NoError(runner.T(), err)

	runner.policyID = policyResp.ID
	runner.policyName = basePolicy.Name
	runner.agentID = agentID

	_, err = tools.InstallPackageFromDefaultFile(ctx, runner.info.KibanaClient, "system",
		integration.PreinstalledPackages["system"], "testdata/system_integration_setup.json", uuid.Must(uuid.NewV4()).String(), policyResp.ID)
	require.NoError(runner.T(), err)
}

func (runner *MonitoringRunner) TestMonitoringLiveness() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*10)
	defer cancel()

	runner.AllComponentsHealthy(ctx)

	client := http.Client{Timeout: time.Second * 4}
	endpoint := "http://localhost:6792/liveness"
	// first stage: ensure the default behavior, http monitoring is off. This should return an error
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	require.NoError(runner.T(), err)

	_, err = client.Do(req)
	require.Error(runner.T(), err)

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

	// check to make sure that we now have a liveness probe response
	require.EventuallyWithT(runner.T(), func(collect *assert.CollectT) {
		req, err = http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		require.NoError(collect, err)
	}, time.Minute, time.Second)

	// second check: the /liveness endpoint should now be responding
	runner.CheckResponse(ctx, endpoint)

	runner.CheckResponse(ctx, fmt.Sprintf("%s?failon=degraded", endpoint))

	runner.CheckResponse(ctx, fmt.Sprintf("%s?failon=failed", endpoint))

	runner.CheckResponse(ctx, fmt.Sprintf("%s?failon=heartbeat", endpoint))
}

// CheckResponse checks to see if the liveness probe returns a 200
func (runner *MonitoringRunner) CheckResponse(ctx context.Context, endpoint string) {
	req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
	require.NoError(runner.T(), err)

	client := http.Client{Timeout: time.Second * 4}

	livenessResp, err := client.Do(req)
	require.NoError(runner.T(), err)
	defer livenessResp.Body.Close()
	require.Equal(runner.T(), http.StatusOK, livenessResp.StatusCode) // this is effectively the check for the test
}

// AllComponentsHealthy ensures all the beats and agent are healthy and working before we continue
func (runner *MonitoringRunner) AllComponentsHealthy(ctx context.Context) {
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
