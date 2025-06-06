// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools"
	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cloudAgentPolicyID = "policy-elastic-agent-on-cloud"

// FIPSTest exercises a FIPS-capable Elastic Agent against a FIPS-capable Fleet Server
// running in ECH. Concretely, it exercises the following functionality:
//   - Building a local, FIPS-capable Elastic Agent Docker image that's deployable
//     to ECH in a FRH region (this is actually done by the CI pipeline running this integration
//     test).
//   - Creating a ECH deployment with the FIPS-capable Elastic Agent Docker image, which
//     run as Integrations Server / Fleet Server in the deployment (also done by the CI pipeline).
//   - Ensure that the ensures that the FIPS-capable Elastic Agent running in ECH is able to
//     successfully connect to its own local Fleet Server instance (which, by definition should
//     also be FIPS-capable and running in ECH).
//   - Installing the local FIPS-capable Elastic Agent artifact locally and enrolling it with the
//     ECH deployment's Fleet Server.
//   - Adding an integration to the Agent's policy. This has the effect of exercising
//     the connectivity between the Fleet UI (Kibana) in the ECH deployment and the Elastic Package
//     Registry (EPR) as well as the connectivity between the data collection component run by the
//     local Elastic Agent and Elasticsearch. The test checks that data for this integration shows
//     up in the Elasticsearch cluster that's part of the ECH deployment.
//   - Upgrading the local FIPS-capable Elastic Agent and ensuring that it only upgrades to another
//     FIPS-capable Elastic Agent version.
func FIPSTest(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Fleet,
		Stack: &define.Stack{},
		OS: []define.OS{
			{Type: define.Linux},
		},
		Sudo:  false,
		Local: true,

		// Ensures the test will run in a FIPS-configured environment against a
		// deployment in ECH that's running a FIPS-capable integrations server.
		FIPS: true,
	})

	ensureFleetServerInDeploymentIsHealthyAndFIPSCapable(t, info)
	fixture, policyID := enrollLocalFIPSAgentInFleetServer(t, info)
	addIntegrationAndCheckData(t, info, fixture, policyID)
	upgradeFIPSAgent(t, info)
}

func ensureFleetServerInDeploymentIsHealthyAndFIPSCapable(t *testing.T, info *define.Info) {
	t.Helper()

	// Check that the Fleet Server in the deployment is healthy
	fleetServerHost := os.Getenv("INTEGRATIONS_SERVER_HOST")
	statusUrl, err := url.JoinPath(fleetServerHost, "/api/status")
	require.NoError(t, err)

	resp, err := http.Get(statusUrl)
	require.NoError(t, err)
	defer resp.Body.Close()

	var body struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	decoder := json.NewDecoder(resp.Body)
	err = decoder.Decode(&body)
	require.NoError(t, err)

	require.Equal(t, "HEALTHY", body.Status)

	// Get all Agents
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	agents, err := info.KibanaClient.ListAgents(ctx, kibana.ListAgentsRequest{})
	require.NoError(t, err)

	// Find Fleet Server's own Agent and get its status and whether it's
	// FIPS-capable
	var agentStatus string
	var agentIsFIPS bool
	for _, item := range agents.Items {
		if item.PolicyID == cloudAgentPolicyID {
			agentStatus = item.Status
			agentIsFIPS = item.LocalMetadata.Elastic.Agent.FIPS
		}
	}

	// Check that this Agent is online (i.e. healthy) and is FIPS-capable. This
	// will prove that a FIPS-capable Agent is able to connect to a FIPS-capable
	// Fleet Server, with both running in ECH.
	require.Equal(t, "online", agentStatus)
	require.Equal(t, true, agentIsFIPS)
}

func enrollLocalFIPSAgentInFleetServer(t *testing.T, info *define.Info) (*atesting.Fixture, string) {
	t.Helper()
	// Select FIPS-capable local Agent artifact
	fixture, err := define.NewFixtureFromLocalFIPSBuild(t, define.Version())
	require.NoError(t, err)

	// Enroll Agent
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

	policyResp, _, err := tools.InstallAgentWithPolicy(ctx, t, installOpts, fixture, info.KibanaClient, basePolicy)
	require.NoError(t, err)

	return fixture, policyResp.ID
}

func addIntegrationAndCheckData(t *testing.T, info *define.Info, fixture *atesting.Fixture, policyID string) {
	t.Helper()

	// Install system integration
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	_, err := tools.InstallPackageFromDefaultFile(ctx, info.KibanaClient, "system", preinstalledPackages["system"], "system_integration_setup.json", uuid.Must(uuid.NewV4()).String(), policyID)
	require.NoError(t, err)

	// Ensure data from system integration shows up in Elasticsearch
	status, err := fixture.ExecStatus(ctx)
	require.NoError(t, err)

	docs, err := estools.GetResultsForAgentAndDatastream(ctx, info.ESClient, "system.cpu", status.Info.ID)
	assert.NoError(t, err, "error fetching system metrics")
	assert.Greater(t, docs.Hits.Total.Value, 0, "could not find any matching system metrics for agent ID %s", status.Info.ID)
	t.Logf("Generated %d system events", docs.Hits.Total.Value)
}

func upgradeFIPSAgent(t *testing.T, info *define.Info) {
	t.Helper()
	// TODO
}
