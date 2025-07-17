// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/elastic-agent/testing/integration"
)

func TestECH(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.ECH,
		Stack: &define.Stack{},
		Sudo:  true,
		Local: false,
		OS: []define.OS{
			{
				Type: define.Linux,
			},
		},
	})

	// Check that the Fleet Server in the deployment is healthy
	fleetServerHost, err := fleettools.DefaultURL(t.Context(), info.KibanaClient)
	statusUrl, err := url.JoinPath(fleetServerHost, "/api/status")
	require.NoError(t, err)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		resp, err := http.Get(statusUrl)
		require.NoError(c, err)
		defer resp.Body.Close()

		require.Equal(c, http.StatusOK, resp.StatusCode)

		var body struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(c, err)

		t.Logf("body.status = %s", body.Status)
		require.Equal(c, "HEALTHY", body.Status)
	}, 5*time.Minute, 10*time.Second, "Fleet Server in ECH deployment is not healthy")

	// Create a policy and install an agent
	policyUUID := uuid.Must(uuid.NewV4()).String()
	policy := kibana.AgentPolicy{
		Name:              "testloglevel-policy-" + policyUUID,
		Namespace:         "default",
		Description:       "Test Log Level Policy " + policyUUID,
		MonitoringEnabled: []kibana.MonitoringEnabledOption{},
	}
	t.Log("Creating Agent policy...")
	policyResp, err := info.KibanaClient.CreatePolicy(t.Context(), policy)
	require.NoError(t, err, "failed creating policy")

	t.Log("Creating Agent enrollment API key...")
	createEnrollmentApiKeyReq := kibana.CreateEnrollmentAPIKeyRequest{
		PolicyID: policyResp.ID,
	}
	enrollmentToken, err := info.KibanaClient.CreateEnrollmentAPIKey(t.Context(), createEnrollmentApiKeyReq)
	require.NoError(t, err, "failed creating enrollment API key")
	t.Logf("Created policy %+v", policyResp.AgentPolicy)

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = fixture.Prepare(t.Context())
	require.NoError(t, err)

	opts := &atesting.InstallOpts{
		Force:      true,
		Privileged: true,
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetServerHost,
			EnrollmentToken: enrollmentToken.APIKey,
		},
	}
	out, err := fixture.Install(t.Context(), opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	var agentID string
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := fixture.ExecStatus(t.Context())
		require.NoError(c, err)
		statusBuffer := new(strings.Builder)
		err = json.NewEncoder(statusBuffer).Encode(status)
		require.NoError(c, err)
		t.Logf("agent status: %v", statusBuffer.String())

		require.Equal(c, int(cproto.State_HEALTHY), status.State, "agent state is not healthy")
		require.Equal(c, int(cproto.State_HEALTHY), status.FleetState, "agent's fleet-server state is not healthy")
		agentID = status.Info.ID
	}, time.Minute, time.Second, "agent never became healthy or connected to Fleet")

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := fleettools.GetAgentStatus(t.Context(), info.KibanaClient, agentID)
		require.NoError(c, err)
		require.Equal(c, "online", status)
	}, time.Minute, time.Second, "agent does not show as online in fleet")

	t.Run("run uninstall", testUninstallAuditUnenroll(t.Context(), fixture, info))
}
