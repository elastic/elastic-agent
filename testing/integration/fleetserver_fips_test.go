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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

const cloudAgentPolicyID = "policy-elastic-agent-on-cloud"

// TestFIPSAgentConnectingToFIPSFleetServerInECHFRH ensures that a FIPS-capable Elastic Agent
// running in an ECH FRH (FedRamp High) environment is able to successfully connect to its
// own local Fleet Server instance (which, by definition should also be FIPS-capable and
// running in the ECH FRH environment).
func TestFIPSAgentConnectingToFIPSFleetServerInECHFRH(t *testing.T) {
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

	fleetServerHost, err := fleettools.DefaultURL(t.Context(), info.KibanaClient)
	require.NoError(t, err)
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

	require.Equalf(t, "HEALTHY", body.Status, "response status code: %d", resp.StatusCode)

	// Get all Agents
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	agents, err := info.KibanaClient.ListAgents(ctx, kibana.ListAgentsRequest{})
	require.NoError(t, err)

	// Find Fleet Server's own Agent and get its status and whether it's
	// FIPS-capable
	//var agentStatus string
	var agentIsFIPS bool
	for _, item := range agents.Items {
		if item.PolicyID == cloudAgentPolicyID {
			t.Logf("Found fleet-server entry: %+v", item)
			//agentStatus = item.Status
			agentIsFIPS = item.LocalMetadata.Elastic.Agent.FIPS
			break
		}
	}

	// Check that this Agent is online (i.e. healthy) and is FIPS-capable. This
	// will prove that a FIPS-capable Agent is able to connect to a FIPS-capable
	// Fleet Server, with both running in ECH.
	require.Equal(t, true, agentIsFIPS)
	//require.Equal(t, "online", agentStatus) // FIXME: Uncomment after https://github.com/elastic/apm-server/issues/17063 is resolved
}
