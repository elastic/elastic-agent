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

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
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

	// Further, the Fleet Server must be configured with FIPS-compliant TLS (TLSv1.2
	// and TLSv1.3 and appropriate ciphers).

	// Check that the Fleet Server in the deployment is healthy
	fleetServerHost := os.Getenv("FLEETSERVER_HOST")
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
	ctx, cancel := context.WithTimeout(5*time.Second, context.Background())
	defer cancel()
	agents, err := info.KibanaClient.ListAgents(ctx)
	require.NoError(t, err)

	// Find Fleet Server's own Agent and get its status and whether it's
	// FIPS-capable
	var agentStatus string
	var agentIsFIPS bool
	for _, item := range agents.Items {
		if item.PolicyID == cloudAgentPolicyID {
			agentStatus = item.Status
			//agentIsFIPS = item.LocalMetadata.Elastic.Agent.FIPS
		}
	}

	// Check that this Agent is online (i.e. healthy) and is FIPS-capable. This
	// will prove that a FIPS-capable Agent is able to connect to a FIPS-capable
	// Fleet Server, with both running in ECH.
	require.Equal(t, "online", agentStatus)
	require.Equal(t, true, agentIsFIPS)
}
