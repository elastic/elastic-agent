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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

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

	searchResp, err := info.ESClient.Search(info.ESClient.Search.WithContext(ctx), info.ESClient.Search.WithIndex(".fleet-agents"), info.ESClient.Search.WithBody(strings.NewReader(`{
          "query": {
	    "term": {
	      "policy_id": "policy-elastic-agent-on-cloud"
	    }
	  }
	}`)))
	require.NoError(t, err)
	defer searchResp.Body.Close()
	require.Equal(t, http.StatusOK, searchResp.StatusCode)

	respObj := struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Source struct {
					LocalMetadata struct {
						Elastic struct {
							Agent struct {
								FIPS bool `json:"fips"`
							} `json:"agent"`
						} `json:"elastic"`
					} `json:"local_metadata"`
					LastCheckinStatus string `json:"last_checkin_status"`
					LastCheckinReason string `json:"last_checkin_reason"`
				} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}{}

	err = json.NewDecoder(searchResp.Body).Decode(&respObj)
	require.NoError(t, err)
	require.Equal(t, 1, respObj.Hits.Total.Value, "expected only one hit from the ES query")
	require.True(t, respObj.Hits.Hits[0].Source.LocalMetadata.Elastic.Agent.FIPS)
	//require.Equalf(t, "online", respObj.Hits.Hits[0].Source.LastCheckinStatus, "last_checkin_status did not meet expectation, unhealthy reason: %v", respObj.Hits.Hits[0].Source.LastCheckinReason) // FIXME: Uncomment after https://github.com/elastic/apm-server/issues/17063 is resolved
}
