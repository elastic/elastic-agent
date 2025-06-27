// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
)

func TestECH(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: ECH,
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

	require.Eventually(t, func() bool {
		resp, err := http.Get(statusUrl)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)

		var body struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		}
		err = json.NewDecoder(resp.Body).Decode(&body)
		require.NoError(t, err)

		t.Logf("body.status = %s", body.Status)
		return body.Status == "HEALTHY"
	}, 5*time.Minute, 10*time.Second, "Fleet Server in ECH deployment is not healthy")

	// Create a policy and install an agent
	policyResp, enrollmentTokenResp := createPolicyAndEnrollmentToken(ctx, t, info.KibanaClient, createBasicPolicy())
	t.Logf("Created policy %+v", policyResp.AgentPolicy)

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	opts := &atesting.InstallOpts{
		Force:      true,
		Privileged: true,
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetServerHost,
			EnrollmentToken: enrollmentTokenResp.APIKey,
		},
	}
	out, err := fixture.Install(ctx, opts)
	if err != nil {
		t.Logf("install output: %s", out)
		require.NoError(t, err)
	}

	require.Eventuallyf(t, func() bool {
		return waitForAgentAndFleetHealthy(ctx, t, fixture)
	}, time.Minute, time.Second, "agent never became healthy or connected to Fleet")

	t.Run("run uninstall", testUninstallAuditUnenroll(ctx, fixture, info))
}
