// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ess

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestClient_CreateAndShutdownDeployment(t *testing.T) {
	essApiKey := os.Getenv("ESS_API_KEY")
	if essApiKey == "" {
		t.Skip("ESS_API_KEY (for QA) environment variable not set")
	}

	cfg := Config{ApiKey: essApiKey}
	client := NewClient(cfg)

	// Create deployment
	resp, err := client.CreateDeployment(context.Background(), CreateDeploymentRequest{
		Name:    "test-880",
		Region:  "gcp-us-central1",
		Version: "8.8.0-SNAPSHOT",
	})
	require.NoError(t, err)
	t.Logf("creation response: %#+v\n", resp)

	require.NotEmpty(t, resp.ID)
	require.NotEmpty(t, resp.ElasticsearchEndpoint)
	require.NotEmpty(t, resp.KibanaEndpoint)
	require.NotEmpty(t, resp.Username)
	require.NotEmpty(t, resp.Password)

	// Wait until deployment is started
	require.Eventually(t, func() bool {
		status, err := client.DeploymentStatus(context.Background(), resp.ID)
		require.NoError(t, err)

		t.Logf("deployment status: %#+v\n", status)
		return status.Overall == DeploymentStatusStarted
	}, 5*time.Minute, 10*time.Second)

	// Delay shutdown if requested (useful for debugging)
	shutdownDelayStr := os.Getenv("ESS_CLIENT_TEST_SHUTDOWN_DELAY_SECONDS")
	if shutdownDelayStr != "" {
		shutdownDelayVal, err := strconv.Atoi(shutdownDelayStr)
		require.NoError(t, err)

		shutdownDelay := time.Duration(shutdownDelayVal) * time.Second
		t.Logf("delaying shutdown by [%d] seconds\n", shutdownDelayVal)
		time.Sleep(shutdownDelay)
	}

	// Shutdown deployment
	err = client.ShutdownDeployment(context.Background(), resp.ID)
	require.NoError(t, err)
}
