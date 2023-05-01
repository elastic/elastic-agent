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
