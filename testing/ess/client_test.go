// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ess

import (
	"fmt"
	"os"
	"testing"
)

func TestClient_CreateDeployment(t *testing.T) {
	essApiKey := os.Getenv("ESS_API_KEY")
	if essApiKey == "" {
		t.Skip("ESS_API_KEY (for QA) environment variable not set")
	}

	cfg := Config{ApiKey: essApiKey}

	client := NewClient(cfg)
	resp, err := client.CreateDeployment(CreateDeploymentRequest{
		Name:    "test-880",
		Region:  "gcp-us-central1",
		Version: "8.8.0-SNAPSHOT",
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: %s\n", err.Error())
		os.Exit(1)
	}

	t.Logf("creation response: %#+v\n", resp)
}
