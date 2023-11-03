// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package ess

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/testing/runner"
)

func TestProvisionGetRegions(t *testing.T) {
	_ = logp.DevelopmentSetup()
	key, found, err := GetESSAPIKey()
	if !found {
		t.Skip("No credentials found for ESS")
	}
	require.NoError(t, err)
	require.True(t, found)

	cfg := ProvisionerConfig{Region: "bad-region-ID", APIKey: key}
	prov := &ServerlessProvision{
		cfg:    cfg,
		stacks: map[string]stackhandlerData{},
		log:    &defaultLogger{wrapped: logp.L()},
	}
	err = prov.CheckCloudRegion()
	require.NoError(t, err)
	require.NotEqual(t, "bad-region-ID", prov.cfg.Region)

}

func TestStackProvisioner(t *testing.T) {
	_ = logp.DevelopmentSetup()
	key, found, err := GetESSAPIKey()
	if !found {
		t.Skip("No credentials found for ESS")
	}
	require.NoError(t, err)
	require.True(t, found)

	cfg := ProvisionerConfig{Region: "aws-eu-west-1", APIKey: key}
	provClient, err := NewServerlessProvisioner(cfg)
	require.NoError(t, err)
	request := runner.StackRequest{ID: "stack-test-one", Version: "8.9.0"}

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*5)
	defer cancel()
	stack, err := provClient.Create(ctx, request)
	require.NoError(t, err)
	t.Logf("got results:")
	t.Logf("stack: %#v", stack)
	require.NotEmpty(t, stack.Elasticsearch)
	require.NotEmpty(t, stack.Kibana)
	require.NotEmpty(t, stack.Password)
	require.NotEmpty(t, stack.Username)
	stack, err = provClient.WaitForReady(ctx, stack)
	require.NoError(t, err)
	t.Logf("tearing down...")
	err = provClient.Delete(ctx, stack)
	require.NoError(t, err)
}

func TestStartServerless(t *testing.T) {
	_ = logp.DevelopmentSetup()
	key, found, err := GetESSAPIKey()
	if !found {
		t.Skip("No credentials found for ESS")
	}
	require.NoError(t, err)
	clientHandle := NewServerlessClient("aws-eu-west-1",
		"observability",
		key,
		&defaultLogger{wrapped: logp.L()})

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*240)
	defer cancel()

	req := ServerlessRequest{Name: "ingest-e2e-test", RegionID: "aws-eu-west-1"}
	_, err = clientHandle.DeployStack(ctx, req)
	require.NoError(t, err)

	t.Logf("Waiting...")
	isReady, err := clientHandle.DeploymentIsReady(ctx)
	require.NoError(t, err)
	require.True(t, isReady)

	require.NotEmpty(t, clientHandle.proj.Endpoints)
	require.NotEmpty(t, clientHandle.proj.Credentials)
	t.Logf("got endpoints: %#v", clientHandle.proj.Endpoints)
	t.Logf("got auth: %#v", clientHandle.proj.Credentials)

	err = clientHandle.DeleteDeployment()
	require.NoError(t, err)
}
