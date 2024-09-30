// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package ess

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/pkg/testing/common"
)

func TestProvisionGetRegions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	_ = logp.DevelopmentSetup()
	key, found, err := GetESSAPIKey()
	if !found {
		t.Skip("No credentials found for ESS")
	}
	require.NoError(t, err)
	require.True(t, found)

	cfg := ProvisionerConfig{Region: "bad-region-ID", APIKey: key}
	prov := &ServerlessProvisioner{
		cfg: cfg,
		log: &defaultLogger{wrapped: logp.L()},
	}
	err = prov.CheckCloudRegion(ctx)
	require.NoError(t, err)
	require.NotEqual(t, "bad-region-ID", prov.cfg.Region)

}

func TestStackProvisioner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	_ = logp.DevelopmentSetup()
	key, found, err := GetESSAPIKey()
	if !found {
		t.Skip("No credentials found for ESS")
	}
	require.NoError(t, err)
	require.True(t, found)

	cfg := ProvisionerConfig{Region: "aws-eu-west-1", APIKey: key}
	provClient, err := NewServerlessProvisioner(ctx, cfg)
	require.NoError(t, err)
	request := common.StackRequest{ID: "stack-test-one", Version: "8.9.0"}

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

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
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

	err = clientHandle.DeleteDeployment(ctx)
	require.NoError(t, err)
}
