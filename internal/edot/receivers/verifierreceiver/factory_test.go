// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifierreceiver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/receiver/receivertest"

	"github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/metadata"
)

func TestNewFactory(t *testing.T) {
	factory := NewFactory()
	require.NotNil(t, factory)

	assert.Equal(t, "verifier", factory.Type().String())
}

func TestCreateDefaultConfig(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig()

	require.NotNil(t, cfg)
	config, ok := cfg.(*Config)
	require.True(t, ok)

	assert.Empty(t, config.Policies)
	assert.Equal(t, "on_demand", config.VerificationType)
}

func TestCreateLogsReceiver(t *testing.T) {
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*Config)

	// Set up required configuration per RFC structure
	cfg.IdentityFederationID = "cc-test-001"
	cfg.VerificationID = "verify-test-001"
	cfg.Policies = []PolicyConfig{
		{
			PolicyID:   "policy-1",
			PolicyName: "Test Policy",
			Integrations: []IntegrationConfig{
				{
					PolicyTemplate:  "cloudtrail",
					PackageName:     "aws",
					PackagePolicyID: "pp-001",
					PackageTitle:    "AWS",
					Config: map[string]interface{}{
						"account_id": "123456789012",
						"region":     "us-east-1",
					},
				},
			},
		},
	}

	consumer := consumertest.NewNop()
	receiver, err := factory.CreateLogs(
		context.Background(),
		receivertest.NewNopSettings(metadata.Type),
		cfg,
		consumer,
	)

	require.NoError(t, err)
	require.NotNil(t, receiver)

	// Verify it can start and shutdown
	err = receiver.Start(context.Background(), componenttest.NewNopHost())
	require.NoError(t, err)

	err = receiver.Shutdown(context.Background())
	require.NoError(t, err)
}
