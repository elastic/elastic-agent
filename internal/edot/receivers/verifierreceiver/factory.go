// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package verifierreceiver // import "github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"

	"github.com/elastic/elastic-agent/internal/edot/receivers/verifierreceiver/internal/metadata"
)

// NewFactory creates a new factory for the verifier receiver.
// The verifier receiver supports multiple cloud providers (AWS, Azure, GCP, Okta)
// and verifies permissions for configured integrations.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithLogs(createLogsReceiver, metadata.LogsStability),
	)
}

// createDefaultConfig creates the default configuration for the receiver.
// Provider credentials are optional and can be configured per-provider.
func createDefaultConfig() component.Config {
	return &Config{
		VerificationType: "on_demand",
		Providers:        ProvidersConfig{},
		Policies:         []PolicyConfig{},
	}
}

// createLogsReceiver creates a new logs receiver instance.
// The receiver initializes verifiers for configured providers and
// verifies permissions based on the configured policies.
func createLogsReceiver(
	_ context.Context,
	params receiver.Settings,
	cfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	config := cfg.(*Config)
	return newVerifierReceiver(params, config, consumer), nil
}
