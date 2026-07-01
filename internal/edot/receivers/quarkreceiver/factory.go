// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package quarkreceiver // import "github.com/elastic/elastic-agent/internal/edot/receivers/quarkreceiver"

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"

	"github.com/elastic/elastic-agent/internal/edot/receivers/quarkreceiver/internal/metadata"
)

// NewFactory creates a new factory for the quark receiver.
func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		metadata.Type,
		createDefaultConfig,
		receiver.WithLogs(createLogsReceiver, metadata.LogsStability),
	)
}

// createDefaultConfig creates the default configuration for the receiver.
func createDefaultConfig() component.Config {
	return &Config{
		Interval: time.Second,
		Message:  "quark",
	}
}

// createLogsReceiver creates a new logs receiver instance.
func createLogsReceiver(
	_ context.Context,
	params receiver.Settings,
	cfg component.Config,
	consumer consumer.Logs,
) (receiver.Logs, error) {
	config := cfg.(*Config)
	return newQuarkReceiver(params, config, consumer), nil
}
