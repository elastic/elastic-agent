// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/receiver"
)

const (
	Name = "elasticmonitoringreceiver"
)

// Config holds the configuration for the elasticmonitoringreceiver.
// Event templates, exporter name mappings, and datastream routing live in the
// downstream elasticmonitoringconnector; this receiver is only responsible for
// polling interval.
type Config struct {
	Interval time.Duration `mapstructure:"interval"`
}

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		component.MustNewType(Name),
		createDefaultConfig,
		receiver.WithMetrics(createReceiver, component.StabilityLevelAlpha))
}

func createDefaultConfig() component.Config {
	return &Config{
		Interval: 60 * time.Second,
	}
}
