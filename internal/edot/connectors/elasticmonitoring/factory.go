// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/connector"
)

const (
	Name = "elasticmonitoringconnector"
)

// Config holds the configuration for the elasticmonitoringconnector.
// The polling interval lives in the upstream elasticmonitoringreceiver; this
// connector is stateless and only handles the metric-to-log conversion.
type Config struct {
	// EventTemplate provides the static fields included in every generated
	// exporter/pipeline metrics event. If data_stream.* is present those fields
	// are set as log record attributes so the elasticsearch exporter routes the
	// event to the correct datastream.
	EventTemplate struct {
		Fields map[string]any `mapstructure:",remain"`
	} `mapstructure:"event_template"`

	// InputEventTemplate provides the static fields for per-input events.
	InputEventTemplate struct {
		Fields map[string]any `mapstructure:",remain"`
	} `mapstructure:"input_event_template"`

	// ExporterNames maps OTel exporter component IDs to the agent component name
	// that should appear in the generated log record.
	ExporterNames map[string]string `mapstructure:"exporter_names"`
}

func NewFactory() connector.Factory {
	return connector.NewFactory(
		component.MustNewType(Name),
		createDefaultConfig,
		connector.WithMetricsToLogs(createConnector, component.StabilityLevelAlpha),
	)
}

func createDefaultConfig() component.Config {
	return &Config{}
}
