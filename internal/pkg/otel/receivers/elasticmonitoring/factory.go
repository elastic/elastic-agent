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

type Config struct {
	// EventTemplate provides the static fields that will be included in every
	// generated event. If data_stream.* is present, these fields will be set
	// as attributes on the resulting log record, so the elasticsearch
	// exporter will route it to the correct datastream.
	EventTemplate struct {
		Fields map[string]interface{} `mapstructure:",remain"`
	} `mapstructure:"event_template"`

	Interval time.Duration `mapstructure:"interval"`

	// A map from OTel exporter IDs to the component name that should be used
	// when reporting their metrics.
	ExporterNames map[string]string `mapstructure:"exporter_names"`
}

func NewFactory() receiver.Factory {
	return receiver.NewFactory(
		component.MustNewType(Name),
		createDefaultConfig,
		receiver.WithLogs(createReceiver, component.StabilityLevelAlpha))
}

func createDefaultConfig() component.Config {
	return &Config{
		Interval: 60 * time.Second,
	}
}
