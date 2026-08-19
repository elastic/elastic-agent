// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoringprocessor

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/processor"
	"go.uber.org/zap"
)

const Name = "elasticmonitoringprocessor"

// Config holds the configuration for the elasticmonitoringprocessor.
type Config struct {
	// ExporterNames maps OTel exporter component IDs to the agent component
	// names that appear in the generated monitoring events.
	ExporterNames map[string]string `mapstructure:"exporter_names"`
}

func NewFactory() processor.Factory {
	return processor.NewFactory(
		component.MustNewType(Name),
		createDefaultConfig,
		processor.WithMetrics(createProcessor, component.StabilityLevelAlpha),
	)
}

func createDefaultConfig() component.Config {
	return &Config{}
}

func createProcessor(
	_ context.Context,
	set processor.Settings,
	baseCfg component.Config,
	next consumer.Metrics,
) (processor.Metrics, error) {
	cfg := baseCfg.(*Config)
	res := pcommon.NewResource()
	set.Resource.CopyTo(res)
	return &monitoringProcessor{
		logger:   set.Logger,
		config:   cfg,
		resource: res,
		next:     next,
	}, nil
}

type monitoringProcessor struct {
	logger   *zap.Logger
	config   *Config
	resource pcommon.Resource
	next     consumer.Metrics
}

func (p *monitoringProcessor) Start(_ context.Context, _ component.Host) error { return nil }
func (p *monitoringProcessor) Shutdown(_ context.Context) error                { return nil }
func (p *monitoringProcessor) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}
