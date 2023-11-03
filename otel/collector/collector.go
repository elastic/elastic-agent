// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package collector presents an interface that wraps the OTel Collector Core
package collector

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/otel/factories"
	"go.opentelemetry.io/collector/otelcol"
	"go.uber.org/zap"
)

type Collector interface {
	Run(context.Context) error
}

type collector struct {
	configPaths []string
	version     string
	loggingOpts []zap.Option
}

func New(configPaths []string, version string, loggingOpts []zap.Option) (Collector, error) {
	return &collector{
		configPaths: configPaths,
		version:     version,
		loggingOpts: loggingOpts,
	}, nil
}

// Run the OTel collector
func (c *collector) Run(ctx context.Context) error {
	factories, err := factories.DefaultFactories()
	if err != nil {
		return fmt.Errorf("error from init factories: %w", err)
	}

	settings, err := NewSettings(c.configPaths, c.version, c.loggingOpts, factories)
	if err != nil {
		return err
	}

	svc, err := otelcol.NewCollector(*settings)
	if err != nil {
		return err
	}

	return svc.Run(ctx)
}
