// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package meterlifecycle releases the OTel meters a component holds once the
// component has stopped.
//
// The collector injects the component ID as an instrumentation *scope*
// attribute, and the SDK's meter cache is append-only, so a component instance
// that goes away still retains its meters, instruments and aggregators for the
// life of the MeterProvider. A full reload rebuilds the provider and reclaims
// everything, but a partial receiver reload does not, so memory grows with
// every receiver generation.
//
// The service already reports componentstatus.StatusStopped for each receiver a
// partial reload tears down. This extension turns that event into the release
// that the metric SDK offers no API for.
package meterlifecycle

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/component/componentstatus"
	"go.opentelemetry.io/collector/extension"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent/internal/edot/internaltelemetry"
)

var _ componentstatus.Watcher = (*meterLifecycleExtension)(nil)

type meterLifecycleExtension struct {
	logger *zap.Logger
}

func (e *meterLifecycleExtension) Start(context.Context, component.Host) error { return nil }

func (e *meterLifecycleExtension) Shutdown(context.Context) error { return nil }

// ComponentStatusChanged releases the meters held by a component once it has
// finished shutting down. The collector reports StatusStopped after the
// component's own Shutdown returns, so no callback can still be running.
func (e *meterLifecycleExtension) ComponentStatusChanged(source *componentstatus.InstanceID, event *componentstatus.Event) {
	if source == nil || event == nil || event.Status() != componentstatus.StatusStopped {
		return
	}
	id := source.ComponentID().String()
	internaltelemetry.ComponentStopped(context.Background(), id)
	if e.logger != nil {
		e.logger.Debug("released meters for stopped component",
			zap.String("otelcol.component.id", id),
			zap.Int("live_meter_components", internaltelemetry.LiveMeterComponents()),
		)
	}
}

func NewFactory() extension.Factory {
	return extension.NewFactory(
		component.MustNewType("elastic_meter_lifecycle"),
		func() component.Config { return &struct{}{} },
		func(_ context.Context, set extension.Settings, _ component.Config) (extension.Extension, error) {
			return &meterLifecycleExtension{logger: set.Logger}, nil
		},
		component.StabilityLevelDevelopment,
	)
}
