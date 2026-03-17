// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package internaltelemetry

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/service/telemetry"
	"go.opentelemetry.io/collector/service/telemetry/otelconftelemetry"
	otelconf "go.opentelemetry.io/contrib/otelconf/v0.3.0"
	noopmetric "go.opentelemetry.io/otel/metric/noop"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
)

// wrappedFactory is a telemetry factory type that mostly passes through to a
// default otelconftelemetry factory, but adds a manual reader to the meter
// provider so we can translate and ingest metrics that are backwards
// compatible with existing ECS dashboards.
type wrappedFactory struct {
	telemetry.Factory

	reader atomic.Pointer[sdkmetric.ManualReader]
}

var ErrNoReader = errors.New("no metrics reader")

// We keep a global pointer to the telemetry factory because there's no direct
// way to pass data in and out -- the natural option would be an extension with
// a defined topology among collector components, but telemetry factories have
// no access to extensions (and vice versa), except by way of this sort of
// global hack.
// (The standard way to get telemetry data out of a factory is by using a
// separate dedicated exporter constructed along with the meter provider, but
// several technical constraints prevent that from being a near-term option for
// EDOT telemetry handling.)
var globalFactory atomic.Pointer[wrappedFactory]
var newFactoryOnce sync.Once

func NewFactory() telemetry.Factory {
	newFactoryOnce.Do(func() {
		// Initialize a wrapped telemetry factory with the collector's
		// default behavior.
		globalFactory.Store(&wrappedFactory{Factory: otelconftelemetry.NewFactory()})

	})
	return globalFactory.Load()
}

func ReadMetrics(ctx context.Context) (*metricdata.ResourceMetrics, error) {
	if f := globalFactory.Load(); f != nil {
		if r := f.reader.Load(); r != nil {
			var metrics metricdata.ResourceMetrics
			err := r.Collect(ctx, &metrics)
			return &metrics, err
		}
	}
	return nil, ErrNoReader
}

func (wf *wrappedFactory) CreateMeterProvider(
	ctx context.Context,
	set telemetry.MeterSettings,
	componentConfig component.Config,
) (telemetry.MeterProvider, error) {
	cfg := componentConfig.(*otelconftelemetry.Config)

	if cfg.Metrics.Level == configtelemetry.LevelNone {
		set.Logger.Info("Internal metrics telemetry disabled")
		return noopMeterProvider{MeterProvider: noopmetric.NewMeterProvider()}, nil
	} else if cfg.Metrics.Views == nil && set.DefaultViews != nil {
		// Apply default views to the config if none were specified
		cfg.Metrics.Views = set.DefaultViews(cfg.Metrics.Level)
	}

	// Create a resource for the meter provider.
	// We call through to the baseline resource creation so we get standard
	// fields, but we need to backconvert it to a config in order to assemble
	// the final meter provider with our manual reader added.
	res, err := wf.CreateResource(ctx, set.Settings, cfg)
	if err != nil {
		return nil, err
	}

	// Create a manual reader that will be invoked to record telemetry state.
	reader := sdkmetric.NewManualReader()

	// Create a meter provider that uses baseline behavior for the provided
	// configuration, but adding the manual reader after any baseline
	// configured ones.
	sdkConf := otelconf.OpenTelemetryConfiguration{
		Resource:      configFromCommonResource(res),
		MeterProvider: ptr(cfg.Metrics.MeterProvider),
	}
	sdk, err := otelconf.NewSDK(
		otelconf.WithOpenTelemetryConfiguration(sdkConf),
		otelconf.WithMeterProviderOptions(sdkmetric.WithReader(reader)),
	)
	if err != nil {
		return nil, err
	}
	wf.reader.Store(reader)

	return sdk.MeterProvider().(telemetry.MeterProvider), nil
}

// Given a pcommon.Resource, return the resource configuration
// (otelconf.Resource) to reproduce the same resource, ignoring any non-string
// values. (Current callers can't produce non-string values since the resource
// is created by the collector's default telemetry factory, but this could
// change if the default telemetry factory starts using non-strings in its
// resources. However, their absence is a strong enough assumption that the
// default telemetry factory itself intentionally panics if this happens.)
func configFromCommonResource(res pcommon.Resource) *otelconf.Resource {
	var attrs []otelconf.AttributeNameValue
	res.Attributes().Range(
		func(k string, v pcommon.Value) bool {
			if v.Type() == pcommon.ValueTypeStr {
				attrs = append(attrs, otelconf.AttributeNameValue{
					Name:  k,
					Value: v.Str(),
				})
			}
			return true
		})
	return &otelconf.Resource{
		SchemaUrl:  ptr(semconv.SchemaURL),
		Attributes: attrs,
	}
}

type noopMeterProvider struct {
	noopmetric.MeterProvider
}

func (noopMeterProvider) Shutdown(context.Context) error {
	return nil
}

func ptr[T any](v T) *T {
	return &v
}
