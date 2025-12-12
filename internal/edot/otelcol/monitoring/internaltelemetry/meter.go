// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package internaltelemetry

import (
	"context"

	noopmetric "go.opentelemetry.io/otel/metric/noop"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configtelemetry"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/service/telemetry"
	"go.opentelemetry.io/collector/service/telemetry/otelconftelemetry"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	sdkresource "go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.18.0"
)

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
		cfg.Metrics.Views = set.DefaultViews(cfg.Metrics.Level)
	}

	res, err := wf.CreateResource(ctx, set.Settings, cfg) //newResource(set.Settings, cfg)
	if err != nil {
		return nil, err
	}
	raw := stripResource(res)
	wf.reader = sdkmetric.NewManualReader()
	p := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(raw),
		//sdkmetric.WithReader(sdkmetric.NewPeriodicReader(&something{})),
		sdkmetric.WithReader(wf.reader))
	//sdkmetric.NewManualReader()
	return p, nil

	/*
		mpConfig := cfg.Metrics.MeterProvider
		sdk, err := newSDK(ctx, res, config.OpenTelemetryConfiguration{
			MeterProvider: &mpConfig,
		})
		if err != nil {
			return nil, err
		}
		return sdk.MeterProvider().(telemetry.MeterProvider), nil*/
}

func stripResource(r pcommon.Resource) *sdkresource.Resource {
	var attrs []attribute.KeyValue
	r.Attributes().Range(
		func(k string, v pcommon.Value) bool {
			if v.Type() == pcommon.ValueTypeStr {
				attrs = append(attrs, attribute.String(k, v.Str()))
			}
			return true
		})
	return sdkresource.NewWithAttributes(semconv.SchemaURL, attrs...)
}

type noopMeterProvider struct {
	noopmetric.MeterProvider
}

func (noopMeterProvider) Shutdown(context.Context) error {
	return nil
}
