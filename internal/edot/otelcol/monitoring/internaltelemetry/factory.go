// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package internaltelemetry

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/service/telemetry"
	"go.opentelemetry.io/collector/service/telemetry/otelconftelemetry"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

/*type Config struct {
	otelconftelemetry.Config `mapstructure:",squash"`
}*/

type wrappedFactory struct {
	telemetry.Factory

	reader *sdkmetric.ManualReader
}

var factory *wrappedFactory

func NewFactory() telemetry.Factory {
	pid := os.Getpid()
	for i := range 20 {
		fmt.Printf("============= [%d] PID: %d =================================\n", i, pid)
		time.Sleep(time.Second)
	}

	//wrapped := otelconftelemetry.NewFactory()
	wrapped := &wrappedFactory{Factory: otelconftelemetry.NewFactory()}
	//return wrapped
	if factory == nil {
		factory = wrapped
	}
	return telemetry.NewFactory(
		wrapped.CreateDefaultConfig,
		telemetry.WithCreateResource(wrapped.CreateResource),
		telemetry.WithCreateMeterProvider(wrapped.CreateMeterProvider),
		telemetry.WithCreateLogger(wrapped.CreateLogger),
		telemetry.WithCreateTracerProvider(wrapped.CreateTracerProvider),
		//telemetry.WithCreateMeterProvider(createMeterProvider),
	)
}

var ErrNoReader = errors.New("no metrics reader")

func ReadMetrics(ctx context.Context) (*metricdata.ResourceMetrics, error) {
	if f := factory; f != nil {
		if r := f.reader; r != nil {
			var metrics metricdata.ResourceMetrics
			err := r.Collect(ctx, &metrics)
			return &metrics, err
		}
	}
	return nil, ErrNoReader
}

func (wf wrappedFactory) CreateDefaultConfig() component.Config {
	return wf.Factory.CreateDefaultConfig()
}

type meterProvider struct {
	telemetry.MeterProvider

	settings telemetry.MeterSettings
	file     *os.File
	writer   *bufio.Writer
}

/*
func createMeterProvider(ctx context.Context,

	meterSettings telemetry.MeterSettings,
	componentConfig component.Config,

	) (telemetry.MeterProvider, error) {
		p := sdkmetric.NewMeterProvider(
			//metric.WithResource(res),
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(nil)),
		)
		return p, nil
	}

func (wf wrappedFactory) CreateMeterProvider(

	ctx context.Context,
	meterSettings telemetry.MeterSettings,
	componentConfig component.Config,

	) (telemetry.MeterProvider, error) {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path := filepath.Join(homeDir, "otel-telemetry-test.txt")
		f, err := os.Create(path)
		if err != nil {
			return nil, err
		}
		w := bufio.NewWriter(f)

		mp, err := wf.Factory.CreateMeterProvider(ctx, meterSettings, componentConfig)
		if err != nil {
			return nil, err
		}

		return &meterProvider{
			MeterProvider: mp,
			settings:      meterSettings,
			file:          f,
			writer:        w,
		}, nil
	}
*/
func (mp *meterProvider) Meter(name string, opts ...metric.MeterOption) metric.Meter {
	message := fmt.Sprintf("hi fae, meter created with name %v", name)
	mp.writer.Write([]byte(message + "\n"))
	mp.writer.Flush()

	mp.settings.Logger.Error(message)
	return mp.MeterProvider.Meter(name, opts...)
}

func (mp *meterProvider) Shutdown(ctx context.Context) error {
	mp.file.Close()
	return mp.MeterProvider.Shutdown(ctx)
}
