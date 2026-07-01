// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"context"
	"time"

	"go.uber.org/zap"

	"github.com/elastic/elastic-agent/internal/edot/internaltelemetry"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/receiver"
)

type monitoringReceiver struct {
	logger   *zap.Logger
	config   *Config
	consumer consumer.Metrics

	runCtx context.Context
	cancel context.CancelFunc

	// done is closed to signal that the receiver is finished shutting down.
	// We use a channel rather than a wait group so the wait duration can
	// be controlled by a provided context.
	done chan struct{}
}

func createReceiver(
	_ context.Context,
	set receiver.Settings,
	baseCfg component.Config,
	next consumer.Metrics,
) (receiver.Metrics, error) {
	cfg := baseCfg.(*Config)

	runCtx, cancel := context.WithCancel(context.Background())

	return &monitoringReceiver{
		logger:   set.Logger,
		config:   cfg,
		consumer: next,
		runCtx:   runCtx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}, nil
}

func (mr *monitoringReceiver) Start(_ context.Context, _ component.Host) error {
	go func() {
		defer close(mr.done)
		mr.run()
	}()
	return nil
}

func (mr *monitoringReceiver) Shutdown(ctx context.Context) error {
	mr.cancel()
	// Wait for the run loop to stop, but return immediately if the context
	// is cancelled.
	select {
	case <-mr.done:
	case <-ctx.Done():
	}
	return nil
}

func (mr *monitoringReceiver) run() {
	mr.updateMetrics()
	for mr.runCtx.Err() == nil {
		select {
		case <-mr.runCtx.Done():
		case <-time.After(mr.config.Interval):
			mr.updateMetrics()
		}
	}
}

func (mr *monitoringReceiver) updateMetrics() {
	resourceMetrics, err := internaltelemetry.ReadMetrics(mr.runCtx)
	if err != nil {
		// This isn't inherently an error state, internal telemetry could
		// be manually disabled, but it's not the expected path.
		mr.logger.Info("couldn't collect metrics", zap.Error(err))
		return
	}
	md := metricdataToPdata(resourceMetrics)
	if err := mr.consumer.ConsumeMetrics(mr.runCtx, md); err != nil && mr.runCtx.Err() == nil {
		// Don't log an error if the context is cancelled, that's just a normal shutdown
		mr.logger.Error("error sending internal telemetry metrics", zap.Error(err))
	}
}
