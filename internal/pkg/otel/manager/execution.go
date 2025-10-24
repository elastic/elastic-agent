// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent/pkg/core/logger"
)

type collectorExecution interface {
	// startCollector starts the otel collector with the given arguments, returning a handle allowing it to be stopped.
	// Cancelling the context will stop all goroutines involved in the execution.
	// The collector will report status events in the statusCh channel and errors on errCh in a non-blocking fashion,
	// draining the channel before writing to it.
	// After the collector exits, it will emit an error describing the exit status (nil if successful) and a nil status.
	startCollector(ctx context.Context, baseLogger *logger.Logger, logger *logger.Logger, cfg *confmap.Conf, errCh chan error, statusCh chan *status.AggregateStatus) (collectorHandle, error)
}

type collectorHandle interface {
	// Stop stops and waits for collector to exit gracefully within the given duration. Note that if the collector
	// doesn't exit within that time, it will be killed and then it will wait an extra second for it to ensure it's
	// really stopped.
	Stop(waitTime time.Duration)
}
