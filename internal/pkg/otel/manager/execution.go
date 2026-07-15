// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"time"

	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// ExecutionFactory creates a collectorExecution. It receives the collector
// binary path. Status reporting and liveness monitoring are handled by the
// manager's embedded OpAMP server (see opamp_server.go), so the execution
// layer does not need any extra handles.
type ExecutionFactory func(collectorPath string) (collectorExecution, error)

type collectorExecution interface {
	// startCollector starts the otel collector with the given configuration,
	// returning a handle that allows the manager to stop it. Cancelling ctx
	// stops all goroutines involved in the execution. Process exit errors are
	// reported via errCh; the manager observes status via the OpAMP server,
	// not through this interface.
	startCollector(
		ctx context.Context,
		logLevel logp.Level,
		collectorLogger *logger.Logger,
		logger *logger.Logger,
		cfg *confmap.Conf,
		errCh chan error,
	) (collectorHandle, error)
}

type collectorHandle interface {
	// Stop stops and waits for collector to exit gracefully within the given duration. Note that if the collector
	// doesn't exit within that time, it will be killed and then it will wait an extra second for it to ensure it's
	// really stopped.
	Stop(waitTime time.Duration)

	// Stopped returns whether the process represented the handle has exited.
	Stopped() bool

	// UpdateConfig sends a new configuration to the running collector for in-place reload.
	// Returns an error if the config could not be written.
	UpdateConfig(cfg *confmap.Conf) error

	// LogLevel returns the log level of the running collector.
	LogLevel() logp.Level
}
