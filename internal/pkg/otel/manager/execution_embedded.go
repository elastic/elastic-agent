// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/otelcol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/internal/pkg/otel/agentprovider"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func newExecutionEmbedded() *embeddedExecution {
	return &embeddedExecution{}
}

type embeddedExecution struct {
}

// startCollector starts the collector in a new goroutine.
func (r *embeddedExecution) startCollector(ctx context.Context, logger *logger.Logger, cfg *confmap.Conf, errCh chan error, statusCh chan *status.AggregateStatus) (collectorHandle, error) {
	collectorCtx, collectorCancel := context.WithCancel(ctx)
	ap := agentprovider.NewProvider(cfg)

	ctl := &ctxHandle{
		collectorDoneCh: make(chan struct{}),
		cancel:          collectorCancel,
	}

	// NewForceExtensionConverterFactory is used to ensure that the agent_status extension is always enabled.
	// It is required for the Elastic Agent to extract the status out of the OTel collector.
	settings := otel.NewSettings(
		release.Version(), []string{ap.URI()},
		otel.WithConfigProviderFactory(ap.NewFactory()),
		otel.WithConfigConvertorFactory(NewForceExtensionConverterFactory(AgentStatusExtensionType.String(), nil)),
		otel.WithExtensionFactory(NewAgentStatusFactory(statusCh)))
	settings.DisableGracefulShutdown = true // managed by this manager
	settings.LoggingOptions = []zap.Option{zap.WrapCore(func(zapcore.Core) zapcore.Core {
		return logger.Core() // use same zap as agent
	})}
	svc, err := otelcol.NewCollector(*settings)
	if err != nil {
		collectorCancel()
		return nil, err
	}
	go func() {
		runErr := svc.Run(collectorCtx)
		close(ctl.collectorDoneCh)
		reportErr(ctx, errCh, runErr)
	}()
	return ctl, nil
}

type ctxHandle struct {
	collectorDoneCh chan struct{}
	cancel          context.CancelFunc
}

// Stop stops the collector
func (s *ctxHandle) Stop(ctx context.Context) {
	if s.cancel == nil {
		return
	}

	s.cancel()

	select {
	case <-ctx.Done():
	case <-s.collectorDoneCh:
	}
}
