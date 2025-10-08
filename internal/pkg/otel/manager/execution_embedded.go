// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/otelcol"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/otel"
	"github.com/elastic/elastic-agent/internal/pkg/otel/agentprovider"
	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// newExecutionEmbedded creates a new execution which runs the otel collector in a goroutine. A metricsPort of 0 will
// result in a random port being used.
func newExecutionEmbedded(metricsPort int) *embeddedExecution {
	return &embeddedExecution{collectorMetricsPort: metricsPort}
}

type embeddedExecution struct {
	collectorMetricsPort int
}

// startCollector starts the collector in a new goroutine.
func (r *embeddedExecution) startCollector(ctx context.Context, logger *logger.Logger, cfg *confmap.Conf, errCh chan error, statusCh chan *status.AggregateStatus) (collectorHandle, error) {
	collectorCtx, collectorCancel := context.WithCancel(ctx)
	ap := agentprovider.NewProvider(cfg)

	ctl := &ctxHandle{
		collectorDoneCh: make(chan struct{}),
		cancel:          collectorCancel,
	}
	extConf := map[string]any{
		"endpoint": paths.DiagnosticsExtensionSocket(),
	}
	collectorMetricsPort, err := r.getCollectorMetricsPort()
	if err != nil {
		return nil, err
	}
	// NewForceExtensionConverterFactory is used to ensure that the agent_status extension is always enabled.
	// It is required for the Elastic Agent to extract the status out of the OTel collector.
	settings := otel.NewSettings(
		release.Version(), []string{ap.URI()},
		otel.WithConfigProviderFactory(ap.NewFactory()),
		otel.WithConfigConvertorFactory(NewForceExtensionConverterFactory(AgentStatusExtensionType.String(), nil)),
		otel.WithConfigConvertorFactory(NewForceExtensionConverterFactory(elasticdiagnostics.DiagnosticsExtensionID.String(), extConf)),
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
		// Set the environment variable for the collector metrics port. See comment at the constant definition for more information.
		setErr := os.Setenv(componentmonitoring.OtelCollectorMetricsPortEnvVarName, strconv.Itoa(collectorMetricsPort))
		defer func() {
			unsetErr := os.Unsetenv(componentmonitoring.OtelCollectorMetricsPortEnvVarName)
			if unsetErr != nil {
				logger.Errorf("couldn't unset environment variable %s: %v", componentmonitoring.OtelCollectorMetricsPortEnvVarName, unsetErr)
			}
		}()
		if setErr != nil {
			reportErr(ctx, errCh, setErr)
			return
		}
		runErr := svc.Run(collectorCtx)
		close(ctl.collectorDoneCh)
		reportErr(ctx, errCh, runErr)
	}()
	return ctl, nil
}

// getCollectorPorts returns the metrics port used by the OTel collector. If the port set in the execution struct is 0,
// a random port is returned instead.
func (r *embeddedExecution) getCollectorMetricsPort() (metricsPort int, err error) {
	// if the port is defined (non-zero), use it
	if r.collectorMetricsPort > 0 {
		return r.collectorMetricsPort, nil
	}

	// get a random port
	ports, err := findRandomTCPPorts(1)
	if err != nil {
		return 0, err
	}
	return ports[0], nil
}

type ctxHandle struct {
	collectorDoneCh chan struct{}
	cancel          context.CancelFunc
}

// Stop stops the collector
func (s *ctxHandle) Stop(waitTime time.Duration) {
	if s.cancel == nil {
		return
	}

	s.cancel()

	select {
	case <-time.After(waitTime):
		return
	case <-s.collectorDoneCh:
	}
}
