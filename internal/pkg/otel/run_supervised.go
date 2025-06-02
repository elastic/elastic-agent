// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"context"
	"fmt"
	"io"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"go.opentelemetry.io/collector/otelcol"

	"github.com/elastic/elastic-agent/internal/pkg/otel/agentprovider"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const EDOTSupevisedCommand = "edot-supervised"

func RunSupervisedCollector(ctx context.Context, l *logger.Logger, in io.Reader) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	configProvider, err := agentprovider.NewProvider(in)
	if err != nil {
		return fmt.Errorf("failed to create config provider: %w", err)
	}

	// NewForceExtensionConverterFactory is used to ensure that the agent_status extension is always enabled.
	// It is required for the Elastic Agent to extract the status out of the OTel collector.
	settings := NewSettings(
		release.Version(), []string{configProvider.URI()},
		WithConfigProviderFactory(configProvider.NewFactory()),
	)
	settings.DisableGracefulShutdown = false
	settings.LoggingOptions = []zap.Option{zap.WrapCore(func(zapcore.Core) zapcore.Core {
		return l.Core()
	})}

	svc, err := otelcol.NewCollector(*settings)
	if err != nil {
		return fmt.Errorf("failed to create collector: %w", err)
	}

	return svc.Run(ctx)
}
