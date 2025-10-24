// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticdiagnostics

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"

	"github.com/elastic/elastic-agent/internal/pkg/otel/extension/elasticdiagnostics/internal/metadata"
)

var (
	DiagnosticsExtensionID component.Type = metadata.Type
)

func NewFactory() extension.Factory {
	return extension.NewFactory(metadata.Type, createDefaultConfig, newExtension, component.StabilityLevelDevelopment)
}

func newExtension(ctx context.Context, set extension.Settings, cfg component.Config) (extension.Extension, error) {
	return &diagnosticsExtension{
		diagnosticsConfig: cfg.(*Config),
		logger:            set.Logger.Named("elastic_diagnostics"),
		componentHooks:    make(map[string][]*diagHook),
		globalHooks:       make(map[string]*diagHook),
	}, nil
}
