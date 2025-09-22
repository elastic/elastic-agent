package elasticdiagnosticsextension

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/otel/elasticdiagnosticsextension/internal/metadata"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
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
