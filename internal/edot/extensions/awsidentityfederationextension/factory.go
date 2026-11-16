// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package awsidentityfederationextension // import "github.com/elastic/elastic-agent/internal/edot/extensions/awsidentityfederationextension"

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/extension"
)

// typeStr is the component type used to reference the extension in collector configs.
var typeStr = component.MustNewType("awsidentityfederation")

// NewFactory creates a factory for the AWS Identity Federation extension.
func NewFactory() extension.Factory {
	return extension.NewFactory(typeStr, createDefaultConfig, createExtension, component.StabilityLevelDevelopment)
}

func createDefaultConfig() component.Config {
	return &Config{}
}

func createExtension(_ context.Context, settings extension.Settings, cfg component.Config) (extension.Extension, error) {
	return newExtension(cfg.(*Config), settings.Logger), nil
}
