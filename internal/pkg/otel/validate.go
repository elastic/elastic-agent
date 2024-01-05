// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package otel

import (
	"context"

	"github.com/elastic/elastic-agent/internal/pkg/release"
	"go.opentelemetry.io/collector/otelcol"
)

func Validate(ctx context.Context, configPath string) error {
	settings, err := newSettings(configPath, release.Version())
	if err != nil {
		return err
	}

	col, err := otelcol.NewCollector(*settings)
	if err != nil {
		return err
	}
	return col.DryRun(ctx)

}
