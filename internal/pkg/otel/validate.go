// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package otel

import (
	"context"

	"go.opentelemetry.io/collector/otelcol"

	"github.com/elastic/elastic-agent/internal/pkg/release"
)

func Validate(ctx context.Context, configPaths []string) error {
	settings := NewSettings(release.Version(), configPaths)
	col, err := otelcol.NewCollector(*settings)
	if err != nil {
		return err
	}
	return col.DryRun(ctx)
}
