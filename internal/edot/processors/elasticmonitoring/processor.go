// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoringprocessor

import (
	"context"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"
)

func (p *monitoringProcessor) ConsumeMetrics(ctx context.Context, md pmetric.Metrics) error {
	processed := buildProcessedMetrics(p.logger, p.config, p.resource, md)
	if processed.ResourceMetrics().Len() == 0 {
		return nil
	}
	return p.next.ConsumeMetrics(ctx, processed)
}

// buildProcessedMetrics transforms raw collector internal-telemetry metrics into
// a canonical form where each ResourceMetrics represents one monitoring event.
// Scope attributes encode the event type and component identity; resource attributes
// carry the collector's own service metadata (service.name, service.version, etc.).
// Metrics carry Beats-compatible field names and aggregated values.
func buildProcessedMetrics(logger *zap.Logger, cfg *Config, res pcommon.Resource, md pmetric.Metrics) pmetric.Metrics {
	out := pmetric.NewMetrics()
	buildExporterMetrics(logger, cfg, res, md, out)
	buildInputMetrics(res, md, out)
	buildReceiverPipelineMetrics(res, md, out)
	return out
}
