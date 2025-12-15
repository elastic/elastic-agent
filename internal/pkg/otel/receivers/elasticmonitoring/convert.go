// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"context"

	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/edot/otelcol/monitoring/internaltelemetry"
)

func addMetricsFields(ctx context.Context, event *mapstr.M) {
	metrics, err := internaltelemetry.ReadMetrics(ctx)
	if err != nil {
		return
	}
	var exporter_queue_size *int64
	for _, scope := range metrics.ScopeMetrics {
		for _, met := range scope.Metrics {
			if met.Name == "otelcol_exporter_queue_size" {
				if d, ok := met.Data.(metricdata.Gauge[int64]); ok { //met.Data.(metricdata.Sum[int64]); ok {
					var total int64
					for _, dp := range d.DataPoints {
						total += dp.Value
					}
					exporter_queue_size = &total
				}
			}
		}
	}

	if exporter_queue_size != nil {
		event.Put("beat.stats.libbeat.pipeline.queue.filled.events", *exporter_queue_size)
	}
}
