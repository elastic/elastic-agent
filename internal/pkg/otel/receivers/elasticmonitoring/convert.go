// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"context"
	"maps"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent/internal/pkg/otel/internaltelemetry"
)

// A summary of current metrics values for a particular exporter
type exporterMetrics struct {
	queue_size     *int64
	queue_capacity *int64

	sent_log_records   *int64
	sent_spans         *int64
	sent_metric_points *int64

	send_failed_log_records   *int64
	send_failed_spans         *int64
	send_failed_metric_points *int64

	docs_processed     *int64
	docs_retried       *int64
	bulk_request_count *int64
	flushed_bytes      *int64
}

func getExporter[T int64 | float64](dp metricdata.DataPoint[T]) string {
	value, ok := dp.Attributes.Value("exporter")
	if ok && value.Type() == attribute.STRING {
		return value.AsString()
	}
	return ""
}

// Add the integer referenced by value, if it isn't nil, to the given
// referenced sum, initializing the sum if needed.
func add(target **int64, value *int64) {
	if value != nil {
		v := *value
		if *target != nil {
			**target += v
		} else {
			*target = &v
		}
	}
}

func (em *exporterMetrics) add(m exporterMetrics) {
	add(&em.queue_size, m.queue_size)
	add(&em.queue_capacity, m.queue_capacity)

	add(&em.sent_log_records, m.sent_log_records)
	add(&em.sent_spans, m.sent_spans)
	add(&em.sent_metric_points, m.sent_metric_points)

	add(&em.send_failed_log_records, m.send_failed_log_records)
	add(&em.send_failed_spans, m.send_failed_spans)
	add(&em.send_failed_metric_points, m.send_failed_metric_points)

	add(&em.docs_processed, m.docs_processed)
	add(&em.docs_retried, m.docs_retried)
	add(&em.bulk_request_count, m.bulk_request_count)
	add(&em.flushed_bytes, m.flushed_bytes)
}

func (em *exporterMetrics) addToEventFields(event *mapstr.M) {
	if em.queue_size != nil {
		_, _ = event.Put("beat.stats.libbeat.pipeline.queue.filled.events", *em.queue_size)
	}
	if em.queue_capacity != nil {
		_, _ = event.Put("beat.stats.libbeat.pipeline.queue.max_events", *em.queue_capacity)
	}
	if em.queue_size != nil && em.queue_capacity != nil {
		filled := float64(*em.queue_size) / float64(*em.queue_capacity)
		_, _ = event.Put("beat.stats.libbeat.pipeline.queue.filled.pct", filled)
	}
	var sent_total int64
	if em.sent_log_records != nil {
		sent_total += *em.sent_log_records
	}
	if em.sent_spans != nil {
		sent_total += *em.sent_spans
	}
	if em.sent_metric_points != nil {
		sent_total += *em.sent_spans
	}
	_, _ = event.Put("beat.stats.libbeat.output.events.acked", sent_total)

	var failed_total int64
	if em.send_failed_log_records != nil {
		failed_total += *em.send_failed_log_records
	}
	if em.send_failed_spans != nil {
		failed_total += *em.send_failed_spans
	}
	if em.send_failed_metric_points != nil {
		failed_total += *em.send_failed_metric_points
	}
	_, _ = event.Put("beat.stats.libbeat.output.events.dropped", failed_total)

	if em.docs_processed != nil {
		_, _ = event.Put("beat.stats.libbeat.output.events.total", *em.docs_processed)
	}
	if em.docs_retried != nil {
		_, _ = event.Put("beat.stats.libbeat.output.events.failed", *em.docs_retried)
	}
	if em.bulk_request_count != nil {
		_, _ = event.Put("beat.stats.libbeat.output.events.batches", *em.bulk_request_count)
	}
	if em.flushed_bytes != nil {
		_, _ = event.Put("beat.stats.libbeat.output.write.bytes", *em.flushed_bytes)
	}
}

func addValue(metrics *exporterMetrics, name string, value int64) {
	switch name {
	case "otelcol_exporter_queue_size":
		add(&metrics.queue_size, &value)
	case "otelcol_exporter_queue_capacity":
		add(&metrics.queue_capacity, &value)
	case "otelcol_exporter_sent_log_records":
		add(&metrics.sent_log_records, &value)
	case "otelcol_exporter_sent_spans":
		add(&metrics.sent_spans, &value)
	case "otelcol_exporter_sent_metric_points":
		add(&metrics.sent_metric_points, &value)
	case "otelcol_exporter_send_failed_log_records":
		add(&metrics.send_failed_log_records, &value)
	case "otelcol_exporter_send_failed_spans":
		add(&metrics.send_failed_spans, &value)
	case "otelcol_exporter_send_failed_metric_points":
		add(&metrics.send_failed_metric_points, &value)
	case "otelcol.elasticsearch.docs.processed":
		add(&metrics.docs_processed, &value)
	case "otelcol.elasticsearch.docs.retried":
		add(&metrics.docs_retried, &value)
	case "otelcol.elasticsearch.bulk_requests.count":
		add(&metrics.bulk_request_count, &value)
	case "otelcol.elasticsearch.flushed.bytes":
		add(&metrics.flushed_bytes, &value)
	}
}

// Returns the datapoints for the given aggregation, or an empty list if
// the aggregation is not a gauge or sum over integer data (all currently
// tracked metrics are integer sums or gauges, though this may change in
// the future).
func getDataPoints(data metricdata.Aggregation) []metricdata.DataPoint[int64] {
	switch v := data.(type) {
	case metricdata.Gauge[int64]:
		return v.DataPoints
	case metricdata.Sum[int64]:
		return v.DataPoints
	}
	return nil
}

func addMetric(exporters map[string]exporterMetrics, met metricdata.Metrics) {
	for _, dp := range getDataPoints(met.Data) {
		exporter := getExporter(dp)
		metrics := exporters[exporter]
		addValue(&metrics, met.Name, dp.Value)
		exporters[exporter] = metrics
	}
}

func collectMetrics(ctx context.Context) (map[string]exporterMetrics, error) {
	const elasticsearchPrefix = "elasticsearch/"
	const monitoringSuffix = "monitoring"
	exporters := map[string]exporterMetrics{}

	metrics, err := internaltelemetry.ReadMetrics(ctx)
	if err != nil {
		return nil, err
	}
	for _, scope := range metrics.ScopeMetrics {
		for _, met := range scope.Metrics {
			addMetric(exporters, met)
		}
	}
	var fallbackExporter string
	for k := range maps.Keys(exporters) {
		if strings.HasPrefix(k, elasticsearchPrefix) {
			fallbackExporter = k
			if !strings.HasSuffix(k, monitoringSuffix) {
				// Prefer a non-monitoring exporter for the fallback, so if
				// we find one of those we're done.
				break
			}
		}
	}
	if fallbackExporter != "" {
		// If any metrics were missing an exporter annotation, add them to
		// metrics for the fallback exporter.
		if unattributed, ok := exporters[""]; ok {
			m := exporters[fallbackExporter]
			m.add(unattributed)
			exporters[fallbackExporter] = m
		}
	}
	result := map[string]exporterMetrics{}
	// Only return entries corresponding to exporter state we know how to
	// monitor (just elasticsearch for now)
	for k, v := range exporters {
		if strings.HasPrefix(k, elasticsearchPrefix) {
			result[k] = v
		}
	}
	return result, nil
}
