// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel/sdk/instrumentation"
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

// Add the integer referenced by value, if it isn't nil, to the given
// referenced sum, initializing the sum if needed.
func add(target **int64, value *int64) {
	if value != nil {
		if *target != nil {
			**target += *value
		} else {
			v := *value
			*target = &v
		}
	}
}

// Set the referenced pointer to contain the given value, if it
// isn't nil. (Like "add" but for gauges instead of sums.)
func set(target **int64, value *int64) {
	if value != nil {
		v := *value
		*target = &v
	}
}

func (em *exporterMetrics) add(m exporterMetrics) {
	add(&em.queue_size, m.queue_size)
	set(&em.queue_capacity, m.queue_capacity)

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

// Add the given metrics as fields on the event, with field names following
// the legacy schema for Beats metrics.
func addMetricsToEventFields(em exporterMetrics, event *mapstr.M) {
	if em.queue_size != nil {
		_, _ = event.Put("beat.stats.libbeat.pipeline.queue.filled.events", *em.queue_size)
	}
	if em.queue_capacity != nil {
		_, _ = event.Put("beat.stats.libbeat.pipeline.queue.max_events", *em.queue_capacity)
	}
	if em.queue_size != nil && em.queue_capacity != nil && *em.queue_capacity > 0 {
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

// Given the name and value of an OTel Collector internal telemetry variable,
// add it to the given metrics struct.
func addValue(metrics *exporterMetrics, name string, value int64) {
	switch name {
	case "otelcol_exporter_queue_size":
		add(&metrics.queue_size, &value)
	case "otelcol_exporter_queue_capacity":
		set(&metrics.queue_capacity, &value)
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
// tracked metrics are integer sums or gauges, though this will change in
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

func addMetric(metrics *exporterMetrics, met metricdata.Metrics) {
	for _, dp := range getDataPoints(met.Data) {
		addValue(metrics, met.Name, dp.Value)
	}
}

// Given an internal telemetry scope, return the ID of the corresponding
// exporter if there is one.
func exporterIDForScope(scope instrumentation.Scope) string {
	kind, ok := scope.Attributes.Value("otelcol.component.kind")
	if !ok || kind.AsString() != "exporter" {
		// Only exporter components have an exporter ID to return.
		return ""
	}
	id, ok := scope.Attributes.Value("otelcol.component.id")
	if !ok {
		return ""
	}
	return id.AsString()
}

func collectMetrics(ctx context.Context) (map[string]exporterMetrics, error) {
	const elasticsearchPrefix = "elasticsearch/"
	const monitoringSuffix = "monitoring"
	exporters := map[string]exporterMetrics{}

	metrics, err := internaltelemetry.ReadMetrics(ctx)
	if err != nil {
		return nil, err
	}
	for _, scopeMetrics := range metrics.ScopeMetrics {
		exporterID := exporterIDForScope(scopeMetrics.Scope)
		metrics := exporters[exporterID]

		for _, met := range scopeMetrics.Metrics {
			addMetric(&metrics, met)
		}
		exporters[exporterID] = metrics
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
