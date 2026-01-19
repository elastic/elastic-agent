// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"strings"

	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-libs/mapstr"
)

// A summary of current metrics values for a particular exporter
type exporterMetrics struct {
	queueSize     *int64
	queueCapacity *int64

	sentLogs    *int64
	sentSpans   *int64
	sentMetrics *int64

	failedLogs    *int64
	failedSpans   *int64
	failedMetrics *int64

	docsProcessed *int64
	docsRetried   *int64
	bulkRequests  *int64
	flushedBytes  *int64
}

const (
	beatsQueueFilledEventsKey   = "beat.stats.libbeat.pipeline.queue.filled.events"
	beatsQueueMaxEventsKey      = "beat.stats.libbeat.pipeline.queue.max_events"
	beatsQueueFilledPctKey      = "beat.stats.libbeat.pipeline.queue.filled.pct"
	beatsOutputEventsTotalKey   = "beat.stats.libbeat.output.events.total"
	beatsOutputEventsActiveKey  = "beat.stats.libbeat.output.events.active"
	beatsOutputEventsAckedKey   = "beat.stats.libbeat.output.events.acked"
	beatsOutputEventsDroppedKey = "beat.stats.libbeat.output.events.dropped"
	beatsOutputEventsFailedKey  = "beat.stats.libbeat.output.events.failed"
	beatsOutputEventsBatchesKey = "beat.stats.libbeat.output.events.batches"
	beatsOutputWriteBytesKey    = "beat.stats.libbeat.output.write.bytes"

	otelQueueCapacityKey = "otelcol_exporter_queue_capacity"
	otelQueueSizeKey     = "otelcol_exporter_queue_size"
	otelSentLogsKey      = "otelcol_exporter_sent_log_records"
	otelSentSpansKey     = "otelcol_exporter_sent_spans"
	otelSentMetricsKey   = "otelcol_exporter_sent_metric_points"
	otelFailedLogsKey    = "otelcol_exporter_send_failed_log_records"
	otelFailedSpansKey   = "otelcol_exporter_send_failed_spans"
	otelFailedMetricsKey = "otelcol_exporter_send_failed_metric_points"
	otelDocsProcessedKey = "otelcol.elasticsearch.docs.processed"
	otelDocsRetriedKey   = "otelcol.elasticsearch.docs.retried"
	otelBulkRequestsKey  = "otelcol.elasticsearch.bulk_requests.count"
	otelFlushedBytesKey  = "otelcol.elasticsearch.flushed.bytes"

	otelComponentIDKey   = "otelcol.component.id"
	otelComponentKindKey = "otelcol.component.kind"
)

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

// Given the name and value of an OTel Collector internal telemetry variable,
// add it to the given metrics struct.
func addValue(metrics *exporterMetrics, name string, value int64) {
	switch name {
	case otelQueueSizeKey:
		add(&metrics.queueSize, &value)
	case otelQueueCapacityKey:
		set(&metrics.queueCapacity, &value)
	case otelSentLogsKey:
		add(&metrics.sentLogs, &value)
	case otelSentSpansKey:
		add(&metrics.sentSpans, &value)
	case otelSentMetricsKey:
		add(&metrics.sentMetrics, &value)
	case otelFailedLogsKey:
		add(&metrics.failedLogs, &value)
	case otelFailedSpansKey:
		add(&metrics.failedSpans, &value)
	case otelFailedMetricsKey:
		add(&metrics.failedMetrics, &value)
	case otelDocsProcessedKey:
		add(&metrics.docsProcessed, &value)
	case otelDocsRetriedKey:
		add(&metrics.docsRetried, &value)
	case otelBulkRequestsKey:
		add(&metrics.bulkRequests, &value)
	case otelFlushedBytesKey:
		add(&metrics.flushedBytes, &value)
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
	kind, ok := scope.Attributes.Value(otelComponentKindKey)
	if !ok || kind.AsString() != "exporter" {
		// Only exporter components have an exporter ID to return.
		return ""
	}
	id, ok := scope.Attributes.Value(otelComponentIDKey)
	if !ok {
		return ""
	}
	return id.AsString()
}

func convertScopeMetrics(scopeMetrics []metricdata.ScopeMetrics) map[string]exporterMetrics {
	const elasticsearchPrefix = "elasticsearch/"
	exporters := map[string]exporterMetrics{}

	for _, sm := range scopeMetrics {
		exporterID := exporterIDForScope(sm.Scope)
		if !strings.HasPrefix(exporterID, elasticsearchPrefix) {
			// Only handle metrics corresponding to exporter state we know how
			// to monitor (just elasticsearch for now)
			continue
		}

		// The same exporter can appear many times in different metrics
		// blocks and we want to aggregate all of them, so load the existing
		// values first.
		metrics := exporters[exporterID]
		for _, met := range sm.Metrics {
			addMetric(&metrics, met)
		}
		exporters[exporterID] = metrics
	}
	return exporters
}

func mapstrSetWithErrorLog(logger *zap.Logger, event *mapstr.M, key string, value interface{}) {
	_, err := event.Put(key, value)
	if err != nil {
		logger.Error("Couldn't set key while generating metrics event",
			zap.String("key", key), zap.Error(err))
	}
}

// Add the given metrics as fields on the event, with field names following
// the legacy schema for Beats metrics.
func addMetricsToEventFields(logger *zap.Logger, em exporterMetrics, event *mapstr.M) {
	if em.queueSize != nil {
		mapstrSetWithErrorLog(logger, event, beatsQueueFilledEventsKey, *em.queueSize)
	}
	if em.queueCapacity != nil {
		mapstrSetWithErrorLog(logger, event, beatsQueueMaxEventsKey, *em.queueCapacity)
	}
	if em.queueSize != nil && em.queueCapacity != nil && *em.queueCapacity > 0 {
		filled := float64(*em.queueSize) / float64(*em.queueCapacity)
		mapstrSetWithErrorLog(logger, event, beatsQueueFilledPctKey, filled)
	}
	var sentTotal int64
	if em.sentLogs != nil {
		sentTotal += *em.sentLogs
	}
	if em.sentSpans != nil {
		sentTotal += *em.sentSpans
	}
	if em.sentMetrics != nil {
		sentTotal += *em.sentMetrics
	}
	mapstrSetWithErrorLog(logger, event, beatsOutputEventsAckedKey, sentTotal)

	var failedTotal int64
	if em.failedLogs != nil {
		failedTotal += *em.failedLogs
	}
	if em.failedSpans != nil {
		failedTotal += *em.failedSpans
	}
	if em.failedMetrics != nil {
		failedTotal += *em.failedMetrics
	}
	mapstrSetWithErrorLog(logger, event, beatsOutputEventsDroppedKey, failedTotal)

	if em.docsProcessed != nil {
		mapstrSetWithErrorLog(logger, event, beatsOutputEventsTotalKey, *em.docsProcessed)

		active := *em.docsProcessed - sentTotal - failedTotal
		mapstrSetWithErrorLog(logger, event, beatsOutputEventsActiveKey, active)
	}
	if em.docsRetried != nil {
		mapstrSetWithErrorLog(logger, event, beatsOutputEventsFailedKey, *em.docsRetried)
	}
	if em.bulkRequests != nil {
		mapstrSetWithErrorLog(logger, event, beatsOutputEventsBatchesKey, *em.bulkRequests)
	}
	if em.flushedBytes != nil {
		mapstrSetWithErrorLog(logger, event, beatsOutputWriteBytesKey, *em.flushedBytes)
	}
}
