// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"strings"

	"go.opentelemetry.io/otel/attribute"
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

	otelInputIDKey   = "input_id"
	otelInputTypeKey = "input_type"

	// registryBridgeScopeName is the instrumentation scope name used by the
	// RegistryBridge in beats, which bridges Beats monitoring registries into
	// OTel async instruments. Metrics from this scope carry a "receiver"
	// data point attribute containing the OTel component ID.
	registryBridgeScopeName = "github.com/elastic/beats/v7/x-pack/otel/telemetry"
	// registryBridgeReceiverKey is the data point attribute key set by the
	// RegistryBridge to identify which Beat receiver emitted the metric.
	registryBridgeReceiverKey = "receiver"
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

// componentIDForScope returns the otelcol.component.id from the scope
// attributes if it matches the given kind, or empty string otherwise.
func componentIDForScope(scope instrumentation.Scope, kind string) string {
	kindVal, ok := scope.Attributes.Value(otelComponentKindKey)
	if !ok || kindVal.AsString() != kind {
		return ""
	}
	id, ok := scope.Attributes.Value(otelComponentIDKey)
	if !ok {
		return ""
	}
	return id.AsString()
}

// agentComponentID extracts the agent component ID from an OTel component ID.
// OTel component IDs follow the pattern "{type}/_agent-component/{compID}".
// Returns the compID portion, or empty string if the pattern doesn't match.
func agentComponentID(otelComponentID string) string {
	const prefix = "_agent-component/"
	idx := strings.Index(otelComponentID, prefix)
	if idx < 0 {
		return ""
	}
	return otelComponentID[idx+len(prefix):]
}

func convertScopeMetrics(scopeMetrics []metricdata.ScopeMetrics) map[string]exporterMetrics {
	const elasticsearchPrefix = "elasticsearch/"
	exporters := map[string]exporterMetrics{}

	for _, sm := range scopeMetrics {
		exporterID := componentIDForScope(sm.Scope, "exporter")
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

// componentInputData holds the per-input metrics for a single agent component,
// along with the beat type derived from the OTel receiver component ID
// (e.g. "filebeat" for a filebeatreceiver component).
type componentInputData struct {
	beatType string
	inputs   map[string]map[string]any // sanitizedInputID -> fields
}

// beatTypeFromOtelID extracts the beat type from an OTel component ID.
// OTel component IDs follow the pattern "{type}[/{rest}]", where {type} is
// e.g. "filebeatreceiver". The "receiver" suffix is stripped to get the beat
// type (e.g. "filebeat").
func beatTypeFromOtelID(otelComponentID string) string {
	typePart := otelComponentID
	if idx := strings.Index(otelComponentID, "/"); idx >= 0 {
		typePart = otelComponentID[:idx]
	}
	return strings.TrimSuffix(typePart, "receiver")
}

// collectComponentInputMetrics iterates all scope metrics and aggregates data
// points that carry an "input_id" attribute, grouped by the agent component
// they belong to (extracted from the scope's otelcol.component.id).
// Returns a map from agent component ID to componentInputData, which holds
// the beat type and a map keyed by sanitized input ID. Each input entry
// contains "id" (original input_id), optionally "input" (input_type), and
// the raw metric name/value pairs.
func collectComponentInputMetrics(scopeMetrics []metricdata.ScopeMetrics) map[string]componentInputData {
	components := map[string]componentInputData{}
	for _, sm := range scopeMetrics {
		// Resolve the full OTel component ID for this scope, preferring the
		// receiver kind but falling back to any component ID present (e.g.
		// beat bridge metrics that may not carry a component kind attribute).
		otelID := componentIDForScope(sm.Scope, "receiver")
		if otelID == "" {
			id, ok := sm.Scope.Attributes.Value(otelComponentIDKey)
			if !ok {
				continue
			}
			otelID = id.AsString()
		}

		compID := agentComponentID(otelID)
		if compID == "" {
			continue
		}

		data, exists := components[compID]
		if !exists {
			data = componentInputData{
				beatType: beatTypeFromOtelID(otelID),
				inputs:   map[string]map[string]any{},
			}
		}

		for _, met := range sm.Metrics {
			switch v := met.Data.(type) {
			case metricdata.Gauge[int64]:
				for _, dp := range v.DataPoints {
					addInputDataPoint(data.inputs, met.Name, dp.Attributes, dp.Value)
				}
			case metricdata.Sum[int64]:
				for _, dp := range v.DataPoints {
					addInputDataPoint(data.inputs, met.Name, dp.Attributes, dp.Value)
				}
			case metricdata.Gauge[float64]:
				for _, dp := range v.DataPoints {
					addInputDataPoint(data.inputs, met.Name, dp.Attributes, dp.Value)
				}
			case metricdata.Sum[float64]:
				for _, dp := range v.DataPoints {
					addInputDataPoint(data.inputs, met.Name, dp.Attributes, dp.Value)
				}
			}
		}

		components[compID] = data
	}
	return components
}

func addInputDataPoint[N int64 | float64](dataset map[string]map[string]any, name string, attrs attribute.Set, value N) {
	inputIDVal, ok := attrs.Value(otelInputIDKey)
	if !ok {
		return
	}
	inputID := inputIDVal.AsString()

	entry, exists := dataset[inputID]
	if !exists {
		entry = map[string]any{"id": inputID}
	}

	if inputTypeVal, ok := attrs.Value(otelInputTypeKey); ok {
		entry["input"] = inputTypeVal.AsString()
	}

	entry[name] = value
	dataset[inputID] = entry
}

// collectReceiverMetrics collects all metrics emitted by the RegistryBridge
// (scope name: github.com/elastic/beats/v7/x-pack/otel/telemetry).
// Each data point carries a "receiver" attribute containing the OTel component ID.
// Metrics are mapped to fields as "beat.stats.{beatType}.{metricName}", where
// beatType is derived from the receiver OTel component ID (e.g. "filebeat").
// This matches the standard Beats monitoring schema
// (e.g. "beat.stats.filebeat.harvester.running", "beat.stats.filebeat.registrar.states.current").
// Returns a map from agent component ID to a map of field names to values,
// one entry per receiver.
func collectReceiverMetrics(scopeMetrics []metricdata.ScopeMetrics) map[string]map[string]any {
	components := map[string]map[string]any{}
	for _, sm := range scopeMetrics {
		if sm.Scope.Name != registryBridgeScopeName {
			continue
		}
		for _, met := range sm.Metrics {
			switch v := met.Data.(type) {
			case metricdata.Gauge[int64]:
				for _, dp := range v.DataPoints {
					addReceiverDataPoint(components, dp.Attributes, met.Name, dp.Value)
				}
			case metricdata.Sum[int64]:
				for _, dp := range v.DataPoints {
					addReceiverDataPoint(components, dp.Attributes, met.Name, dp.Value)
				}
			case metricdata.Gauge[float64]:
				for _, dp := range v.DataPoints {
					addReceiverDataPoint(components, dp.Attributes, met.Name, dp.Value)
				}
			case metricdata.Sum[float64]:
				for _, dp := range v.DataPoints {
					addReceiverDataPoint(components, dp.Attributes, met.Name, dp.Value)
				}
			}
		}
	}
	return components
}

func addReceiverDataPoint[N int64 | float64](components map[string]map[string]any, attrs attribute.Set, metricName string, value N) {
	receiverVal, ok := attrs.Value(registryBridgeReceiverKey)
	if !ok {
		return
	}
	otelID := receiverVal.AsString()
	compID := agentComponentID(otelID)
	if compID == "" {
		return
	}
	field := "beat.stats." + beatTypeFromOtelID(otelID) + "." + metricName
	if _, exists := components[compID]; !exists {
		components[compID] = map[string]any{}
	}
	components[compID][field] = value
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
