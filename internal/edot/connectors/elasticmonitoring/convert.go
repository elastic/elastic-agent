// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

import (
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-libs/mapstr"
)

// exporterMetrics summarises current metric values for a particular exporter.
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

	otelQueueCapacityKey       = "otelcol_exporter_queue_capacity"
	otelQueueSizeKey           = "otelcol_exporter_queue_size"
	otelSentLogsKey            = "otelcol_exporter_sent_log_records"
	otelSentSpansKey           = "otelcol_exporter_sent_spans"
	otelSentMetricsKey         = "otelcol_exporter_sent_metric_points"
	otelFailedLogsKey          = "otelcol_exporter_send_failed_log_records"
	otelFailedSpansKey         = "otelcol_exporter_send_failed_spans"
	otelFailedMetricsKey       = "otelcol_exporter_send_failed_metric_points"
	otelDocsProcessedKey       = "otelcol.elasticsearch.docs.processed"
	otelDocsRetriedKey         = "otelcol.elasticsearch.docs.retried"
	otelDocsRetriedHTTPRequest = "otelcol.elasticsearch.docs.retried_http_request"
	otelBulkRequestsKey        = "otelcol.elasticsearch.bulk_requests.count"
	otelFlushedBytesKey        = "otelcol.elasticsearch.flushed.bytes"

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

// componentInputData holds the per-input metrics for a single agent component,
// along with the beat type derived from the OTel receiver component ID.
type componentInputData struct {
	beatType string
	inputs   map[string]map[string]any // inputID -> fields
}

// add adds the integer referenced by value, if it isn't nil, to the given
// referenced sum, initialising the sum if needed.
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

// set sets the referenced pointer to contain the given value, if it isn't nil.
func set(target **int64, value *int64) {
	if value != nil {
		v := *value
		*target = &v
	}
}

// addValue records the named OTel Collector internal telemetry variable into em.
func addValue(em *exporterMetrics, name string, value int64) {
	switch name {
	case otelQueueSizeKey:
		add(&em.queueSize, &value)
	case otelQueueCapacityKey:
		set(&em.queueCapacity, &value)
	case otelSentLogsKey:
		add(&em.sentLogs, &value)
	case otelSentSpansKey:
		add(&em.sentSpans, &value)
	case otelSentMetricsKey:
		add(&em.sentMetrics, &value)
	case otelFailedLogsKey:
		add(&em.failedLogs, &value)
	case otelFailedSpansKey:
		add(&em.failedSpans, &value)
	case otelFailedMetricsKey:
		add(&em.failedMetrics, &value)
	case otelDocsProcessedKey:
		add(&em.docsProcessed, &value)
	case otelDocsRetriedKey, otelDocsRetriedHTTPRequest:
		add(&em.docsRetried, &value)
	case otelBulkRequestsKey:
		add(&em.bulkRequests, &value)
	case otelFlushedBytesKey:
		add(&em.flushedBytes, &value)
	}
}

// agentComponentID extracts the agent component ID from an OTel component ID.
// OTel component IDs follow the pattern "{type}/_agent-component/{compID}".
//
// TODO(blakerouse): move the "_agent-component/" naming convention to a shared
// module so this package does not duplicate knowledge from the config translation layer.
func agentComponentID(otelComponentID string) string {
	const prefix = "_agent-component/"
	_, after, ok := strings.Cut(otelComponentID, prefix)
	if !ok {
		return ""
	}
	return after
}

// beatTypeFromOtelID extracts the beat type from an OTel component ID by
// stripping the "receiver" suffix from the component type
// (e.g. "filebeatreceiver" → "filebeat").
func beatTypeFromOtelID(otelComponentID string) string {
	var id component.ID
	if err := id.UnmarshalText([]byte(otelComponentID)); err != nil {
		return ""
	}
	return strings.TrimSuffix(id.Type().String(), "receiver")
}

func mapstrSetWithErrorLog(logger *zap.Logger, event *mapstr.M, key string, value any) {
	_, err := event.Put(key, value)
	if err != nil {
		logger.Error("Couldn't set key while generating metrics event",
			zap.String("key", key), zap.Error(err))
	}
}

// addMetricsToEventFields writes exporterMetrics values as fields on the event,
// using the legacy schema for Beats metrics.
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

// componentIDForScope returns the otelcol.component.id from the scope attributes
// if its otelcol.component.kind matches kind, or empty string otherwise.
func componentIDForScope(sm pmetric.ScopeMetrics, kind string) string {
	attrs := sm.Scope().Attributes()
	kindVal, ok := attrs.Get(otelComponentKindKey)
	if !ok || kindVal.Str() != kind {
		return ""
	}
	id, ok := attrs.Get(otelComponentIDKey)
	if !ok {
		return ""
	}
	return id.Str()
}

// numberDataPointValue extracts the numeric value from a data point as any,
// returning false for unset or unknown value types.
func numberDataPointValue(dp pmetric.NumberDataPoint) (any, bool) {
	switch dp.ValueType() {
	case pmetric.NumberDataPointValueTypeInt:
		return dp.IntValue(), true
	case pmetric.NumberDataPointValueTypeDouble:
		return dp.DoubleValue(), true
	}
	return nil, false
}

// addMetric adds a pmetric.Metric's integer data points into em. Only Gauge
// and Sum metrics with integer values are processed; all currently tracked
// exporter metrics are integer sums or gauges.
func addMetric(em *exporterMetrics, m pmetric.Metric) {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		dps := m.Gauge().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			dp := dps.At(i)
			if dp.ValueType() == pmetric.NumberDataPointValueTypeInt {
				addValue(em, m.Name(), dp.IntValue())
			}
		}
	case pmetric.MetricTypeSum:
		dps := m.Sum().DataPoints()
		for i := 0; i < dps.Len(); i++ {
			dp := dps.At(i)
			if dp.ValueType() == pmetric.NumberDataPointValueTypeInt {
				addValue(em, m.Name(), dp.IntValue())
			}
		}
	}
}

// convertScopeMetrics builds a map from elasticsearch exporter component ID to
// its aggregated exporterMetrics from the given pmetric.Metrics.
func convertScopeMetrics(md pmetric.Metrics) map[string]exporterMetrics {
	const elasticsearchPrefix = "elasticsearch/"
	exporters := map[string]exporterMetrics{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			exporterID := componentIDForScope(sm, "exporter")
			if !strings.HasPrefix(exporterID, elasticsearchPrefix) {
				continue
			}
			metrics := exporters[exporterID]
			for k := 0; k < sm.Metrics().Len(); k++ {
				addMetric(&metrics, sm.Metrics().At(k))
			}
			exporters[exporterID] = metrics
		}
	}
	return exporters
}

// addInputDataPoint records a single data point into the inputs map keyed by
// its input_id attribute. Data points without an input_id are ignored.
func addInputDataPoint(dataset map[string]map[string]any, metricName string, dp pmetric.NumberDataPoint) {
	inputIDVal, ok := dp.Attributes().Get(otelInputIDKey)
	if !ok {
		return
	}
	inputID := inputIDVal.Str()

	entry, exists := dataset[inputID]
	if !exists {
		entry = map[string]any{"id": inputID}
	}

	if inputTypeVal, ok := dp.Attributes().Get(otelInputTypeKey); ok {
		entry["input"] = inputTypeVal.Str()
	}

	if val, ok := numberDataPointValue(dp); ok {
		entry[metricName] = val
	}

	dataset[inputID] = entry
}

// collectComponentInputMetrics iterates all scope metrics and aggregates data
// points that carry an input_id attribute, grouped by the agent component they
// belong to (extracted from the scope's otelcol.component.id).
func collectComponentInputMetrics(md pmetric.Metrics) map[string]componentInputData {
	components := map[string]componentInputData{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)

			// Prefer receiver kind, but fall back to any component ID present
			// (e.g. beat bridge metrics that may not carry a component kind).
			otelID := componentIDForScope(sm, "receiver")
			if otelID == "" {
				idVal, ok := sm.Scope().Attributes().Get(otelComponentIDKey)
				if !ok {
					continue
				}
				otelID = idVal.Str()
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

			for k := 0; k < sm.Metrics().Len(); k++ {
				m := sm.Metrics().At(k)
				switch m.Type() {
				case pmetric.MetricTypeGauge:
					dps := m.Gauge().DataPoints()
					for l := 0; l < dps.Len(); l++ {
						addInputDataPoint(data.inputs, m.Name(), dps.At(l))
					}
				case pmetric.MetricTypeSum:
					dps := m.Sum().DataPoints()
					for l := 0; l < dps.Len(); l++ {
						addInputDataPoint(data.inputs, m.Name(), dps.At(l))
					}
				}
			}

			components[compID] = data
		}
	}
	return components
}

// baseComponentID strips the per-container stream ID suffix from an agent
// component ID so that all receivers sharing the same base component
// (e.g. "filestream-default/<streamID>" or "http/metrics-monitoring/<streamID>")
// are aggregated into a single entry. The stream ID is always the last
// slash-delimited segment, so we cut at the last "/" rather than the first.
func baseComponentID(compID string) string {
	i := strings.LastIndexByte(compID, '/')
	if i < 0 {
		return compID
	}
	return compID[:i]
}

// receiverMetricField builds the Beats monitoring field path for a metric
// emitted by the RegistryBridge. The RegistryBridge uses raw monitoring registry
// keys as OTel metric names, which already carry a namespace prefix:
//
//   - "libbeat.*" keys are generic across all beat types: beat.stats.libbeat.*
//   - "<beatType>.*" keys already carry the type prefix; adding it again would
//     produce a double prefix.
//   - Unqualified names get the beat-type prefix: beat.stats.<beatType>.<name>.
func receiverMetricField(beatType, metricName string) string {
	if strings.HasPrefix(metricName, "libbeat.") || strings.HasPrefix(metricName, beatType+".") {
		return "beat.stats." + metricName
	}
	return "beat.stats." + beatType + "." + metricName
}

// addReceiverDataPoint records a single data point from a RegistryBridge metric
// into the components map. otelID is the receiver's OTel component ID.
// Per-container receivers (e.g. "filestream-default/<hash>") are aggregated into
// a single entry keyed by the base component ID, with values summed.
func addReceiverDataPoint(components map[string]map[string]any, dp pmetric.NumberDataPoint, otelID string, metricName string) {
	compID := baseComponentID(agentComponentID(otelID))
	if compID == "" {
		return
	}
	field := receiverMetricField(beatTypeFromOtelID(otelID), metricName)
	if _, exists := components[compID]; !exists {
		components[compID] = map[string]any{}
	}
	val, ok := numberDataPointValue(dp)
	if !ok {
		return
	}
	// Accumulate values from multiple per-container receivers into the same field.
	if existing, exists := components[compID][field]; exists {
		switch ev := existing.(type) {
		case int64:
			if v, ok := val.(int64); ok {
				components[compID][field] = ev + v
				return
			}
		case float64:
			if v, ok := val.(float64); ok {
				components[compID][field] = ev + v
				return
			}
		}
	}
	components[compID][field] = val
}

// collectReceiverMetrics collects all metrics emitted by the RegistryBridge
// (scope name: registryBridgeScopeName). Each data point carries a "receiver"
// attribute containing the OTel component ID. Metrics are mapped using
// receiverMetricField so that libbeat.* and <beatType>.* prefixes are handled
// correctly. Per-container receivers sharing the same base component ID are
// aggregated into a single entry with summed values.
func collectReceiverMetrics(md pmetric.Metrics) map[string]map[string]any {
	components := map[string]map[string]any{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			if sm.Scope().Name() != registryBridgeScopeName {
				continue
			}
			for k := 0; k < sm.Metrics().Len(); k++ {
				m := sm.Metrics().At(k)
				switch m.Type() {
				case pmetric.MetricTypeGauge:
					dps := m.Gauge().DataPoints()
					for l := 0; l < dps.Len(); l++ {
						dp := dps.At(l)
						receiverVal, ok := dp.Attributes().Get(registryBridgeReceiverKey)
						if !ok {
							continue
						}
						addReceiverDataPoint(components, dp, receiverVal.Str(), m.Name())
					}
				case pmetric.MetricTypeSum:
					dps := m.Sum().DataPoints()
					for l := 0; l < dps.Len(); l++ {
						dp := dps.At(l)
						receiverVal, ok := dp.Attributes().Get(registryBridgeReceiverKey)
						if !ok {
							continue
						}
						addReceiverDataPoint(components, dp, receiverVal.Str(), m.Name())
					}
				}
			}
		}
	}
	return components
}
