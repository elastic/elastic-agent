// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoringprocessor

import (
	"strings"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent/internal/edot/internaltelemetry"
)

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

	otelQueueCapacityKey        = "otelcol_exporter_queue_capacity"
	otelQueueSizeKey            = "otelcol_exporter_queue_size"
	otelSentLogsKey             = "otelcol_exporter_sent_log_records"
	otelSentSpansKey            = "otelcol_exporter_sent_spans"
	otelSentMetricsKey          = "otelcol_exporter_sent_metric_points"
	otelFailedLogsKey           = "otelcol_exporter_send_failed_log_records"
	otelFailedSpansKey          = "otelcol_exporter_send_failed_spans"
	otelFailedMetricsKey        = "otelcol_exporter_send_failed_metric_points"
	otelEnqueueFailedLogsKey    = "otelcol_exporter_enqueue_failed_log_records"
	otelEnqueueFailedSpansKey   = "otelcol_exporter_enqueue_failed_spans"
	otelEnqueueFailedMetricsKey = "otelcol_exporter_enqueue_failed_metric_points"
	otelDocsProcessedKey        = "otelcol.elasticsearch.docs.processed"
	otelDocsRetriedKey          = "otelcol.elasticsearch.docs.retried"
	otelDocsRetriedHTTPRequest  = "otelcol.elasticsearch.docs.retried_http_request"
	otelBulkRequestsKey         = "otelcol.elasticsearch.bulk_requests.count"
	otelFlushedBytesKey         = "otelcol.elasticsearch.flushed.bytes"

	otelComponentIDKey   = "otelcol.component.id"
	otelComponentKindKey = "otelcol.component.kind"

	otelInputIDKey   = "input_id"
	otelInputTypeKey = "input_type"

	// registryBridgeScopeName is the instrumentation scope name used by the
	// RegistryBridge in beats, which bridges Beats monitoring registries into
	// OTel async instruments. Metrics from this scope carry a "receiver"
	// data point attribute containing the OTel component ID.
	// This must match the unexported `scopeName` constant in
	// beats/x-pack/otel/telemetry/bridge.go; update both if the beats package path changes.
	registryBridgeScopeName = "github.com/elastic/beats/v7/x-pack/otel/telemetry"
	// registryBridgeReceiverKey is the data point attribute key set by the
	// RegistryBridge to identify which Beat receiver emitted the metric.
	registryBridgeReceiverKey = "receiver"
)

// exporterMetricNames maps the source metric names tracked for exporters to
// the canonical key their values accumulate under. Most names map to
// themselves; retried docs are reported under two source names that feed the
// same counter.
var exporterMetricNames = map[string]string{
	otelQueueSizeKey:            otelQueueSizeKey,
	otelQueueCapacityKey:        otelQueueCapacityKey,
	otelSentLogsKey:             otelSentLogsKey,
	otelSentSpansKey:            otelSentSpansKey,
	otelSentMetricsKey:          otelSentMetricsKey,
	otelFailedLogsKey:           otelFailedLogsKey,
	otelFailedSpansKey:          otelFailedSpansKey,
	otelFailedMetricsKey:        otelFailedMetricsKey,
	otelEnqueueFailedLogsKey:    otelEnqueueFailedLogsKey,
	otelEnqueueFailedSpansKey:   otelEnqueueFailedSpansKey,
	otelEnqueueFailedMetricsKey: otelEnqueueFailedMetricsKey,
	otelDocsProcessedKey:        otelDocsProcessedKey,
	otelDocsRetriedKey:          otelDocsRetriedKey,
	otelDocsRetriedHTTPRequest:  otelDocsRetriedKey,
	otelBulkRequestsKey:         otelBulkRequestsKey,
	otelFlushedBytesKey:         otelFlushedBytesKey,
}

// exporterMetrics accumulates raw values for a single exporter, keyed by
// canonical source metric name, along with the latest data-point timestamp
// seen. The timestamp is propagated to every output data point so downstream
// consumers see a meaningful observation time rather than the zero value.
type exporterMetrics struct {
	timestamp pcommon.Timestamp
	values    map[string]int64
}

// addMetric accumulates a metric's integer data points into em; all currently
// tracked exporter metrics are integer sums or gauges. Queue capacity is a
// point-in-time value and is overwritten rather than summed.
func (em *exporterMetrics) addMetric(m pmetric.Metric) {
	name, tracked := exporterMetricNames[m.Name()]
	if !tracked {
		return
	}
	dps := numberDataPoints(m)
	for i := 0; i < dps.Len(); i++ {
		dp := dps.At(i)
		if dp.ValueType() != pmetric.NumberDataPointValueTypeInt {
			continue
		}
		if name == otelQueueCapacityKey {
			em.values[name] = dp.IntValue()
		} else {
			em.values[name] += dp.IntValue()
		}
		if dp.Timestamp() > em.timestamp {
			em.timestamp = dp.Timestamp()
		}
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

// numberDataPoints returns the data points of a Gauge or Sum metric, or an
// empty slice for any other metric type.
func numberDataPoints(m pmetric.Metric) pmetric.NumberDataPointSlice {
	switch m.Type() {
	case pmetric.MetricTypeGauge:
		return m.Gauge().DataPoints()
	case pmetric.MetricTypeSum:
		return m.Sum().DataPoints()
	}
	return pmetric.NewNumberDataPointSlice()
}

// copyNumberMetric appends a metric to sm mirroring src's type, unit, and (for
// Sums) temporality and monotonicity, with a single data point copied from dp.
// It returns the new data point so callers can aggregate further values into it.
func copyNumberMetric(sm pmetric.ScopeMetrics, src pmetric.Metric, name string, dp pmetric.NumberDataPoint) pmetric.NumberDataPoint {
	m := sm.Metrics().AppendEmpty()
	m.SetName(name)
	m.SetUnit(src.Unit())
	var out pmetric.NumberDataPoint
	if src.Type() == pmetric.MetricTypeSum {
		s := m.SetEmptySum()
		s.SetAggregationTemporality(src.Sum().AggregationTemporality())
		s.SetIsMonotonic(src.Sum().IsMonotonic())
		out = s.DataPoints().AppendEmpty()
	} else {
		out = m.SetEmptyGauge().DataPoints().AppendEmpty()
	}
	dp.CopyTo(out)
	// Strip OTel-internal routing attributes (receiver, input_id, input_type).
	// They drove our aggregation but have no meaning in the monitoring output.
	out.Attributes().Clear()
	return out
}

// addDataPointValue adds dp's value into target when their value types match
// (mismatched types leave the value unchanged), advancing target's timestamp
// to the newer of the two.
func addDataPointValue(target, dp pmetric.NumberDataPoint) {
	if target.ValueType() == dp.ValueType() {
		switch dp.ValueType() {
		case pmetric.NumberDataPointValueTypeInt:
			target.SetIntValue(target.IntValue() + dp.IntValue())
		case pmetric.NumberDataPointValueTypeDouble:
			target.SetDoubleValue(target.DoubleValue() + dp.DoubleValue())
		}
	}
	if dp.Timestamp() > target.Timestamp() {
		target.SetTimestamp(dp.Timestamp())
	}
}

// collectExporterMetrics builds a map from elasticsearch exporter component ID
// to its accumulated exporterMetrics from the given pmetric.Metrics.
func collectExporterMetrics(md pmetric.Metrics) map[string]*exporterMetrics {
	const elasticsearchPrefix = "elasticsearch/"
	exporters := map[string]*exporterMetrics{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			exporterID := componentIDForScope(sm, "exporter")
			if !strings.HasPrefix(exporterID, elasticsearchPrefix) {
				continue
			}
			em, exists := exporters[exporterID]
			if !exists {
				em = &exporterMetrics{values: map[string]int64{}}
				exporters[exporterID] = em
			}
			for k := 0; k < sm.Metrics().Len(); k++ {
				em.addMetric(sm.Metrics().At(k))
			}
		}
	}
	return exporters
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

// --- Output helpers ---

// newEventScope adds a new ResourceMetrics+ScopeMetrics pair to out. The
// resource attributes from res (the collector's own service metadata) are
// copied to the ResourceMetrics; the standard event-type and component-ID
// scope attributes are set on the ScopeMetrics, mirroring the OTel convention
// of placing component-identifying fields on the instrumentation scope.
func newEventScope(out pmetric.Metrics, res pcommon.Resource, eventType, componentID string) pmetric.ScopeMetrics {
	rm := out.ResourceMetrics().AppendEmpty()
	res.CopyTo(rm.Resource())
	sm := rm.ScopeMetrics().AppendEmpty()
	sm.Scope().SetName(internaltelemetry.ScopeName)
	sm.Scope().Attributes().PutStr(internaltelemetry.EventTypeAttr, eventType)
	sm.Scope().Attributes().PutStr(internaltelemetry.ComponentIDAttr, componentID)
	return sm
}

// appendExporterMetrics writes the accumulated exporter values as individual
// pmetric.Metrics on sm, using Beats-compatible field names. Queue metrics are
// point-in-time gauges; event and byte counts are cumulative monotonic sums.
func appendExporterMetrics(sm pmetric.ScopeMetrics, em *exporterMetrics) {
	ts := em.timestamp

	appendGauge := func(name string, value int64) {
		m := sm.Metrics().AppendEmpty()
		m.SetName(name)
		dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
		dp.SetIntValue(value)
		dp.SetTimestamp(ts)
	}
	appendSum := func(name string, value int64) {
		m := sm.Metrics().AppendEmpty()
		m.SetName(name)
		s := m.SetEmptySum()
		s.SetAggregationTemporality(pmetric.AggregationTemporalityCumulative)
		s.SetIsMonotonic(true)
		dp := s.DataPoints().AppendEmpty()
		dp.SetIntValue(value)
		dp.SetTimestamp(ts)
	}

	queueSize, haveQueueSize := em.values[otelQueueSizeKey]
	queueCapacity, haveQueueCapacity := em.values[otelQueueCapacityKey]
	if haveQueueSize {
		appendGauge(beatsQueueFilledEventsKey, queueSize)
	}
	if haveQueueCapacity {
		appendGauge(beatsQueueMaxEventsKey, queueCapacity)
	}
	if haveQueueSize && haveQueueCapacity && queueCapacity > 0 {
		m := sm.Metrics().AppendEmpty()
		m.SetName(beatsQueueFilledPctKey)
		dp := m.SetEmptyGauge().DataPoints().AppendEmpty()
		dp.SetDoubleValue(float64(queueSize) / float64(queueCapacity))
		dp.SetTimestamp(ts)
	}

	sentTotal := em.values[otelSentLogsKey] + em.values[otelSentSpansKey] + em.values[otelSentMetricsKey]
	appendSum(beatsOutputEventsAckedKey, sentTotal)

	// Enqueue failures never reach the bulk indexer and are not counted in
	// docs.processed. Keep them separate from send failures when deriving active.
	sendFailedTotal := em.values[otelFailedLogsKey] + em.values[otelFailedSpansKey] + em.values[otelFailedMetricsKey]
	enqueueFailedTotal := em.values[otelEnqueueFailedLogsKey] + em.values[otelEnqueueFailedSpansKey] + em.values[otelEnqueueFailedMetricsKey]
	appendSum(beatsOutputEventsDroppedKey, sendFailedTotal+enqueueFailedTotal)

	if docsProcessed, ok := em.values[otelDocsProcessedKey]; ok {
		// Include queue rejections so total = acked + dropped + active.
		appendSum(beatsOutputEventsTotalKey, docsProcessed+enqueueFailedTotal)
		appendGauge(beatsOutputEventsActiveKey, docsProcessed-sentTotal-sendFailedTotal)
	}
	if docsRetried, ok := em.values[otelDocsRetriedKey]; ok {
		appendSum(beatsOutputEventsFailedKey, docsRetried)
	}
	if bulkRequests, ok := em.values[otelBulkRequestsKey]; ok {
		appendSum(beatsOutputEventsBatchesKey, bulkRequests)
	}
	if flushedBytes, ok := em.values[otelFlushedBytesKey]; ok {
		appendSum(beatsOutputWriteBytesKey, flushedBytes)
	}
}

// buildExporterMetrics appends one ResourceMetrics per elasticsearch exporter to out.
func buildExporterMetrics(logger *zap.Logger, cfg *Config, res pcommon.Resource, md pmetric.Metrics, out pmetric.Metrics) {
	for exporterID, metrics := range collectExporterMetrics(md) {
		componentID, ok := cfg.ExporterNames[exporterID]
		if !ok {
			logger.Warn("Reporting metrics for exporter with no specified component name", zap.String("exporter_id", exporterID))
			componentID = exporterID
		}
		appendExporterMetrics(newEventScope(out, res, internaltelemetry.EventTypeExporter, componentID), metrics)
	}
}

// inputSystemMetricPrefixes mirrors the systemMetricPrefixes list in the beats
// RegistryBridge (bridge.go). Metrics with these prefixes describe the beat
// process or host and are identical across all streams of a component; they
// must not appear in per-input events.
var inputSystemMetricPrefixes = []string{
	"beat.memstats.",
	"beat.cpu.",
	"beat.handles.",
	"beat.runtime.",
	"beat.cgroup.",
	"beat.info.uptime.ms",
	"system.",
}

// isInputSystemMetric reports whether name matches any of the
// inputSystemMetricPrefixes.
func isInputSystemMetric(name string) bool {
	for _, prefix := range inputSystemMetricPrefixes {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

type inputKey struct{ compID, inputID string }

type inputDP struct {
	outName string
	src     pmetric.Metric
	dp      pmetric.NumberDataPoint
}

type inputCollected struct {
	inputType string
	dps       []inputDP
}

// collectInputMetrics gathers per-(component, input) raw data points from receiver
// scopes. Only filebeat receiver metrics that carry an input_id attribute and are
// not system-level metrics are included. The component ID has its per-stream suffix
// stripped so all streams of the same component aggregate together.
func collectInputMetrics(md pmetric.Metrics) map[inputKey]*inputCollected {
	result := map[inputKey]*inputCollected{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)

			// Accept receiver-kind scopes; fall back to any scope that carries a
			// component ID but no explicit non-receiver kind (e.g. beat bridge metrics).
			otelID := componentIDForScope(sm, "receiver")
			if otelID == "" {
				if kindVal, hasKind := sm.Scope().Attributes().Get(otelComponentKindKey); hasKind && kindVal.Str() != "receiver" {
					continue
				}
				idVal, ok := sm.Scope().Attributes().Get(otelComponentIDKey)
				if !ok {
					continue
				}
				otelID = idVal.Str()
			}

			beatType := beatTypeFromOtelID(otelID)
			compID := baseComponentID(agentComponentID(otelID))
			if compID == "" || beatType != "filebeat" {
				continue
			}

			for k := 0; k < sm.Metrics().Len(); k++ {
				m := sm.Metrics().At(k)
				if isInputSystemMetric(m.Name()) {
					continue
				}
				outName := beatType + "_input." + m.Name()
				dps := numberDataPoints(m)
				for l := 0; l < dps.Len(); l++ {
					dp := dps.At(l)
					inputIDVal, ok := dp.Attributes().Get(otelInputIDKey)
					if !ok || dp.ValueType() == pmetric.NumberDataPointValueTypeEmpty {
						continue
					}
					key := inputKey{compID: compID, inputID: inputIDVal.Str()}
					acc := result[key]
					if acc == nil {
						acc = &inputCollected{}
						result[key] = acc
					}
					if acc.inputType == "" {
						if v, ok := dp.Attributes().Get(otelInputTypeKey); ok {
							acc.inputType = v.Str()
						}
					}
					acc.dps = append(acc.dps, inputDP{outName: outName, src: m, dp: dp})
				}
			}
		}
	}
	return result
}

// buildInputMetrics appends one ResourceMetrics per (component, input) pair to out.
func buildInputMetrics(res pcommon.Resource, md pmetric.Metrics, out pmetric.Metrics) {
	for key, acc := range collectInputMetrics(md) {
		sm := newEventScope(out, res, internaltelemetry.EventTypeInput, key.compID)
		sm.Scope().Attributes().PutStr(internaltelemetry.InputIDAttr, key.inputID)
		if acc.inputType != "" {
			sm.Scope().Attributes().PutStr(internaltelemetry.InputTypeAttr, acc.inputType)
		}
		fields := map[string]pmetric.NumberDataPoint{}
		for _, raw := range acc.dps {
			if existing, ok := fields[raw.outName]; ok {
				addDataPointValue(existing, raw.dp)
			} else {
				fields[raw.outName] = copyNumberMetric(sm, raw.src, raw.outName, raw.dp)
			}
		}
	}
}

type receiverDP struct {
	field string
	src   pmetric.Metric
	dp    pmetric.NumberDataPoint
}

// collectReceiverPipelineMetrics gathers per-component raw data points from the
// RegistryBridge instrumentation scope. Data points that carry an input_id attribute
// are excluded because buildInputMetrics handles them.
func collectReceiverPipelineMetrics(md pmetric.Metrics) map[string][]receiverDP {
	result := map[string][]receiverDP{}
	beatTypes := map[string]string{}
	for i := 0; i < md.ResourceMetrics().Len(); i++ {
		rm := md.ResourceMetrics().At(i)
		for j := 0; j < rm.ScopeMetrics().Len(); j++ {
			sm := rm.ScopeMetrics().At(j)
			if sm.Scope().Name() != registryBridgeScopeName {
				continue
			}
			for k := 0; k < sm.Metrics().Len(); k++ {
				m := sm.Metrics().At(k)
				dps := numberDataPoints(m)
				for l := 0; l < dps.Len(); l++ {
					dp := dps.At(l)
					receiverVal, ok := dp.Attributes().Get(registryBridgeReceiverKey)
					if !ok || dp.ValueType() == pmetric.NumberDataPointValueTypeEmpty {
						continue
					}
					if _, hasInputID := dp.Attributes().Get(otelInputIDKey); hasInputID {
						continue
					}
					otelID := receiverVal.Str()
					compID := baseComponentID(agentComponentID(otelID))
					if compID == "" {
						continue
					}
					bt, ok := beatTypes[otelID]
					if !ok {
						bt = beatTypeFromOtelID(otelID)
						beatTypes[otelID] = bt
					}
					result[compID] = append(result[compID], receiverDP{
						field: receiverMetricField(bt, m.Name()),
						src:   m,
						dp:    dp,
					})
				}
			}
		}
	}
	return result
}

// buildReceiverPipelineMetrics appends one ResourceMetrics per component to out.
// Per-container receivers sharing the same base component ID are aggregated into
// a single event with summed values.
func buildReceiverPipelineMetrics(res pcommon.Resource, md pmetric.Metrics, out pmetric.Metrics) {
	for compID, dps := range collectReceiverPipelineMetrics(md) {
		sm := newEventScope(out, res, internaltelemetry.EventTypeReceiver, compID)
		fields := map[string]pmetric.NumberDataPoint{}
		for _, raw := range dps {
			if existing, ok := fields[raw.field]; ok {
				addDataPointValue(existing, raw.dp)
			} else {
				fields[raw.field] = copyNumberMetric(sm, raw.src, raw.field, raw.dp)
			}
		}
	}
}
