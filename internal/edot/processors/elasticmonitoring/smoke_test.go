// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoringprocessor

// Smoke tests against real OTLP metrics captured from a running elastic-agent
// (testdata/diagnostics-metrics.json). The fixture covers combinations that
// actually occur in production:
//   - Per-container filebeatreceiver scopes (two containers, same base component ID)
//   - metricbeatreceiver scopes for monitoring components whose comp.ID contains "/"
//     (e.g. "http/metrics-monitoring"), served by two separate per-stream receivers
//   - elasticsearch exporter scopes from both the exporterhelper and the
//     elasticsearchexporter instrumentation libraries

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/pmetric"

	"github.com/elastic/elastic-agent/internal/edot/internaltelemetry"
)

func loadRealDataFixture(t *testing.T) pmetric.Metrics {
	t.Helper()
	raw, err := os.ReadFile("testdata/diagnostics-metrics.json")
	require.NoError(t, err)
	var u pmetric.JSONUnmarshaler
	md, err := u.UnmarshalMetrics(raw)
	require.NoError(t, err)
	return md
}

// collectComponentIDs returns all component.id scope attribute values in out.
func collectComponentIDs(out pmetric.Metrics) []string {
	ids := make([]string, 0, out.ResourceMetrics().Len())
	for i := 0; i < out.ResourceMetrics().Len(); i++ {
		rm := out.ResourceMetrics().At(i)
		if rm.ScopeMetrics().Len() == 0 {
			continue
		}
		if v, ok := rm.ScopeMetrics().At(0).Scope().Attributes().Get(internaltelemetry.ComponentIDAttr); ok {
			ids = append(ids, v.Str())
		}
	}
	return ids
}

// TestSmoke_ReceiverPipelineEvents verifies that buildReceiverPipelineMetrics
// correctly extracts component IDs from real RegistryBridge metric scopes.
//
// Expected behaviour:
//  1. Two per-container filebeatreceiver scopes sharing the same base
//     component ID ("filestream-default") are merged into a single event.
//  2. Two per-stream metricbeatreceiver scopes for the monitoring component
//     "http/metrics-monitoring" are merged into a single event keyed by the
//     full "http/metrics-monitoring" — the slash in the comp.ID must NOT be
//     treated as a per-container separator.
func TestSmoke_ReceiverPipelineEvents(t *testing.T) {
	md := loadRealDataFixture(t)
	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	componentIDs := collectComponentIDs(out)

	assert.Contains(t, componentIDs, "http/metrics-monitoring",
		"monitoring component with slash in comp.ID must not be truncated to 'http'")
	assert.Contains(t, componentIDs, "filestream-default",
		"per-container receivers must be aggregated under the base component ID")

	count := 0
	for _, id := range componentIDs {
		if id == "http/metrics-monitoring" {
			count++
		}
	}
	assert.Equal(t, 1, count, "two per-stream monitoring receivers must produce exactly one aggregated event")

	count = 0
	for _, id := range componentIDs {
		if id == "filestream-default" {
			count++
		}
	}
	assert.Equal(t, 1, count, "two per-container filestream receivers must produce exactly one aggregated event")

	assert.NotContains(t, componentIDs, "http",
		"component.id must not be 'http' — that indicates baseComponentID cut at the wrong slash")
}

// TestSmoke_MetricNamePrefixing verifies that receiverMetricField does not
// double-prefix beat-type-specific metric names. The monitoring metricbeatreceiver
// emits metrics whose names already start with "metricbeat." (e.g.
// "metricbeat.http.json.events"). Adding the beat-type prefix again would produce
// "beat.stats.metricbeat.metricbeat.http.json.events"; the correct output is
// "beat.stats.metricbeat.http.json.events".
func TestSmoke_MetricNamePrefixing(t *testing.T) {
	md := loadRealDataFixture(t)
	out := pmetric.NewMetrics()
	buildReceiverPipelineMetrics(pcommon.NewResource(), md, out)

	var targetIdx int = -1
	for i := 0; i < out.ResourceMetrics().Len(); i++ {
		rm := out.ResourceMetrics().At(i)
		if rm.ScopeMetrics().Len() == 0 {
			continue
		}
		if v, ok := rm.ScopeMetrics().At(0).Scope().Attributes().Get(internaltelemetry.ComponentIDAttr); ok && v.Str() == "http/metrics-monitoring" {
			targetIdx = i
			break
		}
	}
	require.NotEqual(t, -1, targetIdx, "expected event for http/metrics-monitoring component")

	// metricbeat.http.json.events = 4 in the fixture
	assert.Equal(t, int64(4),
		findMetricValue(t, out, targetIdx, "beat.stats.metricbeat.http.json.events"),
		"metricbeat.* metric must be prefixed with beat.stats.metricbeat., not double-prefixed")

	// Confirm the double-prefixed form is absent by checking the fixture value doesn't
	// appear under the wrong name — we check this by scanning for the bad name directly.
	badName := "beat.stats.metricbeat.metricbeat.http.json.events"
	rm := out.ResourceMetrics().At(targetIdx)
	for i := 0; i < rm.ScopeMetrics().Len(); i++ {
		sm := rm.ScopeMetrics().At(i)
		for j := 0; j < sm.Metrics().Len(); j++ {
			assert.NotEqual(t, badName, sm.Metrics().At(j).Name(), "double-prefixed metric name must not appear")
		}
	}
}

// TestSmoke_ReceiverDoesNotDoubleCountInputMetrics is a regression test for the
// double-counting bug where RegistryBridge data points carrying both a "receiver"
// attribute (processed by collectReceiverPipelineMetrics) and an "input_id"
// attribute (processed by collectInputMetrics) appeared in both receiver events
// and input events.
//
// The fixture (testdata/double-counting-metrics.json) models this pattern with:
//   - "libbeat.output.events.acked" — receiver attribute only → receiver events only
//   - "beat.input.log.files.open"   — receiver + input_id     → input events only
func TestSmoke_ReceiverDoesNotDoubleCountInputMetrics(t *testing.T) {
	raw, err := os.ReadFile("testdata/double-counting-metrics.json")
	require.NoError(t, err)
	var u pmetric.JSONUnmarshaler
	md, err := u.UnmarshalMetrics(raw)
	require.NoError(t, err)

	receiverResult := collectReceiverPipelineMetrics(md)
	inputResult := collectInputMetrics(md)

	const compID = "filestream-monitoring"

	// The data point with input_id must not appear in receiver pipeline events.
	for _, dp := range receiverResult[compID] {
		assert.NotEqual(t, "beat.input.log.files.open", dp.src.Name(),
			"data points with input_id must be excluded from receiver pipeline metrics to prevent double-counting")
	}

	// The receiver-only data point must still appear in receiver pipeline events.
	receiverFound := false
	for _, dp := range receiverResult[compID] {
		if dp.src.Name() == "libbeat.output.events.acked" {
			receiverFound = true
			break
		}
	}
	assert.True(t, receiverFound, "data points without input_id must still appear in receiver pipeline events")

	// The data point with input_id must appear in input events.
	inputFound := false
	for _, acc := range inputResult {
		for _, dp := range acc.dps {
			if dp.src.Name() == "beat.input.log.files.open" {
				inputFound = true
				break
			}
		}
		if inputFound {
			break
		}
	}
	assert.True(t, inputFound, "data points with input_id must appear in input events")
}

// TestSmoke_ExporterEvents verifies that buildExporterMetrics maps the monitoring
// ES exporter metrics to the configured component name and correctly surfaces
// queue capacity and docs.processed from real exporter scopes.
func TestSmoke_ExporterEvents(t *testing.T) {
	md := loadRealDataFixture(t)

	const monitoringExporterID = "elasticsearch/_agent-component/monitoring"
	const defaultExporterID = "elasticsearch/_agent-component/default"
	cfg := &Config{
		ExporterNames: map[string]string{
			monitoringExporterID: "monitoring",
			defaultExporterID:    "elasticsearch-default",
		},
	}

	out := pmetric.NewMetrics()
	buildExporterMetrics(nil, cfg, pcommon.NewResource(), md, out)

	// Find each exporter by component ID
	monIdx := -1
	defIdx := -1
	for i := 0; i < out.ResourceMetrics().Len(); i++ {
		rm := out.ResourceMetrics().At(i)
		if rm.ScopeMetrics().Len() == 0 {
			continue
		}
		v, ok := rm.ScopeMetrics().At(0).Scope().Attributes().Get(internaltelemetry.ComponentIDAttr)
		if !ok {
			continue
		}
		switch v.Str() {
		case "monitoring":
			monIdx = i
		case "elasticsearch-default":
			defIdx = i
		}
	}

	require.NotEqual(t, -1, monIdx, "expected event for monitoring exporter")
	assert.Equal(t, int64(3200),
		findMetricValue(t, out, monIdx, beatsQueueMaxEventsKey),
		"queue capacity from exporterhelper scope")

	require.NotEqual(t, -1, defIdx, "expected event for default exporter")
	assert.Equal(t, int64(447),
		findMetricValue(t, out, defIdx, beatsOutputEventsTotalKey),
		"docs.processed from elasticsearchexporter scope")
}
