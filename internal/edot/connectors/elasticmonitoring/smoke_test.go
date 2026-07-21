// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package elasticmonitoring

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
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-libs/mapstr"
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

// TestSmoke_ReceiverPipelineEvents verifies that buildReceiverPipelineEvents
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

	events := buildReceiverPipelineEvents(&Config{}, md)

	componentIDs := make([]string, 0, len(events))
	for _, e := range events {
		id, err := e.GetValue("component.id")
		require.NoError(t, err)
		componentIDs = append(componentIDs, id.(string))
	}

	// Both monitoring receiver streams must aggregate to the full comp.ID.
	assert.Contains(t, componentIDs, "http/metrics-monitoring",
		"monitoring component with slash in comp.ID must not be truncated to 'http'")

	// Both per-container filestream-default receivers must aggregate to the base comp.ID.
	assert.Contains(t, componentIDs, "filestream-default",
		"per-container receivers must be aggregated under the base component ID")

	// The two http/metrics-monitoring streams must produce exactly one event, not two.
	count := 0
	for _, id := range componentIDs {
		if id == "http/metrics-monitoring" {
			count++
		}
	}
	assert.Equal(t, 1, count, "two per-stream monitoring receivers must produce exactly one aggregated event")

	// The two filestream-default container receivers must produce exactly one event.
	count = 0
	for _, id := range componentIDs {
		if id == "filestream-default" {
			count++
		}
	}
	assert.Equal(t, 1, count, "two per-container filestream receivers must produce exactly one aggregated event")

	// Truncated IDs must not appear.
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

	events := buildReceiverPipelineEvents(&Config{}, md)

	var monEv mapstr.M
	for _, e := range events {
		id, _ := e.GetValue("component.id")
		if id == "http/metrics-monitoring" {
			monEv = e
			break
		}
	}
	require.NotNil(t, monEv, "expected event for http/metrics-monitoring component")

	// metricbeat.http.json.events = 4 in the fixture — should map to
	// "beat.stats.metricbeat.http.json.events", not the double-prefixed form.
	assert.Equal(t, int64(4),
		eventValue(t, monEv, "beat.stats.metricbeat.http.json.events"),
		"metricbeat.* metric must be prefixed with beat.stats.metricbeat., not double-prefixed")

	// The double-prefixed form must not exist.
	_, err := monEv.GetValue("beat.stats.metricbeat.metricbeat.http.json.events")
	assert.Error(t, err, "double-prefixed metric name must not appear in the event")
}

// TestSmoke_ExporterEvents verifies that buildExporterEvents maps the monitoring
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

	events := buildExporterEvents(zap.NewNop(), cfg, md)

	byComponent := make(map[string]map[string]any, len(events))
	for _, e := range events {
		id, err := e.GetValue("component.id")
		require.NoError(t, err)
		byComponent[id.(string)] = e
	}

	// Monitoring exporter: queue capacity from exporterhelper scope.
	monEv, ok := byComponent["monitoring"]
	require.True(t, ok, "expected event for monitoring exporter")
	assert.Equal(t, int64(3200),
		eventValue(t, monEv, "beat.stats.libbeat.pipeline.queue.max_events"),
		"queue capacity from exporterhelper scope")

	// Default exporter: docs.processed from elasticsearchexporter scope.
	defEv, ok := byComponent["elasticsearch-default"]
	require.True(t, ok, "expected event for default exporter")
	assert.Equal(t, int64(447),
		eventValue(t, defEv, "beat.stats.libbeat.output.events.total"),
		"docs.processed from elasticsearchexporter scope")
}
