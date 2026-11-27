// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package manager

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths/pathstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/featuregate"

	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/pkg/component"
)

// mergeAppendGate is the confmap feature gate the agent turns on at startup. It changes how
// Conf.Merge treats lists, so the merged config has to be correct with it both on and off.
const mergeAppendGate = "confmap.enableMergeAppendOption"

// setMergeAppendGate sets the gate for the duration of the test and restores its previous value afterwards.
func setMergeAppendGate(t testing.TB, enabled bool) {
	t.Helper()
	registry := featuregate.GlobalRegistry()
	var previous bool
	registry.VisitAll(func(gate *featuregate.Gate) {
		if gate.ID() == mergeAppendGate {
			previous = gate.IsEnabled()
		}
	})
	require.NoError(t, registry.Set(mergeAppendGate, enabled))
	t.Cleanup(func() { require.NoError(t, registry.Set(mergeAppendGate, previous)) })
}

// forEachMergeAppendGate runs f with the merge append gate off and on. The agent runs with it on.
func forEachMergeAppendGate(t *testing.T, f func(t *testing.T, gateEnabled bool)) {
	t.Helper()
	for _, enabled := range []bool{false, true} {
		t.Run(fmt.Sprintf("merge append gate %t", enabled), func(t *testing.T) {
			setMergeAppendGate(t, enabled)
			f(t, enabled)
		})
	}
}

func setTestTopPath(t testing.TB) {
	t.Helper()
	pathstest.SetTop(t, t.TempDir())
}

// buildTestMergedConfig builds the merged config for update, with the agent log level at warn.
func buildTestMergedConfig(t *testing.T, update configUpdate) *confmap.Conf {
	t.Helper()
	update.agentLogLevel = logp.WarnLevel
	m := &OTelManager{healthCheckExtComponentID: "healthcheckv2/test", collectorMetricsPort: 8888, hostInfo: testHostInfo}
	got, err := m.buildMergedConfig(t.Context(), update, &info.AgentInfo{}, logp.NewNopLogger())
	require.NoError(t, err)
	require.NotNil(t, got)
	return got
}

// The collector config lists the extension of the component after an extension of its own. The merged
// list has the extensions of both and the ones the agent adds, in an order that depends on the gate.
func TestBuildMergedConfigExtensions(t *testing.T) {
	setTestTopPath(t)
	expected := map[bool][]any{
		false: {"zpages", "beatsauth/_agent-component/", "headers_setter/_agent-component/", "elastic_diagnostics", "elastic_meter_lifecycle", "healthcheckv2/test"},
		true:  {"beatsauth/_agent-component/", "headers_setter/_agent-component/", "zpages", "elastic_diagnostics", "elastic_meter_lifecycle", "healthcheckv2/test"},
	}

	forEachMergeAppendGate(t, func(t *testing.T, gateEnabled bool) {
		got := buildTestMergedConfig(t, configUpdate{
			components: []component.Component{testComponent("default-output")},
			collectorCfg: confmap.NewFromStringMap(map[string]any{
				"extensions": map[string]any{"zpages": map[string]any{}},
				"service":    map[string]any{"extensions": []any{"zpages", "beatsauth/_agent-component/"}},
			}),
		})

		assert.Equal(t, expected[gateEnabled], got.Get("service::extensions"))
	})
}

func TestBuildMergedConfigKeepsCollectorAndComponentConfigs(t *testing.T) {
	setTestTopPath(t)

	forEachMergeAppendGate(t, func(t *testing.T, _ bool) {
		got := buildTestMergedConfig(t, configUpdate{
			components:   []component.Component{testComponent("default-output")},
			collectorCfg: confmap.NewFromStringMap(testConfig),
		})

		receivers, ok := got.Get("receivers").(map[string]any)
		require.True(t, ok)
		assert.Contains(t, receivers, "nop")
		assert.Contains(t, receivers, "filebeatreceiver/_agent-component/default-output/filestream-unit-test-1")
		assert.Contains(t, receivers, "filebeatreceiver/_agent-component/default-output/filestream-unit-test-2")

		exporters, ok := got.Get("exporters").(map[string]any)
		require.True(t, ok)
		assert.Contains(t, exporters, "nop")
		assert.Contains(t, exporters, "elasticsearch/_agent-component/")

		assert.True(t, got.IsSet("service::pipelines::traces"), "pipeline of the collector config")
		assert.True(t, got.IsSet("service::pipelines::logs/_agent-component/default-output"), "pipeline of the component")
	})
}

func TestBuildMergedConfigCollectorTelemetry(t *testing.T) {
	setTestTopPath(t)
	components := []component.Component{testComponent("default-output")}
	consoleReader := map[string]any{"periodic": map[string]any{"exporter": map[string]any{"console": map[string]any{}}}}
	prometheusReader := map[string]any{"pull": map[string]any{"exporter": map[string]any{"prometheus": map[string]any{
		"host": "localhost", "port": 8888, "without_scope_info": false,
	}}}}

	t.Run("the log level and readers of the collector config are kept", func(t *testing.T) {
		got := buildTestMergedConfig(t, configUpdate{
			components: components,
			collectorCfg: confmap.NewFromStringMap(map[string]any{"service": map[string]any{"telemetry": map[string]any{
				"logs":    map[string]any{"level": "debug"},
				"metrics": map[string]any{"readers": []any{consoleReader}},
			}}}),
		})

		assert.Equal(t, "debug", got.Get("service::telemetry::logs::level"))
		assert.Equal(t, []any{consoleReader, prometheusReader}, got.Get("service::telemetry::metrics::readers"))
	})

	t.Run("the agent log level and a reader are added otherwise", func(t *testing.T) {
		got := buildTestMergedConfig(t, configUpdate{components: components})

		assert.Equal(t, "WARN", got.Get("service::telemetry::logs::level"))
		assert.Equal(t, []any{prometheusReader}, got.Get("service::telemetry::metrics::readers"))
	})
}

func TestBuildMergedConfigMonitoringReceiver(t *testing.T) {
	setTestTopPath(t)
	monitoring := &config.MonitoringConfig{Enabled: true, MonitorMetrics: true, MetricsPeriod: time.Minute}
	const (
		metricsPipeline = "service::pipelines::metrics/_agent-component/internal-telemetry-monitoring"
		logsPipeline    = "service::pipelines::logs/_agent-component/internal-telemetry-monitoring"
		fileExporter    = "file/_agent-component/internal-telemetry-monitoring"
		connector       = "elasticmonitoringconnector/_agent-component/internal-telemetry-monitoring"
	)
	defaultOutputComp := testComponent("default-output")
	// A component using the monitoring output defines the exporter that the internal telemetry
	// pipeline shares.
	monitoringOutputComp := testComponent("monitoring-output")
	monitoringOutputComp.OutputName = componentmonitoring.MonitoringOutput

	t.Run("without a monitoring exporter the metrics only go to a file", func(t *testing.T) {
		got := buildTestMergedConfig(t, configUpdate{
			components:    []component.Component{defaultOutputComp},
			monitoringCfg: monitoring,
		})

		assert.ElementsMatch(t, []string{fileExporter}, got.Get(metricsPipeline+"::exporters"))
		assert.False(t, got.IsSet(logsPipeline))
	})

	t.Run("with a monitoring exporter the metrics also go to it", func(t *testing.T) {
		got := buildTestMergedConfig(t, configUpdate{
			components:    []component.Component{defaultOutputComp, monitoringOutputComp},
			monitoringCfg: monitoring,
		})

		assert.ElementsMatch(t, []string{fileExporter, connector}, got.Get(metricsPipeline+"::exporters"))
		assert.ElementsMatch(t, []string{"elasticsearch/_agent-component/monitoring"}, got.Get(logsPipeline+"::exporters"))
	})
}

// testComponentWithInputs returns a filestream component with one input unit, each with one stream, per input.
func testComponentWithInputs(id string, inputs int) component.Component {
	comp := testComponent(id)
	output := comp.Units[1]
	comp.Units = make([]component.Unit, 0, inputs+1)
	for i := 0; i < inputs; i++ {
		comp.Units = append(comp.Units, component.Unit{
			ID:   fmt.Sprintf("filestream-unit-%d", i),
			Type: client.UnitTypeInput,
			Config: component.MustExpectedConfig(map[string]any{
				"id":         fmt.Sprintf("input-%d", i),
				"use_output": "default",
				"streams": []any{
					map[string]any{
						"id":          fmt.Sprintf("stream-%d", i),
						"data_stream": map[string]any{"dataset": "generic"},
						"paths":       []any{filepath.Join(paths.TempDir(), fmt.Sprintf("nonexistent-%d.log", i))},
					},
				},
			}),
		})
	}
	comp.Units = append(comp.Units, output)
	return comp
}

// BenchmarkBuildMergedConfig measures building the collector config for a policy with many inputs.
// Allocations are what matter: the config is rebuilt on every policy change.
func BenchmarkBuildMergedConfig(b *testing.B) {
	setTestTopPath(b)
	// The agent runs with this gate on, and it makes every Conf.Merge more expensive.
	setMergeAppendGate(b, true)

	const inputs = 10_000
	comp := testComponentWithInputs("bench", inputs)
	m := &OTelManager{healthCheckExtComponentID: "healthcheckv2/test", collectorMetricsPort: 8888, hostInfo: testHostInfo}
	agentInfo := &info.AgentInfo{}
	logger := logp.NewNopLogger()

	b.Run(fmt.Sprintf("inputs=%d", inputs), func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			update := configUpdate{
				collectorCfg:  confmap.NewFromStringMap(testConfig),
				components:    []component.Component{comp},
				agentLogLevel: logp.InfoLevel,
			}
			if _, err := m.buildMergedConfig(b.Context(), update, agentInfo, logger); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestBuildMergedConfigAgentMetadataProcessor verifies that the agent metadata processor is added to logs pipelines
// from the collector config, but not to the pipelines of beat receivers, which set the agent metadata themselves.
func TestBuildMergedConfigAgentMetadataProcessor(t *testing.T) {
	pathstest.SetTop(t, t.TempDir())

	m := &OTelManager{
		healthCheckExtComponentID: "healthcheckv2/test",
		hostInfo:                  testHostInfo,
	}
	cfgUpdate := configUpdate{
		collectorCfg: confmap.NewFromStringMap(map[string]any{
			"receivers": map[string]any{"nop": map[string]any{}},
			"exporters": map[string]any{"nop": map[string]any{}},
			"service": map[string]any{
				"pipelines": map[string]any{
					"logs/user": map[string]any{
						"receivers": []any{"nop"},
						"exporters": []any{"nop"},
					},
				},
			},
		}),
		components: []component.Component{testComponent("test-component")},
	}

	result, err := m.buildMergedConfig(t.Context(), cfgUpdate, &info.AgentInfo{}, logp.NewNopLogger())
	require.NoError(t, err)

	pipelines, ok := result.Get("service::pipelines").(map[string]any)
	require.True(t, ok)
	require.Greater(t, len(pipelines), 1, "expected component pipelines in the merged config")
	for id := range pipelines {
		processors := fmt.Sprint(result.Get("service::pipelines::" + id + "::processors"))
		if id == "logs/user" {
			assert.Equal(t, fmt.Sprint([]any{agentMetadataProcessorID}), processors)
		} else {
			assert.NotContains(t, processors, agentMetadataProcessorID, "pipeline %s", id)
		}
	}
	assert.True(t, result.IsSet("processors::"+agentMetadataProcessorID))
}
