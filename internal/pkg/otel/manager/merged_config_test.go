// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package manager

import (
	"errors"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"go.opentelemetry.io/collector/featuregate"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	componentmonitoring "github.com/elastic/elastic-agent/internal/pkg/agent/application/monitoring/component"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/otel/translate"
	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/ecsmeta"
)

// mergeAppendGate is the confmap feature gate the agent turns on at startup. It changes how
// Conf.Merge treats lists, so the merged config has to be correct with it both on and off.
const mergeAppendGate = "confmap.enableMergeAppendOption"

func setMergeAppendGate(t testing.TB, enabled bool) {
	t.Helper()
	registry := featuregate.GlobalRegistry()
	require.NoError(t, registry.Set(mergeAppendGate, enabled))
	t.Cleanup(func() { _ = registry.Set(mergeAppendGate, false) })
}

func setTestTopPath(t testing.TB) {
	t.Helper()
	topPath := paths.Top()
	paths.SetTop(t.TempDir())
	t.Cleanup(func() { paths.SetTop(topPath) })
}

// noHostInfoAgent is an info.Agent that does not look up host information, so the monitoring
// templates fall back to os.Hostname. Besides being faster, this keeps the comparison below
// reliable on macOS, where go-sysinfo's memory lookup, which ECSMetadata calls, has been seen
// overwriting unrelated strings on the Go heap.
type noHostInfoAgent struct {
	info.Agent
}

func (noHostInfoAgent) ECSMetadata(*logger.Logger) (*ecsmeta.ECSMeta, error) {
	return nil, errors.New("host information is not looked up in tests")
}

// buildMergedConfigSequential is the straightforward way to build the merged config: every piece
// is merged, in order, into a Conf that starts out empty. That copies the whole config for each
// piece, which is why buildMergedConfig does not work this way, but it defines the result that
// buildMergedConfig has to produce.
func buildMergedConfigSequential(
	m *OTelManager,
	cfgUpdate configUpdate,
	agentInfo info.Agent,
	logger *logp.Logger,
) (*confmap.Conf, error) {
	mergedOtelCfg := confmap.New()

	var componentOtelCfg *confmap.Conf
	if len(cfgUpdate.components) > 0 {
		model := &component.Model{Components: cfgUpdate.components}
		var err error
		componentOtelCfg, err = translate.GetOtelConfig(model, logger)
		if err != nil {
			return nil, fmt.Errorf("failed to generate otel config: %w", err)
		}
	}

	if componentOtelCfg == nil && cfgUpdate.collectorCfg == nil {
		return nil, nil
	}

	if componentOtelCfg != nil {
		if err := mergeWithExtensions(mergedOtelCfg, componentOtelCfg); err != nil {
			return nil, err
		}
		if err := injectHeaderSetterExtension(mergedOtelCfg, agentInfo); err != nil {
			return nil, err
		}
		if mCfg := cfgUpdate.monitoringCfg; mCfg != nil && mCfg.Enabled && mCfg.MonitorMetrics {
			if err := injectMonitoringReceiver(mergedOtelCfg, mCfg, agentInfo, cfgUpdate.components, logger); err != nil {
				return nil, err
			}
		}
	}

	if cfgUpdate.collectorCfg != nil {
		if err := mergeWithExtensions(mergedOtelCfg, cfgUpdate.collectorCfg); err != nil {
			return nil, err
		}
	}

	if err := injectDiagnosticsExtension(mergedOtelCfg); err != nil {
		return nil, err
	}
	if err := injectMeterLifecycleExtension(mergedOtelCfg); err != nil {
		return nil, err
	}
	if err := maybeInjectLogLevel(mergedOtelCfg, component.MinLogLevel(cfgUpdate.agentLogLevel, cfgUpdate.components)); err != nil {
		return nil, err
	}
	if err := injectHealthCheckV2Extension(mergedOtelCfg, m.healthCheckExtComponentID, 0); err != nil {
		return nil, err
	}
	if err := addCollectorMetricsReader(mergedOtelCfg, m.collectorMetricsPort); err != nil {
		return nil, err
	}
	return mergedOtelCfg, nil
}

func TestBuildMergedConfigMatchesSequentialMerge(t *testing.T) {
	setTestTopPath(t)

	defaultOutputComp := testComponent("default-output")
	// A component using the monitoring output defines the exporter that the internal telemetry
	// pipeline shares.
	monitoringOutputComp := testComponent("monitoring-output")
	monitoringOutputComp.OutputName = componentmonitoring.MonitoringOutput

	// Take the names the collector config has to collide with from the generated component config.
	componentCfg, err := translate.GetOtelConfig(&component.Model{Components: []component.Component{defaultOutputComp}}, logp.NewNopLogger())
	require.NoError(t, err)
	require.NotNil(t, componentCfg)
	componentPipelines, ok := componentCfg.Get("service::pipelines").(map[string]any)
	require.True(t, ok)
	require.NotEmpty(t, componentPipelines)
	var componentPipelineID string
	for id := range componentPipelines {
		componentPipelineID = id
	}
	componentExtensions, ok := componentCfg.Get("service::extensions").([]any)
	require.True(t, ok)
	require.NotEmpty(t, componentExtensions)

	// overlappingCollectorCfg shares a pipeline and an extension with the component config, lists
	// the shared extension after one of its own, and sets collector metrics readers.
	overlappingCollectorCfg := func() *confmap.Conf {
		return confmap.NewFromStringMap(map[string]any{
			"receivers": map[string]any{"nop": map[string]any{}},
			"exporters": map[string]any{"nop": map[string]any{}},
			"extensions": map[string]any{
				"zpages": map[string]any{},
			},
			"service": map[string]any{
				"extensions": []any{"zpages", componentExtensions[0]},
				"pipelines": map[string]any{
					componentPipelineID: map[string]any{
						"receivers": []any{"nop"},
						"exporters": []any{"nop"},
					},
				},
				"telemetry": map[string]any{
					"metrics": map[string]any{
						"readers": []any{
							map[string]any{"periodic": map[string]any{"exporter": map[string]any{"console": map[string]any{}}}},
						},
					},
				},
			},
		})
	}
	monitoringOn := &config.MonitoringConfig{Enabled: true, MonitorMetrics: true, MetricsPeriod: time.Minute}

	tests := []struct {
		name         string
		components   []component.Component
		collectorCfg func() *confmap.Conf
		monitoring   *config.MonitoringConfig
	}{
		{
			name:       "components only",
			components: []component.Component{defaultOutputComp},
		},
		{
			name:         "collector config only",
			collectorCfg: overlappingCollectorCfg,
		},
		{
			name:         "components and collector config with log level",
			components:   []component.Component{defaultOutputComp},
			collectorCfg: func() *confmap.Conf { return confmap.NewFromStringMap(testConfig) },
		},
		{
			name:         "components and collector config without log level",
			components:   []component.Component{defaultOutputComp},
			collectorCfg: func() *confmap.Conf { return confmap.NewFromStringMap(testConfigNoLogLevel) },
		},
		{
			name:         "collector config sharing pipeline and extension with the components",
			components:   []component.Component{defaultOutputComp},
			collectorCfg: overlappingCollectorCfg,
		},
		{
			name:       "monitoring without a monitoring exporter",
			components: []component.Component{defaultOutputComp},
			monitoring: monitoringOn,
		},
		{
			name:         "monitoring with a monitoring exporter and collector config",
			components:   []component.Component{defaultOutputComp, monitoringOutputComp},
			collectorCfg: overlappingCollectorCfg,
			monitoring:   monitoringOn,
		},
		{
			name:         "monitoring disabled",
			components:   []component.Component{defaultOutputComp, monitoringOutputComp},
			collectorCfg: overlappingCollectorCfg,
			monitoring:   &config.MonitoringConfig{Enabled: true, MonitorMetrics: false},
		},
	}

	for _, gateEnabled := range []bool{false, true} {
		for _, tt := range tests {
			t.Run(fmt.Sprintf("%s/merge append gate %t", tt.name, gateEnabled), func(t *testing.T) {
				setMergeAppendGate(t, gateEnabled)

				newUpdate := func() configUpdate {
					// Merging may modify its source, so each build gets its own collector config.
					update := configUpdate{
						components:    tt.components,
						monitoringCfg: tt.monitoring,
						agentLogLevel: logp.WarnLevel,
					}
					if tt.collectorCfg != nil {
						update.collectorCfg = tt.collectorCfg()
					}
					return update
				}
				m := &OTelManager{healthCheckExtComponentID: "healthcheckv2/test", collectorMetricsPort: 8888}
				agentInfo := noHostInfoAgent{&info.AgentInfo{}}

				want, err := buildMergedConfigSequential(m, newUpdate(), agentInfo, logp.NewNopLogger())
				require.NoError(t, err)
				got, err := m.buildMergedConfig(newUpdate(), agentInfo, logp.NewNopLogger())
				require.NoError(t, err)

				require.NotNil(t, want)
				require.NotNil(t, got)
				assert.Equal(t, want.ToStringMap(), got.ToStringMap())
				if tt.monitoring == monitoringOn {
					// Make sure the monitoring receiver is part of what was compared.
					assert.True(t, got.IsSet("service::pipelines::metrics/"+translate.OtelNamePrefix+"internal-telemetry-monitoring::receivers"))
				}
			})
		}
	}
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
	m := &OTelManager{healthCheckExtComponentID: "healthcheckv2/test", collectorMetricsPort: 8888}
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
			if _, err := m.buildMergedConfig(update, agentInfo, logger); err != nil {
				b.Fatal(err)
			}
		}
	})
}
