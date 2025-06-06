// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/mapstr"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pipeline"

	"github.com/elastic/elastic-agent/pkg/component"
)

func TestBeatNameToDefaultDatastreamType(t *testing.T) {
	tests := []struct {
		beatName      string
		expectedType  string
		expectedError error
	}{
		{
			beatName:     "filebeat",
			expectedType: "logs",
		},
		{
			beatName:     "metricbeat",
			expectedType: "metrics",
		},
		{
			beatName:      "cloudbeat",
			expectedError: fmt.Errorf("input type not supported by Otel: "),
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.beatName), func(t *testing.T) {
			comp := component.Component{
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "agentbeat",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{tt.beatName},
						},
					},
				},
			}
			actualType, actualError := getDefaultDatastreamTypeForComponent(&comp)
			assert.Equal(t, tt.expectedType, actualType)

			if tt.expectedError != nil {
				assert.Error(t, actualError)
				assert.EqualError(t, actualError, tt.expectedError.Error())
			} else {
				assert.NoError(t, actualError)
			}
		})
	}
}

func TestGetSignalForComponent(t *testing.T) {
	tests := []struct {
		name           string
		component      component.Component
		expectedSignal pipeline.Signal
		expectedError  error
	}{
		{
			name:          "no input spec",
			component:     component.Component{InputType: "test"},
			expectedError: fmt.Errorf("unknown otel signal for input type: %s", "test"),
		},
		{
			name: "not agentbeat",
			component: component.Component{
				InputType: "test",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "cloudbeat",
				},
			},
			expectedError: fmt.Errorf("unknown otel signal for input type: %s", "test"),
		},
		{
			name: "filebeat",
			component: component.Component{
				InputType: "filestream",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "agentbeat",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{"filebeat"},
						},
					},
				},
			},
			expectedSignal: pipeline.SignalLogs,
		},
		{
			name: "metricbeat",
			component: component.Component{
				InputType: "filestream",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "agentbeat",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{"metricbeat"},
						},
					},
				},
			},
			expectedSignal: pipeline.SignalLogs,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualSignal, actualError := getSignalForComponent(&tt.component)
			assert.Equal(t, tt.expectedSignal, actualSignal)

			if tt.expectedError != nil {
				assert.Error(t, actualError)
				assert.EqualError(t, actualError, tt.expectedError.Error())
			} else {
				assert.NoError(t, actualError)
			}
		})
	}
}

func TestGetOtelConfig(t *testing.T) {
	agentInfo := &info.AgentInfo{}
	fileStreamConfig := map[string]any{
		"id":         "test",
		"use_output": "default",
		"streams": []any{
			map[string]any{
				"id": "test-1",
				"data_stream": map[string]any{
					"dataset": "generic-1",
				},
				"paths": []any{
					"/var/log/*.log",
				},
			},
			map[string]any{
				"id": "test-2",
				"data_stream": map[string]any{
					"dataset": "generic-2",
				},
				"paths": []any{
					"/var/log/*.log",
				},
			},
		},
	}
	beatMetricsConfig := map[string]any{
		"id":         "test",
		"use_output": "default",
		"type":       "beat/metrics",
		"streams": []any{
			map[string]any{
				"id": "test-1",
				"data_stream": map[string]any{
					"dataset": "generic-1",
				},
				"hosts":      "http://localhost:5066",
				"metricsets": []interface{}{"stats"},
				"period":     "60s",
			},
		},
	}
	systemMetricsConfig := map[string]any{
		"id":         "test",
		"use_output": "default",
		"type":       "system/metrics",
		"streams": []any{
			map[string]any{
				"id": "test-1",
				"data_stream": map[string]any{
					"dataset": "generic-1",
				},
				"metricsets": map[string]any{
					"cpu": map[string]any{
						"data_stream.dataset": "system.cpu",
					},
					"memory": map[string]any{
						"data_stream.dataset": "system.memory",
					},
					"network": map[string]any{
						"data_stream.dataset": "system.network",
					},
					"filesystem": map[string]any{
						"data_stream.dataset": "system.filesystem",
					},
				},
			},
		},
	}
	esOutputConfig := map[string]any{
		"type":             "elasticsearch",
		"hosts":            []any{"localhost:9200"},
		"username":         "elastic",
		"password":         "password",
		"preset":           "balanced",
		"queue.mem.events": 3200,
	}

	expectedESConfig := map[string]any{
		"elasticsearch/_agent-component/default": map[string]any{
			"batcher": map[string]any{
				"enabled":  true,
				"max_size": 1600,
				"min_size": 0,
			},
			"logs_index": "",
			"mapping": map[string]any{
				"mode": "bodymap",
			},
			"endpoints": []string{"http://localhost:9200"},
			"password":  "password",
			"user":      "elastic",
			"retry": map[string]any{
				"enabled":          true,
				"initial_interval": 1 * time.Second,
				"max_interval":     1 * time.Minute,
				"max_retries":      3,
			},
			"logs_dynamic_index": map[string]any{
				"enabled": true,
			},
			"logs_dynamic_id": map[string]any{
				"enabled": true,
			},
			"timeout":           90 * time.Second,
			"idle_conn_timeout": 3 * time.Second,
		},
	}

	defaultProcessors := func(streamId, dataset string, namespace string) []any {
		return []any{
			mapstr.M{
				"add_fields": mapstr.M{
					"fields": mapstr.M{
						"input_id": "test",
					},
					"target": "@metadata",
				},
			},
			mapstr.M{
				"add_fields": mapstr.M{
					"fields": mapstr.M{
						"dataset":   dataset,
						"namespace": "default",
						"type":      namespace,
					},
					"target": "data_stream",
				},
			},
			mapstr.M{
				"add_fields": mapstr.M{
					"fields": mapstr.M{
						"dataset": dataset,
					},
					"target": "event",
				},
			},
			mapstr.M{
				"add_fields": mapstr.M{
					"fields": mapstr.M{
						"stream_id": streamId,
					},
					"target": "@metadata",
				},
			},
			mapstr.M{
				"add_fields": mapstr.M{
					"fields": mapstr.M{
						"id":       agentInfo.AgentID(),
						"snapshot": agentInfo.Snapshot(),
						"version":  agentInfo.Version(),
					},
					"target": "elastic_agent",
				},
			},
			mapstr.M{
				"add_fields": mapstr.M{
					"fields": mapstr.M{
						"id": agentInfo.AgentID(),
					},
					"target": "agent",
				},
			},
		}
	}

	getBeatMonitoringConfig := func(_, _ string) map[string]any {
		return map[string]any{
			"http": map[string]any{
				"enabled": true,
				"host":    "localhost",
			},
		}
	}

	tests := []struct {
		name           string
		model          *component.Model
		expectedConfig *confmap.Conf
		expectedError  error
	}{
		{
			name: "no supported components",
			model: &component.Model{
				Components: []component.Component{
					{
						InputType: "test",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "cloudbeat",
						},
					},
				},
			},
		},
		{
			name: "filestream",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "filestream-default",
						InputType:  "filestream",
						OutputType: "elasticsearch",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "agentbeat",
							Spec: component.InputSpec{
								Command: &component.CommandSpec{
									Args: []string{"filebeat"},
								},
							},
						},
						Units: []component.Unit{
							{
								ID:     "filestream-unit",
								Type:   client.UnitTypeInput,
								Config: component.MustExpectedConfig(fileStreamConfig),
							},
							{
								ID:     "filestream-default",
								Type:   client.UnitTypeOutput,
								Config: component.MustExpectedConfig(esOutputConfig),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": expectedESConfig,
				"receivers": map[string]any{
					"filebeatreceiver/_agent-component/filestream-default": map[string]any{
						"filebeat": map[string]any{
							"inputs": []map[string]any{
								{
									"id":   "test-1",
									"type": "filestream",
									"data_stream": map[string]any{
										"dataset": "generic-1",
									},
									"paths": []any{
										"/var/log/*.log",
									},
									"index":      "logs-generic-1-default",
									"processors": defaultProcessors("test-1", "generic-1", "logs"),
								},
								{
									"id":   "test-2",
									"type": "filestream",
									"data_stream": map[string]any{
										"dataset": "generic-2",
									},
									"paths": []any{
										"/var/log/*.log",
									},
									"index":      "logs-generic-2-default",
									"processors": defaultProcessors("test-2", "generic-2", "logs"),
								},
							},
						},
						"output": map[string]any{
							"otelconsumer": map[string]any{},
						},
						"path": map[string]any{
							"data": filepath.Join(paths.Run(), "filestream-default"),
						},
						"queue": map[string]any{
							"mem": map[string]any{
								"events": uint64(3200),
								"flush": map[string]any{
									"min_events": uint64(1600),
									"timeout":    "10s",
								},
							},
						},
						"logging": map[string]any{
							"with_fields": map[string]any{
								"component": map[string]any{
									"binary":  "filebeat",
									"dataset": "elastic_agent.filebeat",
									"type":    "filestream",
									"id":      "filestream-default",
								},
								"log": map[string]any{
									"source": "filestream-default",
								},
							},
						},
						"http": map[string]any{
							"enabled": true,
							"host":    "localhost",
						},
					},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"logs/_agent-component/filestream-default": map[string][]string{
							"exporters": []string{"elasticsearch/_agent-component/default"},
							"receivers": []string{"filebeatreceiver/_agent-component/filestream-default"},
						},
					},
				},
			}),
		},
		{
			name: "beat/metrics",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "beat-metrics-monitoring",
						InputType:  "beat/metrics",
						OutputType: "elasticsearch",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "agentbeat",
							Spec: component.InputSpec{
								Command: &component.CommandSpec{
									Args: []string{"metricbeat"},
								},
							},
						},
						Units: []component.Unit{
							{
								ID:     "beat/metrics-monitoring",
								Type:   client.UnitTypeInput,
								Config: component.MustExpectedConfig(beatMetricsConfig),
							},
							{
								ID:     "beat/metrics-default",
								Type:   client.UnitTypeOutput,
								Config: component.MustExpectedConfig(esOutputConfig),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": expectedESConfig,
				"receivers": map[string]any{
					"metricbeatreceiver/_agent-component/beat-metrics-monitoring": map[string]any{
						"metricbeat": map[string]any{
							"modules": []map[string]any{
								{
									"data_stream": map[string]any{"dataset": "generic-1"},
									"hosts":       "http://localhost:5066",
									"id":          "test-1",
									"index":       "metrics-generic-1-default",
									"metricsets":  []interface{}{"stats"},
									"period":      "60s",
									"processors":  defaultProcessors("test-1", "generic-1", "metrics"),
									"module":      "beat",
								},
							},
						},
						"output": map[string]any{
							"otelconsumer": map[string]any{},
						},
						"path": map[string]any{
							"data": filepath.Join(paths.Run(), "beat-metrics-monitoring"),
						},
						"queue": map[string]any{
							"mem": map[string]any{
								"events": uint64(3200),
								"flush": map[string]any{
									"min_events": uint64(1600),
									"timeout":    "10s",
								},
							},
						},
						"logging": map[string]any{
							"with_fields": map[string]any{
								"component": map[string]any{
									"binary":  "metricbeat",
									"dataset": "elastic_agent.metricbeat",
									"type":    "beat/metrics",
									"id":      "beat-metrics-monitoring",
								},
								"log": map[string]any{
									"source": "beat-metrics-monitoring",
								},
							},
						},
						"http": map[string]any{
							"enabled": true,
							"host":    "localhost",
						},
					},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"logs/_agent-component/beat-metrics-monitoring": map[string][]string{
							"exporters": []string{"elasticsearch/_agent-component/default"},
							"receivers": []string{"metricbeatreceiver/_agent-component/beat-metrics-monitoring"},
						},
					},
				},
			}),
		},
		{
			name: "system/metrics",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "system-metrics",
						InputType:  "system/metrics",
						OutputType: "elasticsearch",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "agentbeat",
							Spec: component.InputSpec{
								Command: &component.CommandSpec{
									Args: []string{"metricbeat"},
								},
							},
						},
						Units: []component.Unit{
							{
								ID:     "system/metrics",
								Type:   client.UnitTypeInput,
								Config: component.MustExpectedConfig(systemMetricsConfig),
							},
							{
								ID:     "system/metrics-default",
								Type:   client.UnitTypeOutput,
								Config: component.MustExpectedConfig(esOutputConfig),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": expectedESConfig,
				"receivers": map[string]any{
					"metricbeatreceiver/_agent-component/system-metrics": map[string]any{
						"metricbeat": map[string]any{
							"modules": []map[string]any{
								{
									"module":      "system",
									"data_stream": map[string]any{"dataset": "generic-1"},
									"id":          "test-1",
									"index":       "metrics-generic-1-default",
									"metricsets": map[string]any{
										"cpu": map[string]any{
											"data_stream.dataset": "system.cpu",
										},
										"memory": map[string]any{
											"data_stream.dataset": "system.memory",
										},
										"network": map[string]any{
											"data_stream.dataset": "system.network",
										},
										"filesystem": map[string]any{
											"data_stream.dataset": "system.filesystem",
										},
									},
									"processors": defaultProcessors("test-1", "generic-1", "metrics"),
								},
							},
						},
						"output": map[string]any{
							"otelconsumer": map[string]any{},
						},
						"path": map[string]any{
							"data": filepath.Join(paths.Run(), "system-metrics"),
						},
						"queue": map[string]any{
							"mem": map[string]any{
								"events": uint64(3200),
								"flush": map[string]any{
									"min_events": uint64(1600),
									"timeout":    "10s",
								},
							},
						},
						"logging": map[string]any{
							"with_fields": map[string]any{
								"component": map[string]any{
									"binary":  "metricbeat",
									"dataset": "elastic_agent.metricbeat",
									"type":    "system/metrics",
									"id":      "system-metrics",
								},
								"log": map[string]any{
									"source": "system-metrics",
								},
							},
						},
						"http": map[string]any{
							"enabled": true,
							"host":    "localhost",
						},
					},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"logs/_agent-component/system-metrics": map[string][]string{
							"exporters": []string{"elasticsearch/_agent-component/default"},
							"receivers": []string{"metricbeatreceiver/_agent-component/system-metrics"},
						},
					},
				},
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualConf, actualError := GetOtelConfig(tt.model, agentInfo, getBeatMonitoringConfig)
			if actualConf == nil || tt.expectedConfig == nil {
				assert.Equal(t, tt.expectedConfig, actualConf)
			} else { // this gives a nicer diff
				assert.Equal(t, tt.expectedConfig.ToStringMap(), actualConf.ToStringMap())
			}

			if actualConf != nil {
				t.Logf("%v", actualConf.ToStringMap())
			}
			if tt.expectedError != nil {
				assert.Error(t, actualError)
				assert.EqualError(t, actualError, tt.expectedError.Error())
			} else {
				assert.NoError(t, actualError)
			}
		})
	}
}

// TODO: Add unit tests for other config generation functions
