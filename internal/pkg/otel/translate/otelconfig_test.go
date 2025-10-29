// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
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

	type extraParams struct {
		key   string
		value any
	}
	// pass ssl params as extra args to this method
	esOutputConfig := func(extra ...extraParams) map[string]any {
		finalOutput := map[string]any{
			"type":             "elasticsearch",
			"hosts":            []any{"localhost:9200"},
			"username":         "elastic",
			"password":         "password",
			"preset":           "balanced",
			"queue.mem.events": 3200,
			"ssl.enabled":      true,
			"proxy_url":        "https://example.com",
		}

		for _, v := range extra {
			finalOutput[v.key] = v.value
		}
		return finalOutput
	}

	expectedExtensionConfig := func(extra ...extraParams) map[string]any {
		finalOutput := map[string]any{
			"continue_on_error":       true,
			"idle_connection_timeout": "3s",
			"proxy_disable":           false,
			"proxy_url":               "https://example.com",
			"ssl": map[string]interface{}{
				"ca_sha256":               []interface{}{},
				"ca_trusted_fingerprint":  "",
				"certificate":             "",
				"certificate_authorities": []interface{}{},
				"cipher_suites":           []interface{}{},
				"curve_types":             []interface{}{},
				"enabled":                 true,
				"key":                     "",
				"key_passphrase":          "",
				"key_passphrase_path":     "",
				"renegotiation":           int64(0),
				"supported_protocols":     []interface{}{},
				"verification_mode":       uint64(0),
			},
			"timeout": "1m30s",
		}
		for _, v := range extra {
			// accepts one level deep parameters to replace
			if _, ok := v.value.(map[string]any); ok {
				for newkey, newvalue := range v.value.(map[string]any) {
					// this is brittle - it is expected that developers will pass expected params correctly here
					finalOutput[v.key].(map[string]any)[newkey] = newvalue
				}
				continue
			}
			finalOutput[v.key] = v.value
		}
		return finalOutput
	}

	expectedESConfig := func(outputName string) map[string]any {
		return map[string]any{
			"compression": "gzip",
			"compression_params": map[string]any{
				"level": 1,
			},
			"mapping": map[string]any{
				"mode": "bodymap",
			},
			"endpoints":          []string{"http://localhost:9200"},
			"password":           "password",
			"user":               "elastic",
			"max_conns_per_host": 1,
			"retry": map[string]any{
				"enabled":          true,
				"initial_interval": 1 * time.Second,
				"max_interval":     1 * time.Minute,
				"max_retries":      3,
			},
			"sending_queue": map[string]any{
				"enabled":           true,
				"num_consumers":     1,
				"queue_size":        3200,
				"block_on_overflow": true,
				"wait_for_result":   true,
				"batch": map[string]any{
					"flush_timeout": "10s",
					"max_size":      1600,
					"min_size":      0,
					"sizer":         "items",
				},
			},
			"logs_dynamic_id": map[string]any{
				"enabled": true,
			},
			"telemetry": map[string]any{
				"log_failed_docs_input": true,
			},
			"auth": map[string]any{
				"authenticator": "beatsauth/_agent-component/" + outputName,
			},
		}
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

	// expects input id
	expectedFilestreamConfig := func(id string) map[string]any {
		return map[string]any{
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
				"data": filepath.Join(paths.Run(), id),
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
						"id":      id,
					},
					"log": map[string]any{
						"source": id,
					},
				},
			},
			"http": map[string]any{
				"enabled": true,
				"host":    "localhost",
			},
			"management.otel.enabled": true,
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
								Config: component.MustExpectedConfig(esOutputConfig()),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": map[string]any{
					"elasticsearch/_agent-component/default": expectedESConfig("default"),
				},
				"extensions": map[string]any{
					"beatsauth/_agent-component/default": expectedExtensionConfig(),
				},
				"receivers": map[string]any{
					"filebeatreceiver/_agent-component/filestream-default": expectedFilestreamConfig("filestream-default"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/filestream-default": map[string][]string{
							"exporters": {"elasticsearch/_agent-component/default"},
							"receivers": {"filebeatreceiver/_agent-component/filestream-default"},
						},
					},
				},
			}),
		},
		{
			name: "multiple filestream inputs and output types",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "filestream-primaryOutput",
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
								ID:     "filestream-primaryOutput",
								Type:   client.UnitTypeOutput,
								Config: component.MustExpectedConfig(esOutputConfig(extraParams{"ssl.verification_mode", "certificate"})),
							},
						},
					},
					{
						ID:         "filestream-secondaryOutput",
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
								ID:     "filestream-unit-2",
								Type:   client.UnitTypeInput,
								Config: component.MustExpectedConfig(fileStreamConfig),
							},
							{
								ID:     "filestream-secondaryOutput",
								Type:   client.UnitTypeOutput,
								Config: component.MustExpectedConfig(esOutputConfig(extraParams{"ssl.ca_trusted_fingerprint", "b9a10bbe64ee9826abeda6546fc988c8bf798b41957c33d05db736716513dc9c"})),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": map[string]any{
					"elasticsearch/_agent-component/primaryOutput":   expectedESConfig("primaryOutput"),
					"elasticsearch/_agent-component/secondaryOutput": expectedESConfig("secondaryOutput"),
				},
				"extensions": map[string]any{
					"beatsauth/_agent-component/primaryOutput":   expectedExtensionConfig(extraParams{"ssl", map[string]any{"verification_mode": uint64(2)}}),
					"beatsauth/_agent-component/secondaryOutput": expectedExtensionConfig(extraParams{"ssl", map[string]any{"ca_trusted_fingerprint": "b9a10bbe64ee9826abeda6546fc988c8bf798b41957c33d05db736716513dc9c"}}),
				},
				"receivers": map[string]any{
					"filebeatreceiver/_agent-component/filestream-primaryOutput":   expectedFilestreamConfig("filestream-primaryOutput"),
					"filebeatreceiver/_agent-component/filestream-secondaryOutput": expectedFilestreamConfig("filestream-secondaryOutput"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/primaryOutput", "beatsauth/_agent-component/secondaryOutput"},
					"pipelines": map[string]any{
						"logs/_agent-component/filestream-primaryOutput": map[string][]string{
							"exporters": {"elasticsearch/_agent-component/primaryOutput"},
							"receivers": {"filebeatreceiver/_agent-component/filestream-primaryOutput"},
						},
						"logs/_agent-component/filestream-secondaryOutput": map[string][]string{
							"exporters": {"elasticsearch/_agent-component/secondaryOutput"},
							"receivers": {"filebeatreceiver/_agent-component/filestream-secondaryOutput"},
						},
					},
				},
			}),
		},
		{
			name: "multiple filestream inputs and one output",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "filestream1-default",
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
								Config: component.MustExpectedConfig(esOutputConfig()),
							},
						},
					},
					{
						ID:         "filestream2-default",
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
								Config: component.MustExpectedConfig(esOutputConfig()),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": map[string]any{
					"elasticsearch/_agent-component/default": expectedESConfig("default"),
				},
				"extensions": map[string]any{
					"beatsauth/_agent-component/default": expectedExtensionConfig(),
				},
				"receivers": map[string]any{
					"filebeatreceiver/_agent-component/filestream1-default": expectedFilestreamConfig("filestream1-default"),
					"filebeatreceiver/_agent-component/filestream2-default": expectedFilestreamConfig("filestream2-default"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/filestream1-default": map[string][]string{
							"exporters": {"elasticsearch/_agent-component/default"},
							"receivers": {"filebeatreceiver/_agent-component/filestream1-default"},
						},
						"logs/_agent-component/filestream2-default": map[string][]string{
							"exporters": {"elasticsearch/_agent-component/default"},
							"receivers": {"filebeatreceiver/_agent-component/filestream2-default"},
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
								Config: component.MustExpectedConfig(esOutputConfig()),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": map[string]any{
					"elasticsearch/_agent-component/default": expectedESConfig("default"),
				},
				"extensions": map[string]any{
					"beatsauth/_agent-component/default": expectedExtensionConfig(),
				},
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
						"management.otel.enabled": true,
					},
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/beat-metrics-monitoring": map[string][]string{
							"exporters": {"elasticsearch/_agent-component/default"},
							"receivers": {"metricbeatreceiver/_agent-component/beat-metrics-monitoring"},
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
								Config: component.MustExpectedConfig(esOutputConfig()),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": map[string]any{
					"elasticsearch/_agent-component/default": expectedESConfig("default"),
				},
				"extensions": map[string]any{
					"beatsauth/_agent-component/default": expectedExtensionConfig(),
				},
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
						"management.otel.enabled": true,
					},
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/system-metrics": map[string][]string{
							"exporters": {"elasticsearch/_agent-component/default"},
							"receivers": {"metricbeatreceiver/_agent-component/system-metrics"},
						},
					},
				},
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualConf, actualError := GetOtelConfig(tt.model, agentInfo, getBeatMonitoringConfig, logp.NewNopLogger())
			if actualConf == nil || tt.expectedConfig == nil {
				assert.Equal(t, tt.expectedConfig, actualConf)
			} else { // this gives a nicer diff
				assert.Equal(t, tt.expectedConfig.ToStringMap(), actualConf.ToStringMap())
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

func TestGetReceiversConfigForComponent(t *testing.T) {
	testAgentInfo := &info.AgentInfo{}
	mockBeatMonitoringConfigGetter := func(componentID, beatName string) map[string]any {
		return nil // Behavior when self-monitoring is disabled
	}

	customBeatMonitoringConfigGetter := func(componentID, beatName string) map[string]any {
		return map[string]any{
			"http": map[string]any{
				"enabled": true,
				"host":    "custom-host:5067",
				"port":    5067,
			},
		}
	}

	// Create proper component configurations that match existing test patterns
	filebeatComponent := &component.Component{
		ID:        "filebeat-test-id",
		InputType: "filestream",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "agentbeat",
			Spec: component.InputSpec{
				Name: "filestream",
				Command: &component.CommandSpec{
					Args: []string{"filebeat"},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "filebeat-test-id-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
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
					},
				}),
			},
		},
	}

	metricbeatComponent := &component.Component{
		ID:        "metricbeat-test-id",
		InputType: "system/metrics",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "agentbeat",
			Spec: component.InputSpec{
				Name: "system/metrics",
				Command: &component.CommandSpec{
					Args: []string{"metricbeat"},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "metricbeat-test-id-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
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
							},
						},
					},
				}),
			},
		},
	}

	tests := []struct {
		name                       string
		component                  *component.Component
		outputQueueConfig          map[string]any
		beatMonitoringConfigGetter BeatMonitoringConfigGetter
		expectedError              string
		expectedReceiverType       string
		expectedBeatName           string
	}{
		{
			name:                       "filebeat component with default monitoring",
			component:                  filebeatComponent,
			outputQueueConfig:          nil,
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
			expectedReceiverType:       "filebeatreceiver",
			expectedBeatName:           "filebeat",
		},
		{
			name:      "metricbeat component with custom monitoring and queue config",
			component: metricbeatComponent,
			outputQueueConfig: map[string]any{
				"type": "memory",
				"size": 1000,
			},
			beatMonitoringConfigGetter: customBeatMonitoringConfigGetter,
			expectedReceiverType:       "metricbeatreceiver",
			expectedBeatName:           "metricbeat",
		},
		{
			name: "component with no input units",
			component: &component.Component{
				ID:        "no-inputs-test-id",
				InputType: "filestream",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "agentbeat",
					Spec: component.InputSpec{
						Name: "filestream",
						Command: &component.CommandSpec{
							Args: []string{"filebeat"},
						},
					},
				},
				Units: []component.Unit{
					{
						ID:   "output-unit",
						Type: client.UnitTypeOutput,
						Config: component.MustExpectedConfig(map[string]any{
							"type": "elasticsearch",
						}),
					},
				},
			},
			outputQueueConfig:          nil,
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
			expectedReceiverType:       "filebeatreceiver",
			expectedBeatName:           "filebeat",
		},
		{
			name: "unsupported component type",
			component: &component.Component{
				ID:        "unsupported-test-id",
				InputType: "unsupported",
			},
			outputQueueConfig:          nil,
			beatMonitoringConfigGetter: mockBeatMonitoringConfigGetter,
			expectedError:              "unknown otel receiver type for input type: unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getReceiversConfigForComponent(
				tt.component,
				testAgentInfo,
				tt.outputQueueConfig,
				tt.beatMonitoringConfigGetter,
			)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.expectedError)
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)

			// Verify the receiver ID is present
			receiverID := fmt.Sprintf("%s/_agent-component/%s", tt.expectedReceiverType, tt.component.ID)
			assert.Contains(t, result, receiverID)

			receiverConfig, ok := result[receiverID].(map[string]any)
			assert.True(t, ok, "receiver config should be a map")

			// Verify configuration section presence
			assert.Contains(t, receiverConfig, "output", "output config should be present")
			assert.Contains(t, receiverConfig, "path", "path config should be present")
			assert.Contains(t, receiverConfig, "logging", "logging config should be present")
			assert.Contains(t, receiverConfig, tt.expectedBeatName, fmt.Sprintf("%s config should be present", tt.expectedBeatName))

			// Verify queue configuration presence
			if tt.outputQueueConfig != nil {
				assert.Contains(t, receiverConfig, "queue", "queue config should be present")
			} else {
				assert.NotContains(t, receiverConfig, "queue", "queue config should not be present")
			}

			// Verify monitoring configuration is present (http section should exist)
			assert.Contains(t, receiverConfig, "http", "http monitoring config should be present")
			expectedMonitoringConfig := tt.beatMonitoringConfigGetter(tt.component.ID, tt.component.InputSpec.BinaryName)
			// If the monitoring getter is not nil, verify the http section is the same
			if expectedMonitoringConfig != nil {
				assert.Equal(t, expectedMonitoringConfig["http"], receiverConfig["http"])
			}
		})
	}
}

func TestVerifyComponentIsOtelSupported(t *testing.T) {
	tests := []struct {
		name          string
		component     *component.Component
		expectedError string
	}{
		{
			name: "supported component",
			component: &component.Component{
				ID:         "supported-comp",
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
						ID:   "filestream-unit",
						Type: client.UnitTypeInput,
						Config: component.MustExpectedConfig(map[string]any{
							"streams": []any{
								map[string]any{
									"paths": []any{"/var/log/*.log"},
								},
							},
						}),
					},
					{
						ID:   "filestream-default",
						Type: client.UnitTypeOutput,
						Config: component.MustExpectedConfig(map[string]any{
							"type":  "elasticsearch",
							"hosts": []any{"localhost:9200"},
						}),
					},
				},
			},
		},
		{
			name: "unsupported output type - kafka",
			component: &component.Component{
				ID:         "unsupported-output",
				InputType:  "filestream",
				OutputType: "kafka", // unsupported
			},
			expectedError: "unsupported output type: kafka",
		},
		{
			name: "unsupported output type - logstash",
			component: &component.Component{
				ID:         "unsupported-output",
				InputType:  "filestream",
				OutputType: "logstash", // unsupported
			},
			expectedError: "unsupported output type: logstash",
		},
		{
			name: "unsupported input type",
			component: &component.Component{
				ID:         "unsupported-input",
				InputType:  "stdin", // unsupported
				OutputType: "elasticsearch",
			},
			expectedError: "unsupported input type: stdin",
		},
		{
			name: "unsupported configuration",
			component: &component.Component{
				ID:         "unsupported-config",
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
						ID:   "filestream-unit",
						Type: client.UnitTypeInput,
						Config: component.MustExpectedConfig(map[string]any{
							"streams": []any{
								map[string]any{
									"paths": []any{"/var/log/*.log"},
								},
							},
						}),
					},
					{
						ID:   "filestream-default",
						Type: client.UnitTypeOutput,
						Config: component.MustExpectedConfig(map[string]any{
							"type":    "elasticsearch",
							"hosts":   []any{"localhost:9200"},
							"indices": []any{},
						}),
					},
				},
			},
			expectedError: "unsupported configuration for unsupported-config: error translating config for output: default, unit: filestream-default, error: indices is currently not supported: unsupported operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyComponentIsOtelSupported(tt.component)
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
