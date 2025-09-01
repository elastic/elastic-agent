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

	otelcomponent "go.opentelemetry.io/collector/component"
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
	esOutputConfig := map[string]any{
		"type":             "elasticsearch",
		"hosts":            []any{"localhost:9200"},
		"username":         "elastic",
		"password":         "password",
		"preset":           "balanced",
		"queue.mem.events": 3200,
		"ssl.enabled":      true,
	}

	expectedExtensionConfig := map[string]any{
		"beatsauth/_agent-component/default": map[string]any{
			"idle_connection_timeout": "3s",
			"proxy_disable":           false,
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
				"verification_mode":       int64(0),
			},
			"timeout": "1m30s",
		},
	}

	expectedESConfig := map[string]any{
		"elasticsearch/_agent-component/default": map[string]any{
			"batcher": map[string]any{
				"enabled":  true,
				"max_size": 1600,
				"min_size": 0,
			},
			"compression": "gzip",
			"compression_params": map[string]any{
				"level": 1,
			},
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
			"logs_dynamic_id": map[string]any{
				"enabled": true,
			},
			"timeout":           90 * time.Second,
			"idle_conn_timeout": 3 * time.Second,
			"auth": map[string]any{
				"authenticator": "beatsauth/_agent-component/default",
			},
			"tls": map[string]any{
				"min_version": "1.2",
				"max_version": "1.3",
			},
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
				"exporters":  expectedESConfig,
				"extensions": expectedExtensionConfig,
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
					"extensions": []interface{}{"beatsauth/_agent-component/default"},
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
				"exporters":  expectedESConfig,
				"extensions": expectedExtensionConfig,
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
					"extensions": []interface{}{"beatsauth/_agent-component/default"},
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
				"exporters":  expectedESConfig,
				"extensions": expectedExtensionConfig,
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
					"extensions": []interface{}{"beatsauth/_agent-component/default"},
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

func TestBeatsAuthExtension(t *testing.T) {
	esInputConfig := map[string]any{
		"type":     "elasticsearch",
		"hosts":    []any{"localhost:9200"},
		"username": "elastic",
		"password": "password",
		"preset":   "balanced",
	}

	extensionConfig := map[string]any{
		"beatsauth/_agent-component/default": map[string]any{},
	}

	esOutputConfig := map[string]any{
		"elasticsearch/_agent-component/default": map[string]any{
			"batcher": map[string]any{
				"enabled":  true,
				"max_size": 1600,
				"min_size": 0,
			},
			"compression": "gzip",
			"compression_params": map[string]any{
				"level": 1,
			},
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
			"logs_dynamic_id": map[string]any{
				"enabled": true,
			},
			"timeout":           90 * time.Second,
			"idle_conn_timeout": 3 * time.Second,
			"auth": map[string]any{
				"authenticator": "beatsauth/_agent-component/default",
			},
		},
	}

	testCases := []struct {
		name                    string
		inputSSLConfig          map[string]any
		expectedES_TLSConfig    map[string]any
		expectedBeatsAuthConfig map[string]any
	}{
		{
			name: "when ssl.enabled is true",
			inputSSLConfig: map[string]any{
				"enabled": true,
			},
			expectedES_TLSConfig: map[string]any{
				"min_version": "1.2",
				"max_version": "1.3",
			},
			expectedBeatsAuthConfig: map[string]any{
				"verification_mode": "full",
			},
		},
		{
			name: "when ca_trusted_fingerprint is set",
			inputSSLConfig: map[string]any{
				"verification_mode":      "full",
				"ca_trusted_fingerprint": "a3:5f:bf:93:12:8f:bc:5c:ab:14:6d:bf:e4:2a:7f:98:9d:2f:16:92:76:c4:12:ab:67:89:fc:56:4b:8e:0c:43",
			},
			expectedES_TLSConfig: map[string]any{
				"min_version": "1.2",
				"max_version": "1.3",
			},
			expectedBeatsAuthConfig: map[string]any{
				"verification_mode":      "full",
				"ca_trusted_fingerprint": "a3:5f:bf:93:12:8f:bc:5c:ab:14:6d:bf:e4:2a:7f:98:9d:2f:16:92:76:c4:12:ab:67:89:fc:56:4b:8e:0c:43",
			},
		},
		{
			name: "when verification_mode is none",
			inputSSLConfig: map[string]any{
				"verification_mode": "none",
			},
			expectedES_TLSConfig: map[string]any{
				"insecure_skip_verify": true,
				"min_version":          "1.2",
				"max_version":          "1.3",
			},
			expectedBeatsAuthConfig: map[string]any{
				"verification_mode": "none",
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			tempMap := esInputConfig
			tempMap["ssl"] = test.inputSSLConfig

			units := []component.Unit{
				{
					ID:     "beat/metrics-default",
					Type:   client.UnitTypeOutput,
					Config: component.MustExpectedConfig(tempMap),
				},
			}

			gotES, _, gotBeatsAuth, err := unitToExporterConfig(units[0], otelcomponent.MustNewType("elasticsearch"), "beat/metrics", logp.NewNopLogger())
			if err != nil {
				t.Fatal(err)
			}

			// add expected TLS config
			expectedES := esOutputConfig
			expectedES["elasticsearch/_agent-component/default"].(map[string]any)["tls"] = test.expectedES_TLSConfig
			require.Equal(t, expectedES, gotES)

			// check beats auth config
			expectedBeatsAuth := extensionConfig
			expectedBeatsAuth["beatsauth/_agent-component/default"].(map[string]any)["tls"] = test.expectedBeatsAuthConfig
			require.Equal(t, expectedBeatsAuth, gotBeatsAuth)

		})
	}
}

// TODO: Add unit tests for other config generation functions
