// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	otelcomponent "go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	internalConfig "github.com/elastic/elastic-agent/internal/pkg/config"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/util"

	"github.com/stretchr/testify/assert"
	"go.opentelemetry.io/collector/pipeline"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/features"
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
		{
			beatName:     "auditbeat",
			expectedType: "logs",
		},
		{
			beatName:     "heartbeat",
			expectedType: "logs",
		},
		{
			beatName:     "osquerybeat",
			expectedType: "logs",
		},
		{
			beatName:     "packetbeat",
			expectedType: "logs",
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.beatName), func(t *testing.T) {
			comp := component.Component{
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "elastic-otel-collector",
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
			name: "not elastic-otel-collector",
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
					BinaryName: "elastic-otel-collector",
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
					BinaryName: "elastic-otel-collector",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{"metricbeat"},
						},
					},
				},
			},
			expectedSignal: pipeline.SignalLogs,
		},
		{
			name: "auditbeat",
			component: component.Component{
				InputType: "audit/auditd",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "elastic-otel-collector",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{"auditbeat"},
						},
					},
				},
			},
			expectedSignal: pipeline.SignalLogs,
		},
		{
			name: "heartbeat",
			component: component.Component{
				InputType: "synthetics/http",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "elastic-otel-collector",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{"heartbeat"},
						},
					},
				},
			},
			expectedSignal: pipeline.SignalLogs,
		},
		{
			name: "osquerybeat",
			component: component.Component{
				InputType: "osquery",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "elastic-otel-collector",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{"osquerybeat"},
						},
					},
				},
			},
			expectedSignal: pipeline.SignalLogs,
		},
		{
			name: "packetbeat",
			component: component.Component{
				InputType: "packet",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "elastic-otel-collector",
					Spec: component.InputSpec{
						Command: &component.CommandSpec{
							Args: []string{"packetbeat"},
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
	auditbeatInputConfig := map[string]any{
		"id":         "test",
		"use_output": "default",
		"type":       "audit/auditd",
		"streams": []any{
			map[string]any{
				"id": "test-1",
				"data_stream": map[string]any{
					"dataset": "generic-1",
				},
				"audit_rules": "-a exit,always -F arch=b64 -S open",
			},
		},
	}

	heartbeatInputConfig := map[string]any{
		"id":         "test",
		"use_output": "default",
		"type":       "synthetics/http",
		"streams": []any{
			map[string]any{
				"id": "test-1",
				"data_stream": map[string]any{
					"dataset": "generic-1",
				},
				"urls":     []any{"https://example.com"},
				"schedule": "@every 5s",
			},
		},
	}

	osquerybeatInputConfig := map[string]any{
		"id":         "test",
		"use_output": "default",
		"type":       "osquery",
		"streams": []any{
			map[string]any{
				"id": "test-1",
				"data_stream": map[string]any{
					"dataset": "generic-1",
				},
				"query":    "SELECT * FROM processes",
				"interval": "3600",
			},
		},
	}

	// osquerybeat with two streams (action responses + results), as deployed by osquery_manager.
	osquerybeatMultiStreamInputConfig := map[string]any{
		"id":         "test",
		"use_output": "default",
		"type":       "osquery",
		"streams": []any{
			map[string]any{
				"id": "action-responses",
				"data_stream": map[string]any{
					"dataset": "osquery_manager.action.responses",
				},
				"query": nil,
			},
			map[string]any{
				"id": "results",
				"data_stream": map[string]any{
					"dataset": "osquery_manager.result",
				},
				"query":    "SELECT * FROM processes",
				"interval": "3600",
			},
		},
	}

	packetbeatInputConfig := map[string]any{
		"id":         "test",
		"use_output": "default",
		"type":       "packet",
		"streams": []any{
			map[string]any{
				"id": "test-1",
				"data_stream": map[string]any{
					"dataset": "generic-1",
				},
				"ports": []any{443, 8443},
			},
		},
	}

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
				"ca_sha256":                  []interface{}{},
				"ca_trusted_fingerprint":     "",
				"certificate":                "",
				"certificate_authorities":    []interface{}{},
				"certificate_reload":         map[string]interface{}{"enabled": nil, "reload_interval": "0s"},
				"cipher_suites":              []interface{}{},
				"disable_legacy_pem_support": false,
				"curve_types":                []interface{}{},
				"enabled":                    true,
				"key":                        "",
				"key_passphrase":             "",
				"key_passphrase_path":        "",
				"renegotiation":              int64(0),
				"supported_protocols":        []interface{}{},
				"verification_mode":          uint64(0),
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
			"bulk_response_filter_path": "errors,items.*.error,items.*.status,items.*.failure_store",
			"compression":               "gzip",
			"compression_params": map[string]any{
				"level": 1,
			},
			"endpoints":          []string{"http://localhost:9200"},
			"password":           "password",
			"user":               "elastic",
			"max_conns_per_host": 1,
			"retry": map[string]any{
				"enabled":                  true,
				"initial_interval":         1 * time.Second,
				"max_interval":             1 * time.Minute,
				"max_retries":              3,
				"retry_on_status":          defaultRetryOnStatus(),
				"retry_on_document_status": []int{429, 500, 501, 502, 503, 504, 505, 506, 507, 508, 510, 511},
			},
			"sending_queue": map[string]any{
				"enabled":           true,
				"num_consumers":     2,
				"queue_size":        6400,
				"block_on_overflow": true,
				"wait_for_result":   true,
				"batch": map[string]any{
					"flush_timeout": "10s",
					"max_size":      1600,
					"min_size":      1600,
					"sizer":         "items",
				},
			},
			"logs_dynamic_id": map[string]any{
				"enabled": true,
			},
			"logs_dynamic_pipeline": map[string]any{
				"enabled": true,
			},
			"include_source_on_error": true,
			"auth": map[string]any{
				"authenticator": "beatsauth/_agent-component/" + outputName,
			},
			"suppress_conflict_errors": true,
			"timeout":                  90 * time.Second,
		}
	}

	defaultInputProcessors := func(streamId, dataset string, namespace string) []any {
		return []any{
			mapstr.M{
				"add_agent_metadata": mapstr.M{
					"data_stream": mapstr.M{
						"dataset":   dataset,
						"namespace": "default",
						"type":      namespace,
					},
					"elastic_agent": mapstr.M{
						"id":       agentInfo.AgentID(),
						"snapshot": agentInfo.Snapshot(),
						"version":  agentInfo.Version(),
					},
					"input_id":  "test",
					"stream_id": streamId,
				},
			},
		}
	}

	// beatProcessorID returns the id of the default beat processor for the
	// component with the given id, matching translate.GetProcessorID.
	beatProcessorID := func(id string) string {
		return "beat/_agent-component/" + id
	}
	// defaultExpectedProcessors builds the expected top-level "processors" map
	// for the components with the given ids, each getting the beat-specific default
	// processor definition matching what GetDefaultProcessors returns for that beat.
	defaultExpectedProcessors := func(beatName string, ids ...string) map[string]any {
		m := map[string]any{}
		for _, id := range ids {
			m[beatProcessorID(id)] = map[string]any{
				"processors": GetDefaultProcessors(beatName),
			}
		}
		return m
	}

	// expected receiver config shared shape for ES-output beats with a single stream.
	// queue uses uint64 because the "balanced" ES preset produces typed uint64 values.
	beatReceiverBaseConfig := func(id, binaryName, inputType string) map[string]any {
		dataset := fmt.Sprintf("elastic_agent.%s", binaryName)
		return map[string]any{
			"path": map[string]any{
				"home": paths.Components(),
				"data": filepath.Join(paths.Run(), id),
			},
			"queue": map[string]any{
				"mem": map[string]any{
					"events": int64(6400),
					"flush": map[string]any{
						"min_events": uint64(1600),
						"timeout":    "10s",
					},
				},
			},
			"logging": map[string]any{
				"with_fields": map[string]any{
					"component": map[string]any{
						"binary":  binaryName,
						"dataset": dataset,
						"type":    inputType,
						"id":      id,
					},
					"log": map[string]any{
						"source": id,
					},
				},
			},
			"http": map[string]any{
				"enabled": false,
			},
			"management.otel.enabled": true,
		}
	}

	// expects component id
	expectedAuditbeatReceiverConfig := func(id string) map[string]any {
		cfg := beatReceiverBaseConfig(id, "auditbeat", "audit/auditd")
		cfg["auditbeat"] = map[string]any{
			"modules": []map[string]any{
				{
					"id": "test-1",
					"data_stream": map[string]any{
						"dataset": "generic-1",
					},
					"audit_rules": "-a exit,always -F arch=b64 -S open",
					"index":       "logs-generic-1-default",
					"module":      "auditd",
					"processors":  defaultInputProcessors("test-1", "generic-1", "logs"),
				},
			},
		}
		return cfg
	}

	// expects component id
	expectedHeartbeatReceiverConfig := func(id string) map[string]any {
		cfg := beatReceiverBaseConfig(id, "heartbeat", "synthetics/http")
		cfg["heartbeat"] = map[string]any{
			"monitors": []map[string]any{
				{
					"id": "test-1",
					"data_stream": map[string]any{
						"dataset": "generic-1",
					},
					"urls":       []any{"https://example.com"},
					"schedule":   "@every 5s",
					"index":      "logs-generic-1-default",
					"processors": defaultInputProcessors("test-1", "generic-1", "logs"),
					"type":       "http",
				},
			},
		}
		return cfg
	}

	// expects component id
	expectedOsquerybeatReceiverConfig := func(id string) map[string]any {
		cfg := beatReceiverBaseConfig(id, "osquerybeat", "osquery")
		cfg["osquerybeat"] = map[string]any{
			"inputs": []map[string]any{
				{
					"id": "test-1",
					"data_stream": map[string]any{
						"dataset": "generic-1",
					},
					"query":      "SELECT * FROM processes",
					"interval":   "3600",
					"index":      "logs-generic-1-default",
					"processors": defaultInputProcessors("test-1", "generic-1", "logs"),
					"type":       "osquery",
				},
			},
		}
		return cfg
	}

	// expectedOsquerybeatSingleReceiverConfig is the expected config for an osquery component
	// with single_receiver: true and two streams merged into one receiver.
	// The osquery_manager.result stream must be first (index 0) so that
	// osquerybeat assigns its client to it.
	expectedOsquerybeatSingleReceiverConfig := func(id string) map[string]any {
		cfg := beatReceiverBaseConfig(id, "osquerybeat", "osquery")
		cfg["osquerybeat"] = map[string]any{
			"inputs": []map[string]any{
				{
					"id": "results",
					"data_stream": map[string]any{
						"dataset":   "osquery_manager.result",
						"namespace": "default",
					},
					"query":      "SELECT * FROM processes",
					"interval":   "3600",
					"index":      "logs-osquery_manager.result-default",
					"processors": defaultInputProcessors("results", "osquery_manager.result", "logs"),
					"type":       "osquery",
				},
				{
					"id": "action-responses",
					"data_stream": map[string]any{
						"dataset":   "osquery_manager.action.responses",
						"namespace": "default",
					},
					"query":      nil,
					"index":      "logs-osquery_manager.action.responses-default",
					"processors": defaultInputProcessors("action-responses", "osquery_manager.action.responses", "logs"),
					"type":       "osquery",
				},
			},
		}
		return cfg
	}

	// expects component id
	expectedPacketbeatReceiverConfig := func(id string) map[string]any {
		cfg := beatReceiverBaseConfig(id, "packetbeat", "packet")
		cfg["packetbeat"] = map[string]any{
			"protocols": []map[string]any{
				{
					"id": "test-1",
					"data_stream": map[string]any{
						"dataset": "generic-1",
					},
					"ports":      []any{float64(443), float64(8443)},
					"index":      "logs-generic-1-default",
					"processors": defaultInputProcessors("test-1", "generic-1", "logs"),
					"type":       "packet",
				},
			},
		}
		return cfg
	}

	// expects component id, input id, and dataset
	expectedFilestreamConfig := func(compID string, inputID string, dataset string) map[string]any {
		return map[string]any{
			"filebeat": map[string]any{
				"inputs": []map[string]any{
					{
						"id":   inputID,
						"type": "filestream",
						"data_stream": map[string]any{
							"dataset": dataset,
						},
						"paths": []any{
							"/var/log/*.log",
						},
						"index":      fmt.Sprintf("logs-%s-default", dataset),
						"processors": defaultInputProcessors(inputID, dataset, "logs"),
					},
				},
			},
			"path": map[string]any{
				"home": paths.Components(),
				"data": filepath.Join(paths.Run(), compID),
			},
			"queue": map[string]any{
				"mem": map[string]any{
					"events": int64(6400),
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
						"id":      compID,
					},
					"log": map[string]any{
						"source": compID,
					},
				},
			},
			"http": map[string]any{
				"enabled": false,
			},
			"management.otel.enabled": true,
		}
	}

	expectedBeatMetricConfig := map[string]any{
		"include_metadata": true,
		"metricbeat": map[string]any{
			"modules": []map[string]any{
				{
					"data_stream": map[string]any{"dataset": "generic-1"},
					"hosts":       "http://localhost:5066",
					"id":          "test-1",
					"index":       "metrics-generic-1-default",
					"metricsets":  []interface{}{"stats"},
					"period":      "60s",
					"processors":  defaultInputProcessors("test-1", "generic-1", "metrics"),
					"module":      "beat",
				},
			},
		},
		"path": map[string]any{
			"home": paths.Components(),
			"data": filepath.Join(paths.Run(), "beat-metrics-monitoring"),
		},
		"queue": map[string]any{
			"mem": map[string]any{
				"events": float64(3200),
				"flush": map[string]any{
					"min_events": float64(1600),
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
			"enabled": false,
		},
		"management.otel.enabled": true,
	}

	tests := []struct {
		name              string
		model             *component.Model
		expectedConfig    *confmap.Conf
		expectedError     error
		defaultProcessors *bool // value of the default_processors feature flag
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
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
				"processors": defaultExpectedProcessors("filebeat", "filestream-default"),
				"receivers": map[string]any{
					"filebeatreceiver/_agent-component/filestream-default/test-1": expectedFilestreamConfig("filestream-default", "test-1", "generic-1"),
					"filebeatreceiver/_agent-component/filestream-default/test-2": expectedFilestreamConfig("filestream-default", "test-2", "generic-2"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/filestream-default": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("filestream-default")},
							"receivers":  {"filebeatreceiver/_agent-component/filestream-default/test-1", "filebeatreceiver/_agent-component/filestream-default/test-2"},
						},
					},
				},
			}),
		},
		{
			name:              "filestream with default processors disabled",
			defaultProcessors: func() *bool { b := false; return &b }(), // Looking forward to Go v1.26 and its `new(false)` notation
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "filestream-default",
						InputType:  "filestream",
						OutputType: "elasticsearch",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
					"filebeatreceiver/_agent-component/filestream-default/test-1": expectedFilestreamConfig("filestream-default", "test-1", "generic-1"),
					"filebeatreceiver/_agent-component/filestream-default/test-2": expectedFilestreamConfig("filestream-default", "test-2", "generic-2"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/filestream-default": map[string][]string{
							"exporters": {"elasticsearch/_agent-component/default"},
							"receivers": {"filebeatreceiver/_agent-component/filestream-default/test-1", "filebeatreceiver/_agent-component/filestream-default/test-2"},
						},
					},
				},
			}),
		},
		{
			name: "filestream with global processors",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "filestream-default",
						InputType:  "filestream",
						OutputType: "elasticsearch",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
								ID:   "filestream-default",
								Type: client.UnitTypeOutput,
								Config: component.MustExpectedConfig(esOutputConfig(extraParams{
									key:   "processors",
									value: []any{"filter/remove-something", "beat", "batch"},
								})),
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
				"processors": defaultExpectedProcessors("filebeat", "filestream-default"),
				"receivers": map[string]any{
					"filebeatreceiver/_agent-component/filestream-default/test-1": expectedFilestreamConfig("filestream-default", "test-1", "generic-1"),
					"filebeatreceiver/_agent-component/filestream-default/test-2": expectedFilestreamConfig("filestream-default", "test-2", "generic-2"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/filestream-default": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("filestream-default"), "filter/remove-something", "beat", "batch"},
							"receivers":  {"filebeatreceiver/_agent-component/filestream-default/test-1", "filebeatreceiver/_agent-component/filestream-default/test-2"},
						},
					},
				},
			}),
		},
		{
			name: "metricbeat with logstash output",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "beat-metrics-monitoring",
						InputType:  "beat/metrics",
						OutputType: "logstash",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
								ID:   "beat/metrics-default",
								Type: client.UnitTypeOutput,
								Config: component.MustExpectedConfig(map[string]any{
									"type":                       "logstash",
									"hosts":                      []any{"localhost:5044"},
									"queue.mem.events":           3200,
									"queue.mem.flush.min_events": 1600,
									"queue.mem.flush.timeout":    "10s",
								}),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": map[string]any{
					"logstash/_agent-component/default": map[string]any{
						"hosts": []any{"localhost:5044"},
						"backoff": map[string]any{
							"init": "1s",
							"max":  "1m0s",
						},
						"bulk_max_size":            uint64(2048),
						"compression_level":        uint64(3),
						"escape_html":              false,
						"index":                    "",
						"loadbalance":              false,
						"max_retries":              uint64(3),
						"pipelining":               uint64(2),
						"proxy_url":                "",
						"proxy_use_local_resolver": false,
						"slow_start":               false,
						"timeout":                  "30s",
						"ttl":                      "0s",
						"worker":                   int64(0),
						"workers":                  int64(0),
					},
				},
				"processors": defaultExpectedProcessors("metricbeat", "beat-metrics-monitoring"),
				"receivers": map[string]any{
					"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1": map[string]any{
						"include_metadata": true,
						"metricbeat": map[string]any{
							"modules": []map[string]any{
								{
									"data_stream": map[string]any{"dataset": "generic-1"},
									"hosts":       "http://localhost:5066",
									"id":          "test-1",
									"index":       "metrics-generic-1-default",
									"metricsets":  []interface{}{"stats"},
									"period":      "60s",
									"processors":  defaultInputProcessors("test-1", "generic-1", "metrics"),
									"module":      "beat",
								},
							},
						},
						"path": map[string]any{
							"home": paths.Components(),
							"data": filepath.Join(paths.Run(), "beat-metrics-monitoring"),
						},
						"queue": map[string]any{
							"mem": map[string]any{
								"events": float64(3200),
								"flush": map[string]any{
									"min_events": float64(1600),
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
							"enabled": false,
						},
						"management.otel.enabled": true,
					},
				},
				"service": map[string]any{
					"pipelines": map[string]any{
						"logs/_agent-component/beat-metrics-monitoring": map[string][]string{
							"exporters":  {"logstash/_agent-component/default"},
							"processors": {beatProcessorID("beat-metrics-monitoring")},
							"receivers":  {"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1"},
						},
					},
				},
			}),
		},
		{
			name: "metricbeat with kafka output",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "beat-metrics-monitoring",
						InputType:  "beat/metrics",
						OutputType: "kafka",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
								ID:   "beat/metrics-default",
								Type: client.UnitTypeOutput,
								Config: component.MustExpectedConfig(map[string]any{
									"type":                       "kafka",
									"hosts":                      []any{"127.0.0.1:9022"},
									"topic":                      "%{[data_stream.type]}-%{[data_stream.dataset]}-%{[data_stream.namespace]}",
									"queue.mem.events":           3200,
									"queue.mem.flush.min_events": 1600,
									"queue.mem.flush.timeout":    "10s",
								}),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": map[string]any{
					"kafka/_agent-component/default": map[string]any{
						"brokers":              []string{"127.0.0.1:9022"},
						"topic_from_attribute": "topic",
						"client_id":            "beats",
						"metadata": map[string]any{
							"refresh_interval": 10 * time.Minute,
						},
						"producer": map[string]any{
							"compression": "gzip",
							"compression_params": map[string]any{
								"level": 4,
							},
							"max_message_bytes": 1000000,
							"required_acks":     1,
						},
						"protocol_version": "2.1.0",
						"retry_on_failure": map[string]any{
							"initial_interval": 1 * time.Second,
							"max_interval":     60 * time.Second,
						},
						"sending_queue": map[string]any{
							"batch": map[string]any{
								"flush_timeout": "10s",
								"max_size":      2048,
								"sizer":         "items",
								"min_size":      1600,
							},
							"queue_size": 3200,
						},
						"logs": map[string]any{
							"encoding": "raw",
						},
						"timeout": 10 * time.Second,
						"record_partitioner": map[string]any{
							"extension": "kafkapartitioner/_agent-component/default",
						},
					},
				},
				"processors": map[string]any{
					beatProcessorID("beat-metrics-monitoring"): map[string]any{
						"processors": GetDefaultProcessors("metricbeat"),
					},
					"transform/_agent-component/default": map[string]any{
						"error_mode": "ignore",
						"log_statements": []string{
							`set(resource.attributes["topic"], log.body["data_stream"]["type"])`,
							`set(resource.attributes["topic"], Concat([resource.attributes["topic"], log.body["data_stream"]["dataset"]], "-"))`,
							`set(resource.attributes["topic"], Concat([resource.attributes["topic"], log.body["data_stream"]["namespace"]], "-"))`,
						},
					},
				},
				"extensions": map[string]any{
					"kafkapartitioner/_agent-component/default": map[string]interface{}{},
				},
				"receivers": map[string]any{
					"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1": expectedBeatMetricConfig,
				},
				"service": map[string]any{
					"extensions": []any{"kafkapartitioner/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/beat-metrics-monitoring": map[string][]string{
							"exporters":  {"kafka/_agent-component/default"},
							"processors": {beatProcessorID("beat-metrics-monitoring"), "transform/_agent-component/default"},
							"receivers":  {"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1"},
						},
					},
				},
			}),
		},
		{
			name: "metricbeat with kafka output and hash partition",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "beat-metrics-monitoring",
						InputType:  "beat/metrics",
						OutputType: "kafka",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
								ID:   "beat/metrics-default",
								Type: client.UnitTypeOutput,
								Config: component.MustExpectedConfig(map[string]any{
									"type":                       "kafka",
									"hosts":                      []any{"127.0.0.1:9022"},
									"topic":                      "static-topic",
									"queue.mem.events":           3200,
									"queue.mem.flush.min_events": 1600,
									"queue.mem.flush.timeout":    "10s",
									"partition": map[string]any{
										"hash": map[string]any{
											"hash":   "fields",
											"fields": []any{"log.level"},
										},
									},
								}),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": map[string]any{
					"kafka/_agent-component/default": map[string]any{
						"brokers":   []string{"127.0.0.1:9022"},
						"client_id": "beats",
						"logs": map[string]any{
							"topic":    "static-topic",
							"encoding": "raw",
						},
						"metadata": map[string]any{
							"refresh_interval": 10 * time.Minute,
						},
						"producer": map[string]any{
							"compression": "gzip",
							"compression_params": map[string]any{
								"level": 4,
							},
							"max_message_bytes": 1000000,
							"required_acks":     1,
						},
						"protocol_version": "2.1.0",
						"retry_on_failure": map[string]any{
							"initial_interval": 1 * time.Second,
							"max_interval":     60 * time.Second,
						},
						"sending_queue": map[string]any{
							"batch": map[string]any{
								"flush_timeout": "10s",
								"max_size":      2048,
								"sizer":         "items",
								"min_size":      1600,
							},
							"queue_size": 3200,
						},
						"timeout": 10 * time.Second,
						"record_partitioner": map[string]any{
							"extension": "kafkapartitioner/_agent-component/default",
						},
					},
				},
				"extensions": map[string]any{
					"kafkapartitioner/_agent-component/default": map[string]interface{}{
						"hash": map[string]interface{}{
							"hash":   "fields",
							"fields": []interface{}{"log.level"},
						},
					},
				},
				"processors": defaultExpectedProcessors("metricbeat", "beat-metrics-monitoring"),
				"receivers": map[string]any{
					"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1": expectedBeatMetricConfig,
				},
				"service": map[string]any{
					"extensions": []any{"kafkapartitioner/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/beat-metrics-monitoring": map[string][]string{
							"exporters":  {"kafka/_agent-component/default"},
							"processors": {beatProcessorID("beat-metrics-monitoring")},
							"receivers":  {"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1"},
						},
					},
				},
			}),
		},
		{
			name: "metricbeat with kafka output and round_robin partition",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "beat-metrics-monitoring",
						InputType:  "beat/metrics",
						OutputType: "kafka",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
								ID:   "beat/metrics-default",
								Type: client.UnitTypeOutput,
								Config: component.MustExpectedConfig(map[string]any{
									"type":                       "kafka",
									"hosts":                      []any{"127.0.0.1:9022"},
									"topic":                      "static-topic",
									"queue.mem.events":           3200,
									"queue.mem.flush.min_events": 1600,
									"queue.mem.flush.timeout":    "10s",
									"partition": map[string]any{
										"round_robin": map[string]any{
											"group_events": 10,
										},
									},
								}),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": map[string]any{
					"kafka/_agent-component/default": map[string]any{
						"brokers":   []string{"127.0.0.1:9022"},
						"client_id": "beats",
						"logs": map[string]any{
							"topic":    "static-topic",
							"encoding": "raw",
						},
						"metadata": map[string]any{
							"refresh_interval": 10 * time.Minute,
						},
						"producer": map[string]any{
							"compression": "gzip",
							"compression_params": map[string]any{
								"level": 4,
							},
							"max_message_bytes": 1000000,
							"required_acks":     1,
						},
						"protocol_version": "2.1.0",
						"retry_on_failure": map[string]any{
							"initial_interval": 1 * time.Second,
							"max_interval":     60 * time.Second,
						},
						"sending_queue": map[string]any{
							"batch": map[string]any{
								"flush_timeout": "10s",
								"max_size":      2048,
								"sizer":         "items",
								"min_size":      1600,
							},
							"queue_size": 3200,
						},
						"timeout": 10 * time.Second,
						"record_partitioner": map[string]any{
							"extension": "kafkapartitioner/_agent-component/default",
						},
					},
				},
				"extensions": map[string]any{
					"kafkapartitioner/_agent-component/default": map[string]interface{}{
						"round_robin": map[string]interface{}{
							"group_events": float64(10),
						},
					},
				},
				"processors": defaultExpectedProcessors("metricbeat", "beat-metrics-monitoring"),
				"receivers": map[string]any{
					"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1": expectedBeatMetricConfig,
				},
				"service": map[string]any{
					"extensions": []any{"kafkapartitioner/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/beat-metrics-monitoring": map[string][]string{
							"exporters":  {"kafka/_agent-component/default"},
							"processors": {beatProcessorID("beat-metrics-monitoring")},
							"receivers":  {"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1"},
						},
					},
				},
			}),
		},
		{
			name: "two kafka outputs with different partitioners",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "beat-metrics-monitoring",
						InputType:  "beat/metrics",
						OutputType: "kafka",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
								ID:   "beat/metrics-default",
								Type: client.UnitTypeOutput,
								Config: component.MustExpectedConfig(map[string]any{
									"type":                       "kafka",
									"hosts":                      []any{"127.0.0.1:9022"},
									"topic":                      "static-topic",
									"queue.mem.events":           3200,
									"queue.mem.flush.min_events": 1600,
									"queue.mem.flush.timeout":    "10s",
									"partition": map[string]any{
										"hash": map[string]any{
											"hash":   "fields",
											"fields": []any{"log.level"},
										},
									},
								}),
							},
						},
					},
					{
						ID:         "beat-metrics-monitoring2",
						InputType:  "beat/metrics",
						OutputType: "kafka",
						OutputName: "monitoring",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
							Spec: component.InputSpec{
								Command: &component.CommandSpec{
									Args: []string{"metricbeat"},
								},
							},
						},
						Units: []component.Unit{
							{
								ID:     "beat/metrics-monitoring2",
								Type:   client.UnitTypeInput,
								Config: component.MustExpectedConfig(beatMetricsConfig),
							},
							{
								ID:   "beat/metrics-monitoring",
								Type: client.UnitTypeOutput,
								Config: component.MustExpectedConfig(map[string]any{
									"type":                       "kafka",
									"hosts":                      []any{"127.0.0.1:9023"},
									"topic":                      "monitoring-topic",
									"queue.mem.events":           3200,
									"queue.mem.flush.min_events": 1600,
									"queue.mem.flush.timeout":    "10s",
									"partition": map[string]any{
										"round_robin": map[string]any{
											"group_events": 10,
										},
									},
								}),
							},
						},
					},
				},
			},
			expectedConfig: confmap.NewFromStringMap(map[string]any{
				"exporters": map[string]any{
					"kafka/_agent-component/default": map[string]any{
						"brokers":   []string{"127.0.0.1:9022"},
						"client_id": "beats",
						"logs": map[string]any{
							"topic":    "static-topic",
							"encoding": "raw",
						},
						"metadata": map[string]any{
							"refresh_interval": 10 * time.Minute,
						},
						"producer": map[string]any{
							"compression": "gzip",
							"compression_params": map[string]any{
								"level": 4,
							},
							"max_message_bytes": 1000000,
							"required_acks":     1,
						},
						"protocol_version": "2.1.0",
						"retry_on_failure": map[string]any{
							"initial_interval": 1 * time.Second,
							"max_interval":     60 * time.Second,
						},
						"sending_queue": map[string]any{
							"batch": map[string]any{
								"flush_timeout": "10s",
								"max_size":      2048,
								"sizer":         "items",
								"min_size":      1600,
							},
							"queue_size": 3200,
						},
						"timeout": 10 * time.Second,
						"record_partitioner": map[string]any{
							"extension": "kafkapartitioner/_agent-component/default",
						},
					},
					"kafka/_agent-component/monitoring": map[string]any{
						"brokers":   []string{"127.0.0.1:9023"},
						"client_id": "beats",
						"logs": map[string]any{
							"topic":    "monitoring-topic",
							"encoding": "raw",
						},
						"metadata": map[string]any{
							"refresh_interval": 10 * time.Minute,
						},
						"producer": map[string]any{
							"compression": "gzip",
							"compression_params": map[string]any{
								"level": 4,
							},
							"max_message_bytes": 1000000,
							"required_acks":     1,
						},
						"protocol_version": "2.1.0",
						"retry_on_failure": map[string]any{
							"initial_interval": 1 * time.Second,
							"max_interval":     60 * time.Second,
						},
						"sending_queue": map[string]any{
							"batch": map[string]any{
								"flush_timeout": "10s",
								"max_size":      2048,
								"sizer":         "items",
								"min_size":      1600,
							},
							"queue_size": 3200,
						},
						"timeout": 10 * time.Second,
						"record_partitioner": map[string]any{
							"extension": "kafkapartitioner/_agent-component/monitoring",
						},
					},
				},
				"extensions": map[string]any{
					"kafkapartitioner/_agent-component/default": map[string]interface{}{
						"hash": map[string]interface{}{
							"hash":   "fields",
							"fields": []interface{}{"log.level"},
						},
					},
					"kafkapartitioner/_agent-component/monitoring": map[string]interface{}{
						"round_robin": map[string]interface{}{
							"group_events": float64(10),
						},
					},
				},
				"processors": defaultExpectedProcessors("metricbeat", "beat-metrics-monitoring", "beat-metrics-monitoring2"),
				"receivers": map[string]any{
					"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1": expectedBeatMetricConfig,
					"metricbeatreceiver/_agent-component/beat-metrics-monitoring2/test-1": map[string]any{
						"include_metadata": true,
						"metricbeat": map[string]any{
							"modules": []map[string]any{
								{
									"data_stream": map[string]any{"dataset": "generic-1"},
									"hosts":       "http://localhost:5066",
									"id":          "test-1",
									"index":       "metrics-generic-1-default",
									"metricsets":  []interface{}{"stats"},
									"period":      "60s",
									"processors":  defaultInputProcessors("test-1", "generic-1", "metrics"),
									"module":      "beat",
								},
							},
						},
						"path": map[string]any{
							"home": paths.Components(),
							"data": filepath.Join(paths.Run(), "beat-metrics-monitoring2"),
						},
						"queue": map[string]any{
							"mem": map[string]any{
								"events": float64(3200),
								"flush": map[string]any{
									"min_events": float64(1600),
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
									"id":      "beat-metrics-monitoring2",
								},
								"log": map[string]any{
									"source": "beat-metrics-monitoring2",
								},
							},
						},
						"http": map[string]any{
							"enabled": false,
						},
						"management.otel.enabled": true,
					},
				},
				"service": map[string]any{
					"extensions": []any{"kafkapartitioner/_agent-component/default", "kafkapartitioner/_agent-component/monitoring"},
					"pipelines": map[string]any{
						"logs/_agent-component/beat-metrics-monitoring": map[string][]string{
							"exporters":  {"kafka/_agent-component/default"},
							"processors": {beatProcessorID("beat-metrics-monitoring")},
							"receivers":  {"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1"},
						},
						"logs/_agent-component/beat-metrics-monitoring2": map[string][]string{
							"exporters":  {"kafka/_agent-component/monitoring"},
							"processors": {beatProcessorID("beat-metrics-monitoring2")},
							"receivers":  {"metricbeatreceiver/_agent-component/beat-metrics-monitoring2/test-1"},
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
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
				"processors": defaultExpectedProcessors("filebeat", "filestream1-default", "filestream2-default"),
				"receivers": map[string]any{
					"filebeatreceiver/_agent-component/filestream1-default/test-1": expectedFilestreamConfig("filestream1-default", "test-1", "generic-1"),
					"filebeatreceiver/_agent-component/filestream1-default/test-2": expectedFilestreamConfig("filestream1-default", "test-2", "generic-2"),
					"filebeatreceiver/_agent-component/filestream2-default/test-1": expectedFilestreamConfig("filestream2-default", "test-1", "generic-1"),
					"filebeatreceiver/_agent-component/filestream2-default/test-2": expectedFilestreamConfig("filestream2-default", "test-2", "generic-2"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/filestream1-default": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("filestream1-default")},
							"receivers":  {"filebeatreceiver/_agent-component/filestream1-default/test-1", "filebeatreceiver/_agent-component/filestream1-default/test-2"},
						},
						"logs/_agent-component/filestream2-default": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("filestream2-default")},
							"receivers":  {"filebeatreceiver/_agent-component/filestream2-default/test-1", "filebeatreceiver/_agent-component/filestream2-default/test-2"},
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
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
				"processors": defaultExpectedProcessors("metricbeat", "beat-metrics-monitoring"),
				"receivers": map[string]any{
					"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1": map[string]any{
						"metricbeat": map[string]any{
							"modules": []map[string]any{
								{
									"data_stream": map[string]any{"dataset": "generic-1"},
									"hosts":       "http://localhost:5066",
									"id":          "test-1",
									"index":       "metrics-generic-1-default",
									"metricsets":  []interface{}{"stats"},
									"period":      "60s",
									"processors":  defaultInputProcessors("test-1", "generic-1", "metrics"),
									"module":      "beat",
								},
							},
						},
						"path": map[string]any{
							"home": paths.Components(),
							"data": filepath.Join(paths.Run(), "beat-metrics-monitoring"),
						},
						"queue": map[string]any{
							"mem": map[string]any{
								"events": int64(6400),
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
							"enabled": false,
						},
						"management.otel.enabled": true,
					},
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/beat-metrics-monitoring": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("beat-metrics-monitoring")},
							"receivers":  {"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1"},
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
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
				"processors": defaultExpectedProcessors("metricbeat", "system-metrics"),
				"receivers": map[string]any{
					"metricbeatreceiver/_agent-component/system-metrics/test-1": map[string]any{
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
									"processors": defaultInputProcessors("test-1", "generic-1", "metrics"),
								},
							},
						},
						"path": map[string]any{
							"home": paths.Components(),
							"data": filepath.Join(paths.Run(), "system-metrics"),
						},
						"queue": map[string]any{
							"mem": map[string]any{
								"events": int64(6400),
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
							"enabled": false,
						},
						"management.otel.enabled": true,
					},
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/system-metrics": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("system-metrics")},
							"receivers":  {"metricbeatreceiver/_agent-component/system-metrics/test-1"},
						},
					},
				},
			}),
		},
		{
			name: "auditbeat",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "auditbeat-default",
						InputType:  "audit/auditd",
						OutputType: "elasticsearch",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
							Spec: component.InputSpec{
								Command: &component.CommandSpec{
									Args: []string{"auditbeat"},
								},
							},
						},
						Units: []component.Unit{
							{
								ID:     "auditbeat-unit",
								Type:   client.UnitTypeInput,
								Config: component.MustExpectedConfig(auditbeatInputConfig),
							},
							{
								ID:     "auditbeat-default",
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
				"processors": defaultExpectedProcessors("auditbeat", "auditbeat-default"),
				"receivers": map[string]any{
					"auditbeatreceiver/_agent-component/auditbeat-default/test-1": expectedAuditbeatReceiverConfig("auditbeat-default"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/auditbeat-default": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("auditbeat-default")},
							"receivers":  {"auditbeatreceiver/_agent-component/auditbeat-default/test-1"},
						},
					},
				},
			}),
		},
		{
			name: "heartbeat",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "heartbeat-default",
						InputType:  "synthetics/http",
						OutputType: "elasticsearch",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
							Spec: component.InputSpec{
								Command: &component.CommandSpec{
									Args: []string{"heartbeat"},
								},
							},
						},
						Units: []component.Unit{
							{
								ID:     "heartbeat-unit",
								Type:   client.UnitTypeInput,
								Config: component.MustExpectedConfig(heartbeatInputConfig),
							},
							{
								ID:     "heartbeat-default",
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
					"heartbeatreceiver/_agent-component/heartbeat-default/test-1": expectedHeartbeatReceiverConfig("heartbeat-default"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/heartbeat-default": map[string][]string{
							"exporters": {"elasticsearch/_agent-component/default"},
							"receivers": {"heartbeatreceiver/_agent-component/heartbeat-default/test-1"},
						},
					},
				},
			}),
		},
		{
			name: "osquerybeat",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "osquerybeat-default",
						InputType:  "osquery",
						OutputType: "elasticsearch",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
							Spec: component.InputSpec{
								Command: &component.CommandSpec{
									Args: []string{"osquerybeat"},
								},
							},
						},
						Units: []component.Unit{
							{
								ID:     "osquerybeat-unit",
								Type:   client.UnitTypeInput,
								Config: component.MustExpectedConfig(osquerybeatInputConfig),
							},
							{
								ID:     "osquerybeat-default",
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
				"processors": defaultExpectedProcessors("osquerybeat", "osquerybeat-default"),
				"receivers": map[string]any{
					"osquerybeatreceiver/_agent-component/osquerybeat-default/test-1": expectedOsquerybeatReceiverConfig("osquerybeat-default"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/osquerybeat-default": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("osquerybeat-default")},
							"receivers":  {"osquerybeatreceiver/_agent-component/osquerybeat-default/test-1"},
						},
					},
				},
			}),
		},
		{
			name: "osquerybeat with single_receiver merges all streams into one receiver",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "osquerybeat-default",
						InputType:  "osquery",
						OutputType: "elasticsearch",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
							Spec: component.InputSpec{
								Command: &component.CommandSpec{
									Args: []string{"osquerybeat"},
								},
								SingleReceiver: true,
							},
						},
						Units: []component.Unit{
							{
								ID:     "osquerybeat-unit",
								Type:   client.UnitTypeInput,
								Config: component.MustExpectedConfig(osquerybeatMultiStreamInputConfig),
							},
							{
								ID:     "osquerybeat-default",
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
				"processors": defaultExpectedProcessors("osquerybeat", "osquerybeat-default"),
				"receivers": map[string]any{
					// Single receiver keyed by component ID with the placeholder "single" stream suffix.
					"osquerybeatreceiver/_agent-component/osquerybeat-default/single": expectedOsquerybeatSingleReceiverConfig("osquerybeat-default"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/osquerybeat-default": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("osquerybeat-default")},
							"receivers":  {"osquerybeatreceiver/_agent-component/osquerybeat-default/single"},
						},
					},
				},
			}),
		},
		{
			name: "packetbeat",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "packetbeat-default",
						InputType:  "packet",
						OutputType: "elasticsearch",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
							Spec: component.InputSpec{
								Command: &component.CommandSpec{
									Args: []string{"packetbeat"},
								},
							},
						},
						Units: []component.Unit{
							{
								ID:     "packetbeat-unit",
								Type:   client.UnitTypeInput,
								Config: component.MustExpectedConfig(packetbeatInputConfig),
							},
							{
								ID:     "packetbeat-default",
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
				"processors": defaultExpectedProcessors("packetbeat", "packetbeat-default"),
				"receivers": map[string]any{
					"packetbeatreceiver/_agent-component/packetbeat-default/test-1": expectedPacketbeatReceiverConfig("packetbeat-default"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/packetbeat-default": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("packetbeat-default")},
							"receivers":  {"packetbeatreceiver/_agent-component/packetbeat-default/test-1"},
						},
					},
				},
			}),
		},
		{
			name: "fleet policy global add_cloud_metadata stripped from input processors, kept in beatprocessor",
			model: &component.Model{
				Components: []component.Component{
					{
						ID:         "filestream-default",
						InputType:  "filestream",
						OutputType: "elasticsearch",
						OutputName: "default",
						InputSpec: &component.InputRuntimeSpec{
							BinaryName: "elastic-otel-collector",
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
									"id":         "test",
									"use_output": "default",
									// Fleet integration packages include add_cloud_metadata at
									// the input root; it must be stripped in OTel mode.
									"processors": []any{
										map[string]any{"add_cloud_metadata": nil},
									},
									"streams": []any{
										map[string]any{
											"id": "test-1",
											"data_stream": map[string]any{
												"dataset": "generic-1",
											},
											"paths": []any{"/var/log/*.log"},
										},
									},
								}),
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
				"processors": defaultExpectedProcessors("filebeat", "filestream-default"),
				"receivers": map[string]any{
					"filebeatreceiver/_agent-component/filestream-default/test-1": expectedFilestreamConfig("filestream-default", "test-1", "generic-1"),
				},
				"service": map[string]any{
					"extensions": []any{"beatsauth/_agent-component/default"},
					"pipelines": map[string]any{
						"logs/_agent-component/filestream-default": map[string][]string{
							"exporters":  {"elasticsearch/_agent-component/default"},
							"processors": {beatProcessorID("filestream-default")},
							"receivers":  {"filebeatreceiver/_agent-component/filestream-default/test-1"},
						},
					},
				},
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.defaultProcessors != nil {
				originalFlags := features.GetDefaultProcessors()
				defer func() {
					err := features.Apply(internalConfig.MustNewConfigFrom(map[string]any{
						"agent.features.default_processors.add_host_metadata":       originalFlags.AddHostMetadata,
						"agent.features.default_processors.add_cloud_metadata":      originalFlags.AddCloudMetadata,
						"agent.features.default_processors.add_docker_metadata":     originalFlags.AddDockerMetadata,
						"agent.features.default_processors.add_kubernetes_metadata": originalFlags.AddKubernetesMetadata,
					}))
					require.NoError(t, err)
				}()
				err := features.Apply(internalConfig.MustNewConfigFrom(map[string]any{
					"agent.features.default_processors.enabled": *tt.defaultProcessors,
				}))
				require.NoError(t, err)
			}
			actualConf, actualError := GetOtelConfig(tt.model, agentInfo, logp.NewNopLogger())
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

func TestFilterDefaultProcessors(t *testing.T) {
	allDefaults := GetDefaultProcessors("filebeat")

	tests := []struct {
		name  string
		flags features.DefaultProcessors
		want  []map[string]any
	}{
		{
			name: "all enabled returns full list",
			flags: features.DefaultProcessors{
				AddHostMetadata:       true,
				AddCloudMetadata:      true,
				AddDockerMetadata:     true,
				AddKubernetesMetadata: true,
			},
			want: allDefaults,
		},
		{
			name: "all flags false returns empty list",
			flags: features.DefaultProcessors{
				AddHostMetadata:       false,
				AddCloudMetadata:      false,
				AddDockerMetadata:     false,
				AddKubernetesMetadata: false,
			},
			want: []map[string]any{},
		},
		{
			name: "add_host_metadata disabled",
			flags: features.DefaultProcessors{
				AddHostMetadata:       false,
				AddCloudMetadata:      true,
				AddDockerMetadata:     true,
				AddKubernetesMetadata: true,
			},
			want: []map[string]any{
				{"add_cloud_metadata": nil},
				{"add_docker_metadata": nil},
				{"add_kubernetes_metadata": nil},
			},
		},
		{
			name: "add_cloud_metadata disabled",
			flags: features.DefaultProcessors{
				AddHostMetadata:       true,
				AddCloudMetadata:      false,
				AddDockerMetadata:     true,
				AddKubernetesMetadata: true,
			},
			want: []map[string]any{
				{"add_host_metadata": map[string]any{"when.not.contains.tags": "forwarded"}},
				{"add_docker_metadata": nil},
				{"add_kubernetes_metadata": nil},
			},
		},
		{
			name: "all metadata processors disabled leaves empty list",
			flags: features.DefaultProcessors{
				AddHostMetadata:       false,
				AddCloudMetadata:      false,
				AddDockerMetadata:     false,
				AddKubernetesMetadata: false,
			},
			want: []map[string]any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterDefaultProcessors(allDefaults, tt.flags)
			assert.Equal(t, tt.want, got)
		})
	}

	// Packetbeat has non-metadata processors (drop_fields, detect_mime_type) that
	// must survive regardless of which metadata flags are set. These tests verify
	// the filterDefaultProcessors default: case always keeps those processors.
	t.Run("packetbeat", func(t *testing.T) {
		packetbeatDefaults := GetDefaultProcessors("packetbeat")
		dropFields := packetbeatDefaults[0]     // drop_fields
		addHostMeta := packetbeatDefaults[1]    // add_host_metadata
		addCloudMeta := packetbeatDefaults[2]   // add_cloud_metadata
		addDockerMeta := packetbeatDefaults[3]  // add_docker_metadata
		detectMimeReq := packetbeatDefaults[4]  // detect_mime_type (request)
		detectMimeResp := packetbeatDefaults[5] // detect_mime_type (response)

		tests := []struct {
			name  string
			flags features.DefaultProcessors
			want  []map[string]any
		}{
			{
				name: "all enabled returns full list",
				flags: features.DefaultProcessors{
					AddHostMetadata: true, AddCloudMetadata: true,
					AddDockerMetadata: true, AddKubernetesMetadata: true,
				},
				want: packetbeatDefaults,
			},
			{
				name: "add_host_metadata disabled keeps drop_fields",
				flags: features.DefaultProcessors{
					AddHostMetadata: false, AddCloudMetadata: true,
					AddDockerMetadata: true, AddKubernetesMetadata: true,
				},
				want: []map[string]any{dropFields, addCloudMeta, addDockerMeta, detectMimeReq, detectMimeResp},
			},
			{
				name: "all metadata flags false keeps non-metadata processors",
				flags: features.DefaultProcessors{
					AddHostMetadata: false, AddCloudMetadata: false,
					AddDockerMetadata: false, AddKubernetesMetadata: false,
				},
				want: []map[string]any{dropFields, detectMimeReq, detectMimeResp},
			},
			{
				name: "add_cloud_metadata disabled keeps drop_fields and detect_mime_type",
				flags: features.DefaultProcessors{
					AddHostMetadata: true, AddCloudMetadata: false,
					AddDockerMetadata: true, AddKubernetesMetadata: true,
				},
				want: []map[string]any{dropFields, addHostMeta, addDockerMeta, detectMimeReq, detectMimeResp},
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := filterDefaultProcessors(packetbeatDefaults, tt.flags)
				assert.Equal(t, tt.want, got)
			})
		}
	})
}

func TestEffectiveDefaultProcessorFlags(t *testing.T) {
	newComp := func(outputCfg map[string]any) *component.Component {
		return &component.Component{
			ID:         "filestream-default",
			InputType:  "filestream",
			OutputType: "elasticsearch",
			OutputName: "default",
			InputSpec: &component.InputRuntimeSpec{
				BinaryName: "elastic-otel-collector",
				Spec: component.InputSpec{
					Command: &component.CommandSpec{Args: []string{"filebeat"}},
				},
			},
			Units: []component.Unit{
				{
					ID:     "filestream-default",
					Type:   client.UnitTypeOutput,
					Config: component.MustExpectedConfig(outputCfg),
				},
			},
		}
	}

	baseOutputCfg := map[string]any{
		"type":  "elasticsearch",
		"hosts": []any{"localhost:9200"},
	}

	tests := []struct {
		name    string
		global  features.DefaultProcessors
		output  map[string]any
		want    features.DefaultProcessors
		wantErr bool
	}{
		{
			name: "no per-output config returns global flags",
			global: features.DefaultProcessors{
				AddHostMetadata: true, AddCloudMetadata: true,
				AddDockerMetadata: true, AddKubernetesMetadata: true,
			},
			output: baseOutputCfg,
			want: features.DefaultProcessors{
				AddHostMetadata: true, AddCloudMetadata: true,
				AddDockerMetadata: true, AddKubernetesMetadata: true,
			},
		},
		{
			name: "per-output enabled:false disables all unspecified processors",
			global: features.DefaultProcessors{
				AddHostMetadata: true, AddCloudMetadata: true,
				AddDockerMetadata: true, AddKubernetesMetadata: true,
			},
			output: mergeMap(baseOutputCfg, map[string]any{
				"default_processors": map[string]any{"enabled": false},
			}),
			want: features.DefaultProcessors{
				AddHostMetadata: false, AddCloudMetadata: false,
				AddDockerMetadata: false, AddKubernetesMetadata: false,
			},
		},
		{
			name: "per-output individual flag overrides enabled:false",
			global: features.DefaultProcessors{
				AddHostMetadata: true, AddCloudMetadata: true,
				AddDockerMetadata: true, AddKubernetesMetadata: true,
			},
			output: mergeMap(baseOutputCfg, map[string]any{
				"default_processors": map[string]any{
					"enabled":            false,
					"add_cloud_metadata": true,
				},
			}),
			want: features.DefaultProcessors{
				AddHostMetadata: false, AddCloudMetadata: true,
				AddDockerMetadata: false, AddKubernetesMetadata: false,
			},
		},
		{
			name: "per-output add_cloud_metadata:false restricts global",
			global: features.DefaultProcessors{
				AddHostMetadata: true, AddCloudMetadata: true,
				AddDockerMetadata: true, AddKubernetesMetadata: true,
			},
			output: mergeMap(baseOutputCfg, map[string]any{
				"default_processors": map[string]any{
					"add_cloud_metadata": false,
				},
			}),
			want: features.DefaultProcessors{
				AddHostMetadata: true, AddCloudMetadata: false,
				AddDockerMetadata: true, AddKubernetesMetadata: true,
			},
		},
		{
			name: "per-output cannot re-enable globally disabled processor",
			global: features.DefaultProcessors{
				AddHostMetadata: false, AddCloudMetadata: true,
				AddDockerMetadata: true, AddKubernetesMetadata: true,
			},
			output: mergeMap(baseOutputCfg, map[string]any{
				"default_processors": map[string]any{
					"add_host_metadata": true,
				},
			}),
			// global AddHostMetadata:false AND per-output true → false (AND logic)
			want: features.DefaultProcessors{
				AddHostMetadata: false, AddCloudMetadata: true,
				AddDockerMetadata: true, AddKubernetesMetadata: true,
			},
		},
		{
			name: "per-output default_processors without enabled defaults enabled to true",
			global: features.DefaultProcessors{
				AddHostMetadata: true, AddCloudMetadata: true,
				AddDockerMetadata: true, AddKubernetesMetadata: true,
			},
			output: mergeMap(baseOutputCfg, map[string]any{
				"default_processors": map[string]any{
					"add_cloud_metadata": false,
					// enabled is absent — should default to true, not false
				},
			}),
			want: features.DefaultProcessors{
				AddHostMetadata: true, AddCloudMetadata: false,
				AddDockerMetadata: true, AddKubernetesMetadata: true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Apply the global flags via features.Apply.
			originalFlags := features.GetDefaultProcessors()
			defer func() {
				_ = features.Apply(internalConfig.MustNewConfigFrom(map[string]any{
					"agent.features.default_processors.add_host_metadata":       originalFlags.AddHostMetadata,
					"agent.features.default_processors.add_cloud_metadata":      originalFlags.AddCloudMetadata,
					"agent.features.default_processors.add_docker_metadata":     originalFlags.AddDockerMetadata,
					"agent.features.default_processors.add_kubernetes_metadata": originalFlags.AddKubernetesMetadata,
				}))
			}()
			err := features.Apply(internalConfig.MustNewConfigFrom(map[string]any{
				"agent.features.default_processors.add_host_metadata":       tt.global.AddHostMetadata,
				"agent.features.default_processors.add_cloud_metadata":      tt.global.AddCloudMetadata,
				"agent.features.default_processors.add_docker_metadata":     tt.global.AddDockerMetadata,
				"agent.features.default_processors.add_kubernetes_metadata": tt.global.AddKubernetesMetadata,
			}))
			require.NoError(t, err)

			comp := newComp(tt.output)
			got, err := effectiveDefaultProcessorFlags(comp)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

	// This sub-test verifies that the DefaultProcessors.Unpack method is called by
	// ucfg when populating the *DefaultProcessors field in the cfg struct (via
	// features.Apply → features.Parse → config.UnpackTo). Without Unpack, the
	// enabled: key has no matching struct field and would be silently ignored, leaving
	// all processors at their zero value (false) regardless of intent.
	t.Run("global enabled:false via Apply disables all processors", func(t *testing.T) {
		originalFlags := features.GetDefaultProcessors()
		defer func() {
			_ = features.Apply(internalConfig.MustNewConfigFrom(map[string]any{
				"agent.features.default_processors.add_host_metadata":       originalFlags.AddHostMetadata,
				"agent.features.default_processors.add_cloud_metadata":      originalFlags.AddCloudMetadata,
				"agent.features.default_processors.add_docker_metadata":     originalFlags.AddDockerMetadata,
				"agent.features.default_processors.add_kubernetes_metadata": originalFlags.AddKubernetesMetadata,
			}))
		}()
		require.NoError(t, features.Apply(internalConfig.MustNewConfigFrom(map[string]any{
			"agent.features.default_processors.enabled": false,
		})))

		comp := newComp(baseOutputCfg)
		got, err := effectiveDefaultProcessorFlags(comp)
		require.NoError(t, err)
		assert.Equal(t, features.DefaultProcessors{}, got)
	})

	t.Run("global enabled:false with individual override via Apply", func(t *testing.T) {
		originalFlags := features.GetDefaultProcessors()
		defer func() {
			_ = features.Apply(internalConfig.MustNewConfigFrom(map[string]any{
				"agent.features.default_processors.add_host_metadata":       originalFlags.AddHostMetadata,
				"agent.features.default_processors.add_cloud_metadata":      originalFlags.AddCloudMetadata,
				"agent.features.default_processors.add_docker_metadata":     originalFlags.AddDockerMetadata,
				"agent.features.default_processors.add_kubernetes_metadata": originalFlags.AddKubernetesMetadata,
			}))
		}()
		require.NoError(t, features.Apply(internalConfig.MustNewConfigFrom(map[string]any{
			"agent.features.default_processors.enabled":            false,
			"agent.features.default_processors.add_cloud_metadata": true,
		})))

		comp := newComp(baseOutputCfg)
		got, err := effectiveDefaultProcessorFlags(comp)
		require.NoError(t, err)
		assert.Equal(t, features.DefaultProcessors{AddCloudMetadata: true}, got)
	})
}

// mergeMap returns a shallow copy of base with the entries from extra merged in.
func mergeMap(base, extra map[string]any) map[string]any {
	result := make(map[string]any, len(base)+len(extra))
	maps.Copy(result, base)
	maps.Copy(result, extra)
	return result
}

// testFileStreamInputConfig is a minimal filestream input config used by tests outside TestGetOtelConfig.
var testFileStreamInputConfig = map[string]any{
	"id":         "test",
	"use_output": "default",
	"streams": []any{
		map[string]any{
			"id": "test-1",
			"data_stream": map[string]any{
				"dataset": "generic-1",
			},
			"paths": []any{"/var/log/*.log"},
		},
	},
}

// testESOutputConfig returns a minimal ES output config, optionally merged with extra fields.
func testESOutputConfig(extra ...map[string]any) map[string]any {
	base := map[string]any{
		"type":     "elasticsearch",
		"hosts":    []any{"localhost:9200"},
		"username": "elastic",
		"password": "password",
		"preset":   "balanced",
	}
	for _, e := range extra {
		maps.Copy(base, e)
	}
	return base
}

// testBeatProcessorID returns the OTel processor ID for the beat default processor of a component.
func testBeatProcessorID(compID string) string {
	return "beat/_agent-component/" + compID
}

// testFilebeatComp builds a simple filestream/ES component for testing default processors.
func testFilebeatComp(compID, outputName string, outputExtra ...map[string]any) component.Component {
	outputCfg := testESOutputConfig(outputExtra...)
	return component.Component{
		ID:         compID,
		InputType:  "filestream",
		OutputType: "elasticsearch",
		OutputName: outputName,
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Command: &component.CommandSpec{Args: []string{"filebeat"}},
			},
		},
		Units: []component.Unit{
			{
				ID:     compID + "-input",
				Type:   client.UnitTypeInput,
				Config: component.MustExpectedConfig(testFileStreamInputConfig),
			},
			{
				ID:     compID + "-output",
				Type:   client.UnitTypeOutput,
				Config: component.MustExpectedConfig(outputCfg),
			},
		},
	}
}

// processorNamesFromOtelConfig extracts the list of processor names from the beatprocessor
// config for the given component ID.
func processorNamesFromOtelConfig(t *testing.T, conf *confmap.Conf, compID string) []string {
	t.Helper()
	m := conf.ToStringMap()
	procsAny, ok := m["processors"]
	if !ok {
		return nil
	}
	procs, ok := procsAny.(map[string]any)
	if !ok {
		return nil
	}
	beatProcAny, ok := procs[testBeatProcessorID(compID)]
	if !ok {
		return nil
	}
	beatProc, ok := beatProcAny.(map[string]any)
	if !ok {
		return nil
	}
	listAny, ok := beatProc["processors"]
	if !ok {
		return nil
	}
	list, ok := listAny.([]map[string]any)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(list))
	for _, p := range list {
		for k := range p {
			names = append(names, k)
		}
	}
	return names
}

// applyDefaultProcessorFlags applies the given flags to the global features and
// registers a cleanup to restore the original flags when the test ends.
func applyDefaultProcessorFlags(t *testing.T, f features.DefaultProcessors) {
	t.Helper()
	orig := features.GetDefaultProcessors()
	t.Cleanup(func() {
		_ = features.Apply(internalConfig.MustNewConfigFrom(map[string]any{
			"agent.features.default_processors.add_host_metadata":       orig.AddHostMetadata,
			"agent.features.default_processors.add_cloud_metadata":      orig.AddCloudMetadata,
			"agent.features.default_processors.add_docker_metadata":     orig.AddDockerMetadata,
			"agent.features.default_processors.add_kubernetes_metadata": orig.AddKubernetesMetadata,
		}))
	})
	require.NoError(t, features.Apply(internalConfig.MustNewConfigFrom(map[string]any{
		"agent.features.default_processors.add_host_metadata":       f.AddHostMetadata,
		"agent.features.default_processors.add_cloud_metadata":      f.AddCloudMetadata,
		"agent.features.default_processors.add_docker_metadata":     f.AddDockerMetadata,
		"agent.features.default_processors.add_kubernetes_metadata": f.AddKubernetesMetadata,
	})))
}

func TestGetOtelConfigWithGlobalPerProcessorFlags(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err)

	filebeatComp := testFilebeatComp("filestream-default", "default")

	t.Run("global add_cloud_metadata disabled", func(t *testing.T) {
		applyDefaultProcessorFlags(t, features.DefaultProcessors{
			AddHostMetadata: true, AddCloudMetadata: false,
			AddDockerMetadata: true, AddKubernetesMetadata: true,
		})

		model := &component.Model{Components: []component.Component{filebeatComp}}
		conf, err := GetOtelConfig(model, agentInfo, logp.NewNopLogger())
		require.NoError(t, err)

		names := processorNamesFromOtelConfig(t, conf, "filestream-default")
		require.NotNil(t, names)
		assert.NotContains(t, names, "add_cloud_metadata")
		assert.Contains(t, names, "add_host_metadata")
		assert.Contains(t, names, "add_docker_metadata")
		assert.Contains(t, names, "add_kubernetes_metadata")
	})

	t.Run("all metadata processors disabled leaves no beatprocessor", func(t *testing.T) {
		applyDefaultProcessorFlags(t, features.DefaultProcessors{
			AddHostMetadata: false, AddCloudMetadata: false,
			AddDockerMetadata: false, AddKubernetesMetadata: false,
		})

		model := &component.Model{Components: []component.Component{filebeatComp}}
		conf, err := GetOtelConfig(model, agentInfo, logp.NewNopLogger())
		require.NoError(t, err)

		m := conf.ToStringMap()
		// No processors section when the effective list is empty.
		assert.NotContains(t, m, "processors")

		// Pipeline should have no processors entry (pipeline config is map[string][]string
		// since no processors were added).
		svc := m["service"].(map[string]any)
		pipelines := svc["pipelines"].(map[string]any)
		pipe := pipelines["logs/_agent-component/filestream-default"].(map[string][]string)
		assert.NotContains(t, pipe, "processors")
	})
}

func TestGetOtelConfigWithPerOutputDefaultProcessors(t *testing.T) {
	agentInfo, err := info.NewAgentInfo(context.Background(), false)
	require.NoError(t, err)

	t.Run("per-output enabled:false disables all processors for that output", func(t *testing.T) {
		comp := testFilebeatComp("filestream-default", "default", map[string]any{
			"default_processors": map[string]any{"enabled": false},
		})
		model := &component.Model{Components: []component.Component{comp}}
		conf, err := GetOtelConfig(model, agentInfo, logp.NewNopLogger())
		require.NoError(t, err)

		m := conf.ToStringMap()
		assert.NotContains(t, m, "processors")

		// Pipeline has no processors entry; its type is map[string][]string.
		svc := m["service"].(map[string]any)
		pipelines := svc["pipelines"].(map[string]any)
		pipe := pipelines["logs/_agent-component/filestream-default"].(map[string][]string)
		assert.NotContains(t, pipe, "processors")
	})

	t.Run("per-output add_host_metadata:false removes only that processor", func(t *testing.T) {
		comp := testFilebeatComp("filestream-default", "default", map[string]any{
			"default_processors": map[string]any{
				"add_host_metadata": false,
			},
		})
		model := &component.Model{Components: []component.Component{comp}}
		conf, err := GetOtelConfig(model, agentInfo, logp.NewNopLogger())
		require.NoError(t, err)

		names := processorNamesFromOtelConfig(t, conf, "filestream-default")
		require.NotNil(t, names)
		assert.NotContains(t, names, "add_host_metadata")
		assert.Contains(t, names, "add_cloud_metadata")
		assert.Contains(t, names, "add_docker_metadata")
		assert.Contains(t, names, "add_kubernetes_metadata")
	})

	t.Run("per-output default_processors does not affect other output components", func(t *testing.T) {
		// compA disables add_cloud_metadata for its output; compB has no restriction.
		compA := testFilebeatComp("filestream-outputA", "outputA", map[string]any{
			"default_processors": map[string]any{"add_cloud_metadata": false},
		})
		compB := testFilebeatComp("filestream-outputB", "outputB")

		model := &component.Model{Components: []component.Component{compA, compB}}
		conf, err := GetOtelConfig(model, agentInfo, logp.NewNopLogger())
		require.NoError(t, err)

		namesA := processorNamesFromOtelConfig(t, conf, "filestream-outputA")
		require.NotNil(t, namesA)
		assert.NotContains(t, namesA, "add_cloud_metadata", "compA should not have add_cloud_metadata")
		assert.Contains(t, namesA, "add_host_metadata", "compA should still have add_host_metadata")

		namesB := processorNamesFromOtelConfig(t, conf, "filestream-outputB")
		require.NotNil(t, namesB)
		assert.Contains(t, namesB, "add_cloud_metadata", "compB should still have add_cloud_metadata")
	})

	t.Run("per-output cannot re-enable globally disabled processor", func(t *testing.T) {
		applyDefaultProcessorFlags(t, features.DefaultProcessors{
			AddHostMetadata: false, AddCloudMetadata: true,
			AddDockerMetadata: true, AddKubernetesMetadata: true,
		})
		comp := testFilebeatComp("filestream-default", "default", map[string]any{
			"default_processors": map[string]any{
				"add_host_metadata": true, // attempt to re-enable globally disabled processor
			},
		})
		model := &component.Model{Components: []component.Component{comp}}
		conf, err := GetOtelConfig(model, agentInfo, logp.NewNopLogger())
		require.NoError(t, err)

		names := processorNamesFromOtelConfig(t, conf, "filestream-default")
		require.NotNil(t, names)
		assert.NotContains(t, names, "add_host_metadata", "globally disabled processor should not be re-enabled per-output")
		assert.Contains(t, names, "add_cloud_metadata")
	})
}

func TestGetReceiversConfigForComponent(t *testing.T) {
	testAgentInfo := &info.AgentInfo{}

	// Create proper component configurations that match existing test patterns
	filebeatComponent := &component.Component{
		ID:        "filebeat-test-id",
		InputType: "filestream",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
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
			BinaryName: "elastic-otel-collector",
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

	auditbeatComponent := &component.Component{
		ID:        "auditbeat-test-id",
		InputType: "audit/auditd",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "audit/auditd",
				Command: &component.CommandSpec{
					Args: []string{"auditbeat"},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "auditbeat-test-id-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"id":         "test",
					"use_output": "default",
					"type":       "audit/auditd",
					"streams": []any{
						map[string]any{
							"id": "test-1",
							"data_stream": map[string]any{
								"dataset": "generic-1",
							},
							"audit_rules": "-a exit,always -F arch=b64 -S open",
						},
					},
				}),
			},
		},
	}

	heartbeatComponent := &component.Component{
		ID:        "heartbeat-test-id",
		InputType: "synthetics/http",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "synthetics/http",
				Command: &component.CommandSpec{
					Args: []string{"heartbeat"},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "heartbeat-test-id-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"id":         "test",
					"use_output": "default",
					"type":       "synthetics/http",
					"streams": []any{
						map[string]any{
							"id": "test-1",
							"data_stream": map[string]any{
								"dataset": "generic-1",
							},
							"urls":     []any{"https://example.com"},
							"schedule": "@every 5s",
						},
					},
				}),
			},
		},
	}

	osquerybeatComponent := &component.Component{
		ID:        "osquerybeat-test-id",
		InputType: "osquery",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "osquery",
				Command: &component.CommandSpec{
					Args: []string{"osquerybeat"},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "osquerybeat-test-id-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"id":         "test",
					"use_output": "default",
					"type":       "osquery",
					"streams": []any{
						map[string]any{
							"id": "test-1",
							"data_stream": map[string]any{
								"dataset": "generic-1",
							},
							"query": "SELECT * FROM processes",
						},
					},
				}),
			},
		},
	}

	// osquerybeat with two streams and single_receiver: true, matching the real osquery_manager setup.
	osquerybeatSingleReceiverComponent := &component.Component{
		ID:        "osquerybeat-test-id",
		InputType: "osquery",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "osquery",
				Command: &component.CommandSpec{
					Args: []string{"osquerybeat"},
				},
				SingleReceiver: true,
			},
		},
		Units: []component.Unit{
			{
				ID:   "osquerybeat-test-id-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"id":         "test",
					"use_output": "default",
					"type":       "osquery",
					"streams": []any{
						map[string]any{
							"id": "action-responses",
							"data_stream": map[string]any{
								"dataset": "osquery_manager.action.responses",
							},
							"query": nil,
						},
						map[string]any{
							"id": "results",
							"data_stream": map[string]any{
								"dataset": "osquery_manager.result",
							},
							"query":    "SELECT * FROM processes",
							"interval": "3600",
						},
					},
					"osquery": map[string]any{
						"schedule": map[string]any{
							"system_info": map[string]any{
								"query":    "SELECT hostname FROM system_info",
								"interval": 60,
							},
						},
						"decorators": map[string]any{
							"load": []any{
								"SELECT uuid AS host_uuid FROM system_info;",
							},
						},
					},
				}),
			},
		},
	}

	// osquerybeat with single_receiver but without an "osquery" key (no scheduled queries
	// or packs configured — live-query-only policy). The result stream must still be
	// placed first so publisher.Configure routes live-query result rows correctly.
	// Regression test for https://github.com/elastic/elastic-agent/issues/15601.
	osquerybeatSingleReceiverNoOsqueryKeyComponent := &component.Component{
		ID:        "osquerybeat-test-id",
		InputType: "osquery",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "osquery",
				Command: &component.CommandSpec{
					Args: []string{"osquerybeat"},
				},
				SingleReceiver: true,
			},
		},
		Units: []component.Unit{
			{
				ID:   "osquerybeat-test-id-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"id":         "test",
					"use_output": "default",
					"type":       "osquery",
					"streams": []any{
						map[string]any{
							"id": "action-responses",
							"data_stream": map[string]any{
								"dataset": "osquery_manager.action.responses",
							},
							"query": nil,
						},
						map[string]any{
							"id": "results",
							"data_stream": map[string]any{
								"dataset": "osquery_manager.result",
							},
						},
					},
					// Intentionally no "osquery" key — simulates a live-query-only policy
					// with no scheduled queries or packs.
				}),
			},
		},
	}

	// osquerybeat with single_receiver and a custom namespace set at the unit level.
	osquerybeatCustomNamespaceComponent := &component.Component{
		ID:        "osquerybeat-test-id",
		InputType: "osquery",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "osquery",
				Command: &component.CommandSpec{
					Args: []string{"osquerybeat"},
				},
				SingleReceiver: true,
			},
		},
		Units: []component.Unit{
			{
				ID:   "osquerybeat-test-id-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"id":         "test",
					"use_output": "default",
					"type":       "osquery",
					"data_stream": map[string]any{
						"namespace": "custom-ns",
					},
					"streams": []any{
						map[string]any{
							"id": "action-responses",
							"data_stream": map[string]any{
								"dataset": "osquery_manager.action.responses",
							},
							"query": nil,
						},
						map[string]any{
							"id": "results",
							"data_stream": map[string]any{
								"dataset": "osquery_manager.result",
							},
							"query":    "SELECT * FROM processes",
							"interval": "3600",
						},
					},
					"osquery": map[string]any{
						"schedule": map[string]any{
							"process_list": map[string]any{
								"query":    "SELECT * FROM processes",
								"interval": 60,
							},
						},
					},
				}),
			},
		},
	}

	packetbeatComponent := &component.Component{
		ID:        "packetbeat-test-id",
		InputType: "packet",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "packet",
				Command: &component.CommandSpec{
					Args: []string{"packetbeat"},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "packetbeat-test-id-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"id":         "test",
					"use_output": "default",
					"type":       "packet",
					"streams": []any{
						map[string]any{
							"id": "test-1",
							"data_stream": map[string]any{
								"dataset": "generic-1",
							},
							"ports": []any{443},
						},
					},
				}),
			},
		},
	}

	tests := []struct {
		name               string
		component          *component.Component
		outputQueueConfig  map[string]any
		expectedError      string
		expectedReceiverID string // full receiver ID, empty for no-inputs case
		expectedBeatName   string
		verifyBeatConfig   func(t *testing.T, beatConfig map[string]any)
	}{
		{
			name:               "filebeat component",
			component:          filebeatComponent,
			outputQueueConfig:  nil,
			expectedReceiverID: "filebeatreceiver/_agent-component/filebeat-test-id/test-1",
			expectedBeatName:   "filebeat",
		},
		{
			name:      "metricbeat component with queue config",
			component: metricbeatComponent,
			outputQueueConfig: map[string]any{
				"type": "memory",
				"size": 1000,
			},
			expectedReceiverID: "metricbeatreceiver/_agent-component/metricbeat-test-id/test-1",
			expectedBeatName:   "metricbeat",
		},
		{
			name:               "auditbeat component",
			component:          auditbeatComponent,
			outputQueueConfig:  nil,
			expectedReceiverID: "auditbeatreceiver/_agent-component/auditbeat-test-id/test-1",
			expectedBeatName:   "auditbeat",
			verifyBeatConfig: func(t *testing.T, beatConfig map[string]any) {
				modules, ok := beatConfig["modules"].([]map[string]any)
				require.True(t, ok, "auditbeat modules should be a slice of maps")
				require.NotEmpty(t, modules, "auditbeat modules should not be empty")
				for i, mod := range modules {
					assert.Equal(t, "auditd", mod["module"], "auditbeat module[%d] must have module=auditd", i)
				}
			},
		},
		{
			name:               "heartbeat component",
			component:          heartbeatComponent,
			outputQueueConfig:  nil,
			expectedReceiverID: "heartbeatreceiver/_agent-component/heartbeat-test-id/test-1",
			expectedBeatName:   "heartbeat",
		},
		{
			name:               "osquerybeat component",
			component:          osquerybeatComponent,
			outputQueueConfig:  nil,
			expectedReceiverID: "osquerybeatreceiver/_agent-component/osquerybeat-test-id/test-1",
			expectedBeatName:   "osquerybeat",
		},
		{
			name:               "osquerybeat component with single_receiver merges streams",
			component:          osquerybeatSingleReceiverComponent,
			outputQueueConfig:  nil,
			expectedReceiverID: "osquerybeatreceiver/_agent-component/osquerybeat-test-id/single",
			expectedBeatName:   "osquerybeat",
			verifyBeatConfig: func(t *testing.T, beatConfig map[string]any) {
				inputs, ok := beatConfig["inputs"].([]map[string]any)
				require.True(t, ok, "osquerybeat inputs should be a slice of maps")
				require.Len(t, inputs, 2, "both streams must be merged into the single receiver")

				// The result stream must be placed first so inputs[0].Osquery is non-nil
				// when config_plugin reads it at beat startup.
				assert.Equal(t, "results", inputs[0]["id"], "osquery_manager.result stream must be first")

				// Only the result stream gets the osquery section injected from the input level.
				resultInput := inputs[0]
				osquery, ok := resultInput["osquery"]
				require.True(t, ok, "inputs[0] (result stream) must have osquery section injected from input level")
				osqueryMap, ok := osquery.(map[string]any)
				require.True(t, ok, "inputs[0].osquery must be a map")
				schedule, ok := osqueryMap["schedule"]
				assert.True(t, ok, "inputs[0].osquery must have schedule")
				scheduleMap, ok := schedule.(map[string]any)
				assert.True(t, ok, "inputs[0].osquery.schedule must be a map (query name → definition)")
				assert.Contains(t, scheduleMap, "system_info", "inputs[0].osquery.schedule must have system_info query")
				assert.Contains(t, osqueryMap, "decorators", "inputs[0].osquery must have decorators")

				// The action-responses stream must NOT have osquery injected.
				actionInput := inputs[1]
				_, hasOsquery := actionInput["osquery"]
				assert.False(t, hasOsquery, "action-responses stream must not have osquery injected")
			},
		},
		{
			name:               "osquerybeat single_receiver without osquery key still puts result stream first",
			component:          osquerybeatSingleReceiverNoOsqueryKeyComponent,
			outputQueueConfig:  nil,
			expectedReceiverID: "osquerybeatreceiver/_agent-component/osquerybeat-test-id/single",
			expectedBeatName:   "osquerybeat",
			verifyBeatConfig: func(t *testing.T, beatConfig map[string]any) {
				inputs, ok := beatConfig["inputs"].([]map[string]any)
				require.True(t, ok, "osquerybeat inputs should be a slice of maps")
				require.Len(t, inputs, 2, "both streams must be merged into the single receiver")

				// Even without an "osquery" key, the result stream must be at position 0.
				// If action.responses were first, live-query result rows would be routed to the wrong data stream.
				assert.Equal(t, "results", inputs[0]["id"], "osquery_manager.result stream must be first even without osquery key")

				_, hasOsquery := inputs[0]["osquery"]
				assert.False(t, hasOsquery, "no osquery section should be injected when key is absent from unit config")
			},
		},
		{
			name:               "osquerybeat single_receiver propagates custom namespace to all streams",
			component:          osquerybeatCustomNamespaceComponent,
			outputQueueConfig:  nil,
			expectedReceiverID: "osquerybeatreceiver/_agent-component/osquerybeat-test-id/single",
			expectedBeatName:   "osquerybeat",
			verifyBeatConfig: func(t *testing.T, beatConfig map[string]any) {
				inputs, ok := beatConfig["inputs"].([]map[string]any)
				require.True(t, ok, "osquerybeat inputs should be a slice of maps")
				require.Len(t, inputs, 2, "both streams must be merged into the single receiver")

				assert.Equal(t, "results", inputs[0]["id"], "osquery_manager.result stream must be first")

				// osquery section must be injected into the result stream (not action-responses).
				_, hasOsquery := inputs[0]["osquery"]
				assert.True(t, hasOsquery, "inputs[0] (result stream) must have osquery section injected")
				_, hasOsquery = inputs[1]["osquery"]
				assert.False(t, hasOsquery, "inputs[1] (action-responses) must not have osquery section")

				for i, inp := range inputs {
					ds, ok := inp["data_stream"].(map[string]any)
					require.True(t, ok, "inputs[%d] must have a data_stream map", i)
					assert.Equal(t, "custom-ns", ds["namespace"],
						"inputs[%d] data_stream.namespace must be the unit-level custom namespace, not the default", i)
				}
			},
		},
		{
			name:               "packetbeat component",
			component:          packetbeatComponent,
			outputQueueConfig:  nil,
			expectedReceiverID: "packetbeatreceiver/_agent-component/packetbeat-test-id/test-1",
			expectedBeatName:   "packetbeat",
		},
		{
			name: "component with no input units",
			component: &component.Component{
				ID:        "no-inputs-test-id",
				InputType: "filestream",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "elastic-otel-collector",
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
			outputQueueConfig: nil,
			// No expectedReceiverID - no inputs means no receivers
		},
		{
			name: "input unit with nil config is skipped without panic",
			component: &component.Component{
				ID:        "nil-config-test-id",
				InputType: "filestream",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "elastic-otel-collector",
					Spec: component.InputSpec{
						Name: "filestream",
						Command: &component.CommandSpec{
							Args: []string{"filebeat"},
						},
					},
				},
				Units: []component.Unit{
					{
						ID:     "input-unit",
						Type:   client.UnitTypeInput,
						Config: nil,
					},
					{
						ID:   "output-unit",
						Type: client.UnitTypeOutput,
						Config: component.MustExpectedConfig(map[string]any{
							"type": "elasticsearch",
						}),
					},
				},
			},
			outputQueueConfig: nil,
			// No expectedReceiverID - nil config input is skipped
		},
		{
			name: "unsupported component type",
			component: &component.Component{
				ID:        "unsupported-test-id",
				InputType: "unsupported",
			},
			outputQueueConfig: nil,
			expectedError:     "unknown otel receiver type for input type: unsupported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getReceiversConfigForComponent(
				tt.component,
				testAgentInfo,
				tt.outputQueueConfig,
				GetDefaultProcessors(tt.component.BeatName()),
			)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.ErrorContains(t, err, tt.expectedError)
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
			assert.NotNil(t, result)

			// Component with no inputs produces no receivers
			if tt.expectedReceiverID == "" {
				assert.Empty(t, result)
				return
			}

			// Verify the receiver ID is present
			assert.Contains(t, result, tt.expectedReceiverID)

			receiverConfig, ok := result[tt.expectedReceiverID].(map[string]any)
			assert.True(t, ok, "receiver config should be a map")

			// Verify configuration section presence
			assert.Contains(t, receiverConfig, "path", "path config should be present")
			assert.Contains(t, receiverConfig, "logging", "logging config should be present")
			assert.Contains(t, receiverConfig, tt.expectedBeatName, fmt.Sprintf("%s config should be present", tt.expectedBeatName))

			// Verify queue configuration presence
			if tt.outputQueueConfig != nil {
				assert.Contains(t, receiverConfig, "queue", "queue config should be present")
			} else {
				assert.NotContains(t, receiverConfig, "queue", "queue config should not be present")
			}

			// Verify HTTP monitoring is disabled for OTel-managed beat receivers
			assert.Contains(t, receiverConfig, "http", "http monitoring config should be present")
			httpConfig, ok := receiverConfig["http"].(map[string]any)
			require.True(t, ok, "http config should be a map")
			assert.Equal(t, false, httpConfig["enabled"], "http monitoring should be disabled for OTel-managed components")

			// Run any beat-specific assertions
			if tt.verifyBeatConfig != nil {
				beatConfig, ok := receiverConfig[tt.expectedBeatName].(map[string]any)
				require.True(t, ok, "%s config should be a map", tt.expectedBeatName)
				tt.verifyBeatConfig(t, beatConfig)
			}
		})
	}
}

// TestGetReceiversConfigForComponentBrowserMonitor verifies that a Synthetics browser
// monitor, which compiles into a single synthetics/browser input with a scheduled
// "browser" stream plus schedule-less "browser.network" and "browser.screenshot"
// auxiliary streams, produces exactly one heartbeat monitor. The auxiliary streams
// must be dropped so the heartbeatreceiver does not reject them for missing a schedule.
// Regression test for https://github.com/elastic/elastic-agent/issues/15968.
func TestGetReceiversConfigForComponentBrowserMonitor(t *testing.T) {
	testAgentInfo := &info.AgentInfo{}

	browserComponent := &component.Component{
		ID:        "heartbeat-browser-test-id",
		InputType: "synthetics/browser",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "synthetics/browser",
				Command: &component.CommandSpec{
					Args: []string{"heartbeat"},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "heartbeat-browser-test-id-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"id":         "test",
					"use_output": "default",
					"type":       "synthetics/browser",
					"streams": []any{
						map[string]any{
							"id":   "browser-1",
							"type": "browser",
							"data_stream": map[string]any{
								"dataset": "browser",
								"type":    "synthetics",
							},
							"schedule": "@every 3m",
						},
						map[string]any{
							"id": "browser-network-1",
							"data_stream": map[string]any{
								"dataset": "browser.network",
								"type":    "synthetics",
							},
						},
						map[string]any{
							"id": "browser-screenshot-1",
							"data_stream": map[string]any{
								"dataset": "browser.screenshot",
								"type":    "synthetics",
							},
						},
					},
				}),
			},
		},
	}

	result, err := getReceiversConfigForComponent(browserComponent, testAgentInfo, nil, nil)
	require.NoError(t, err)

	// Only the scheduled "browser" stream must become a receiver/monitor; the
	// schedule-less auxiliary streams must be dropped.
	require.Len(t, result, 1, "only the scheduled browser stream should produce a receiver")

	scheduledReceiverID := "heartbeatreceiver/_agent-component/heartbeat-browser-test-id/browser-1"
	require.Contains(t, result, scheduledReceiverID)
	assert.NotContains(t, result, "heartbeatreceiver/_agent-component/heartbeat-browser-test-id/browser-network-1")
	assert.NotContains(t, result, "heartbeatreceiver/_agent-component/heartbeat-browser-test-id/browser-screenshot-1")

	receiverConfig, ok := result[scheduledReceiverID].(map[string]any)
	require.True(t, ok, "receiver config should be a map")
	heartbeatConfig, ok := receiverConfig["heartbeat"].(map[string]any)
	require.True(t, ok, "heartbeat config should be a map")
	monitors, ok := heartbeatConfig["monitors"].([]map[string]any)
	require.True(t, ok, "heartbeat monitors should be a slice of maps")
	require.Len(t, monitors, 1, "exactly one monitor should be emitted")
	assert.Equal(t, "@every 3m", monitors[0]["schedule"], "the emitted monitor must carry the schedule")
	assert.Equal(t, "browser", monitors[0]["type"], "the emitted monitor must be the browser stream")
}

func TestGetInputsForUnitSyntheticsAPI(t *testing.T) {
	unit := component.Unit{
		ID:   "heartbeat-api-test-unit",
		Type: client.UnitTypeInput,
		Config: component.MustExpectedConfig(map[string]any{
			"id":         "test",
			"use_output": "default",
			"type":       "synthetics/api",
			"streams": []any{
				map[string]any{
					"id": "test-1",
					"data_stream": map[string]any{
						"dataset": "generic-1",
					},
					"schedule": "@every 5s",
				},
			},
		}),
	}
	comp := &component.Component{InputType: "synthetics/api"}

	inputs, err := getInputsForUnit(unit, &info.AgentInfo{}, "logs", comp, nil)
	require.NoError(t, err)
	require.Len(t, inputs, 1)
	assert.Equal(t, "api", inputs[0].config["type"])
}

// TestKeepScheduledMonitors verifies the schedule-based filtering used to drop
// auxiliary Synthetics browser sub-streams, including the malformed-config fallback.
func TestKeepScheduledMonitors(t *testing.T) {
	scheduled := receiverInput{streamID: "browser-1", config: map[string]any{"schedule": "@every 3m"}}
	network := receiverInput{streamID: "browser-network-1", config: map[string]any{}}
	screenshot := receiverInput{streamID: "browser-screenshot-1", config: map[string]any{"schedule": nil}}

	t.Run("drops schedule-less streams", func(t *testing.T) {
		got := keepScheduledMonitors([]receiverInput{scheduled, network, screenshot})
		require.Len(t, got, 1)
		assert.Equal(t, "browser-1", got[0].streamID)
	})

	t.Run("returns inputs unchanged when none are scheduled", func(t *testing.T) {
		in := []receiverInput{network, screenshot}
		got := keepScheduledMonitors(in)
		assert.Equal(t, in, got)
	})
}

// TestGetReceiversConfigForComponentFeatures verifies that all agent feature flags
// are propagated into the generated Beat receiver config.
func TestGetReceiversConfigForComponentFeatures(t *testing.T) {
	comp := &component.Component{
		ID:        "filestream-features",
		InputType: "filestream",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "filestream",
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

	featureFlags, err := features.Parse(map[string]any{
		"agent": map[string]any{
			"features": map[string]any{
				"fqdn": map[string]any{
					"enabled": false,
				},
				"log_input_run_as_filestream": map[string]any{
					"enabled": true,
				},
				"aws_s3_v2": map[string]any{
					"enabled": true,
				},
			},
		},
	})
	require.NoError(t, err)
	comp.Features = featureFlags.AsProto()
	// The raw source is the only propagation path; the typed FQDN value must
	// not override the value preserved in agent.features.
	comp.Features.Fqdn.Enabled = true

	result, err := getReceiversConfigForComponent(comp, &info.AgentInfo{}, nil, GetDefaultProcessors(comp.BeatName()))
	require.NoError(t, err)
	require.Len(t, result, 1)

	var receiverConfig map[string]any
	for _, value := range result {
		receiverConfig = value.(map[string]any)
	}
	require.Equal(t, map[string]any{
		"fqdn": map[string]any{
			"enabled": false,
		},
		"log_input_run_as_filestream": map[string]any{
			"enabled": true,
		},
		"aws_s3_v2": map[string]any{
			"enabled": true,
		},
	}, receiverConfig["features"])
	require.Equal(t, false, comp.Features.Source.AsMap()["agent"].(map[string]any)["features"].(map[string]any)["fqdn"].(map[string]any)["enabled"],
		"building receiver config must not mutate the component feature source")
}

func TestGetReceiversConfigForComponentWithoutFeatures(t *testing.T) {
	comp := &component.Component{
		ID:        "filestream-no-features",
		InputType: "filestream",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "filestream",
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
							"id":    "test-1",
							"paths": []any{"/var/log/*.log"},
						},
					},
				}),
			},
		},
	}

	result, err := getReceiversConfigForComponent(comp, &info.AgentInfo{}, nil, GetDefaultProcessors(comp.BeatName()))
	require.NoError(t, err)
	require.Len(t, result, 1)
	for _, value := range result {
		require.NotContains(t, value.(map[string]any), "features")
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
				OutputName: "default",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "elastic-otel-collector",
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
			name: "supported output type - kafka",
			component: &component.Component{
				ID:         "unsupported-output",
				InputType:  "filestream",
				OutputType: "kafka",
				OutputName: "default",
			},
		},
		{
			name: "unsupported configuration",
			component: &component.Component{
				ID:         "unsupported-config",
				InputType:  "filestream",
				OutputType: "elasticsearch",
				OutputName: "default",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "elastic-otel-collector",
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
		{
			name: "input unit with nil config does not panic",
			component: &component.Component{
				ID:         "nil-config-comp",
				InputType:  "filestream",
				OutputType: "elasticsearch",
				OutputName: "default",
				InputSpec: &component.InputRuntimeSpec{
					BinaryName: "elastic-otel-collector",
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
						Config: nil,
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

func TestVerifyOutputIsOtelSupported(t *testing.T) {
	tests := []struct {
		name          string
		outputType    string
		outputCfg     map[string]any
		expectedError string
	}{
		{
			name:       "supported output - elasticsearch",
			outputType: "elasticsearch",
			outputCfg: map[string]any{
				"type":  "elasticsearch",
				"hosts": []any{"localhost:9200"},
			},
		},
		{
			name:       "supported output type - kafka",
			outputType: "kafka",
			outputCfg:  map[string]any{},
		},
		{
			name:       "unsupported configuration - indices field",
			outputType: "elasticsearch",
			outputCfg: map[string]any{
				"type":    "elasticsearch",
				"hosts":   []any{"localhost:9200"},
				"indices": []any{},
			},
			expectedError: "unsupported configuration for elasticsearch:",
		},
		{
			name:       "unsupported configuration - negative retries",
			outputType: "elasticsearch",
			outputCfg: map[string]any{
				"type":        "elasticsearch",
				"hosts":       []any{"localhost:9200"},
				"max_retries": -1,
			},
			expectedError: "unsupported configuration for elasticsearch:",
		},
		{
			name:       "supported configuration - 0 retries",
			outputType: "elasticsearch",
			outputCfg: map[string]any{
				"type":        "elasticsearch",
				"hosts":       []any{"localhost:9200"},
				"max_retries": 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyOutputIsOtelSupported(tt.outputType, tt.outputCfg)
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestUnitToExporterConfig(t *testing.T) {
	logger := logp.NewNopLogger()
	esExporterType := otelcomponent.MustNewType("elasticsearch")
	kafkaExporterType := otelcomponent.MustNewType("kafka")
	unsupportedExporterType := otelcomponent.MustNewType("unsupported")

	// Mock translation function
	originalConfigTranslationFuncForExporter := configTranslationFuncForExporter
	defer func() { configTranslationFuncForExporter = originalConfigTranslationFuncForExporter }()
	configTranslationFuncForExporter = map[otelcomponent.Type]exporterConfigTranslationFunc{
		esExporterType: func(c *config.C, _ string, l *logp.Logger) (map[string]any, map[string]any, map[string]any, error) {
			if c.HasField("unsupported") {
				return nil, nil, nil, errors.New("unsupported config")
			}
			// Simple translation for testing purposes
			cfgMap := make(map[string]any)
			if err := c.Unpack(&cfgMap); err != nil {
				return nil, nil, nil, err
			}

			cfgMap["translated"] = true

			// Perform beats auth extension translation
			cfgMap["auth"] = map[string]any{
				"authenticator": "beatsauth/_agent-component/default",
			}

			// return extension config
			beatsAuthCfg, err := getBeatsAuthExtensionConfig(c)
			if err != nil {
				return nil, nil, nil, err
			}

			extensionConfig := make(map[string]any)
			extensionConfig[getBeatsAuthExtensionID("default").String()] = beatsAuthCfg

			return cfgMap, nil, extensionConfig, nil
		},
		kafkaExporterType: KafkaToOTelConfig,
	}

	tests := []struct {
		name                  string
		unit                  component.Unit
		exporterType          otelcomponent.Type
		outputName            string
		expectedExporterCfg   map[string]any
		expectedQueueSettings map[string]any
		expectedExtensionCfg  map[string]any
		expectedError         string
	}{
		{
			name:          "error on input unit type",
			unit:          component.Unit{ID: "input-unit", Type: client.UnitTypeInput},
			exporterType:  esExporterType,
			outputName:    "default",
			expectedError: "unit type is an input, expected output",
		},
		{
			name: "error on unsupported exporter type",
			unit: component.Unit{
				ID:     "output-unit",
				Type:   client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{"type": "elasticsearch"}),
			},
			exporterType:  unsupportedExporterType,
			outputName:    "default",
			expectedError: "no config translation function for exporter type: unsupported",
		},
		{
			name: "error from translation function",
			unit: component.Unit{
				ID:     "filestream-default",
				Type:   client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{"unsupported": true}),
			},
			exporterType:  esExporterType,
			outputName:    "default",
			expectedError: "unsupported config",
		},
		{
			name: "success with basic config",
			unit: component.Unit{
				ID:     "filestream-default",
				Type:   client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{"hosts": []any{"es:9200"}}),
			},
			exporterType: esExporterType,
			outputName:   "default",
			expectedExporterCfg: map[string]any{
				"hosts":      []interface{}{"es:9200"},
				"translated": true,
				"auth": map[string]any{
					"authenticator": "beatsauth/_agent-component/default",
				},
			},
			expectedQueueSettings: nil,
			expectedExtensionCfg: map[string]any{
				"beatsauth/_agent-component/default": map[string]any{
					"continue_on_error":       true,
					"idle_connection_timeout": "3s",
					"proxy_disable":           false,
					"timeout":                 "1m30s",
				},
			},
		},
		{
			name: "success with queue settings",
			unit: component.Unit{
				ID:   "filestream-default",
				Type: client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{
					"hosts": []any{"es:9200"},
					"queue": map[string]any{"mem": map[string]any{"events": 100, "flush": map[string]any{
						"timeout": "20s",
					}}},
				}),
			},
			exporterType: esExporterType,
			outputName:   "default",
			expectedExporterCfg: map[string]any{
				"hosts": []interface{}{"es:9200"},
				"queue": map[string]any{"mem": map[string]any{
					"events": float64(100),
					"flush": map[string]any{
						"timeout": "20s",
					},
				}},
				"translated": true,
				"auth": map[string]any{
					"authenticator": "beatsauth/_agent-component/default",
				},
			},
			expectedQueueSettings: map[string]any{"mem": map[string]any{"events": float64(100), "flush": map[string]any{
				"timeout": "20s",
			}}},
			expectedExtensionCfg: map[string]any{
				"beatsauth/_agent-component/default": map[string]any{
					"continue_on_error":       true,
					"idle_connection_timeout": "3s",
					"proxy_disable":           false,
					"timeout":                 "1m30s",
				},
			},
		},
		{
			name: "success with otel override",
			unit: component.Unit{
				ID:   "filestream-default",
				Type: client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{
					"hosts": []any{"es:9200"},
					"otel": map[string]any{
						"exporter": map[string]any{"hosts": []any{}},
					},
				}),
			},
			exporterType: esExporterType,
			outputName:   "default",
			expectedExporterCfg: map[string]any{
				"hosts":      []any{}, // from override
				"translated": true,
				"auth": map[string]any{
					"authenticator": "beatsauth/_agent-component/default",
				},
			},
			expectedQueueSettings: nil,
			expectedExtensionCfg: map[string]any{
				"beatsauth/_agent-component/default": map[string]any{
					"continue_on_error":       true,
					"idle_connection_timeout": "3s",
					"proxy_disable":           false,
					"timeout":                 "1m30s",
				},
			},
		},
		{
			name: "success with otel extensions override",
			unit: component.Unit{
				ID:   "filestream-default",
				Type: client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{
					"hosts": []any{"es:9200"},
					"otel": map[string]any{
						"extensions": map[string]any{
							"beatsauth": map[string]any{
								"timeout": "5m",
							},
						},
					},
				}),
			},
			exporterType: esExporterType,
			outputName:   "default",
			expectedExporterCfg: map[string]any{
				"hosts":      []interface{}{"es:9200"},
				"translated": true,
				"auth": map[string]any{
					"authenticator": "beatsauth/_agent-component/default",
				},
			},
			expectedQueueSettings: nil,
			expectedExtensionCfg: map[string]any{
				"beatsauth/_agent-component/default": map[string]any{
					"continue_on_error":       true,
					"idle_connection_timeout": "3s",
					"proxy_disable":           false,
					"timeout":                 "5m",
				},
			},
		},
		{
			name: "kafka output with hash partition adds kafkapartitioner extension",
			unit: component.Unit{
				ID:   "kafka-default",
				Type: client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{
					"hosts": []any{"127.0.0.1:9092"},
					"topic": "my-topic",
					"partition": map[string]any{
						"hash": map[string]any{
							"hash":   "fields",
							"fields": []any{"log.level"},
						},
					},
				}),
			},
			exporterType: kafkaExporterType,
			outputName:   "default",
			expectedExporterCfg: map[string]any{
				"brokers":   []string{"127.0.0.1:9092"},
				"client_id": "beats",
				"logs": map[string]any{
					"topic":    "my-topic",
					"encoding": "raw",
				},
				"metadata": map[string]any{
					"refresh_interval": 10 * time.Minute,
				},
				"producer": map[string]any{
					"compression": "gzip",
					"compression_params": map[string]any{
						"level": 4,
					},
					"max_message_bytes": 1000000,
					"required_acks":     1,
				},
				"protocol_version": "2.1.0",
				"retry_on_failure": map[string]any{
					"initial_interval": 1 * time.Second,
					"max_interval":     60 * time.Second,
				},
				"sending_queue": map[string]any{
					"batch": map[string]any{
						"flush_timeout": "10s",
						"max_size":      2048,
						"min_size":      1600,
						"sizer":         "items",
					},
					"queue_size": 3200,
				},
				"timeout": 10 * time.Second,
				"record_partitioner": map[string]any{
					"extension": "kafkapartitioner/_agent-component/default",
				},
			},
			expectedQueueSettings: nil,
			expectedExtensionCfg: map[string]any{
				"kafkapartitioner/_agent-component/default": map[string]interface{}{
					"hash": map[string]interface{}{
						"hash":   "fields",
						"fields": []interface{}{"log.level"},
					},
				},
			},
		},
		{
			name: "kafka output with round_robin partition adds kafkapartitioner extension",
			unit: component.Unit{
				ID:   "kafka-default",
				Type: client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{
					"hosts": []any{"127.0.0.1:9092"},
					"topic": "my-topic",
					"partition": map[string]any{
						"round_robin": map[string]any{
							"group_events": 10,
						},
					},
				}),
			},
			exporterType: kafkaExporterType,
			outputName:   "default",
			expectedExporterCfg: map[string]any{
				"brokers":   []string{"127.0.0.1:9092"},
				"client_id": "beats",
				"logs": map[string]any{
					"topic":    "my-topic",
					"encoding": "raw",
				},
				"metadata": map[string]any{
					"refresh_interval": 10 * time.Minute,
				},
				"producer": map[string]any{
					"compression": "gzip",
					"compression_params": map[string]any{
						"level": 4,
					},
					"max_message_bytes": 1000000,
					"required_acks":     1,
				},
				"protocol_version": "2.1.0",
				"retry_on_failure": map[string]any{
					"initial_interval": 1 * time.Second,
					"max_interval":     60 * time.Second,
				},
				"sending_queue": map[string]any{
					"batch": map[string]any{
						"flush_timeout": "10s",
						"max_size":      2048,
						"min_size":      1600,
						"sizer":         "items",
					},
					"queue_size": 3200,
				},
				"timeout": 10 * time.Second,
				"record_partitioner": map[string]any{
					"extension": "kafkapartitioner/_agent-component/default",
				},
			},
			expectedQueueSettings: nil,
			expectedExtensionCfg: map[string]any{
				"kafkapartitioner/_agent-component/default": map[string]interface{}{
					"round_robin": map[string]interface{}{
						"group_events": float64(10),
					},
				},
			},
		},
		{
			name: "kafka output with random partition adds kafkapartitioner extension",
			unit: component.Unit{
				ID:   "kafka-default",
				Type: client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{
					"hosts": []any{"127.0.0.1:9092"},
					"topic": "my-topic",
					"partition": map[string]any{
						"random": map[string]any{
							"group_events": 1,
						},
					},
				}),
			},
			exporterType: kafkaExporterType,
			outputName:   "default",
			expectedExporterCfg: map[string]any{
				"brokers":   []string{"127.0.0.1:9092"},
				"client_id": "beats",
				"logs": map[string]any{
					"topic":    "my-topic",
					"encoding": "raw",
				},
				"metadata": map[string]any{
					"refresh_interval": 10 * time.Minute,
				},
				"producer": map[string]any{
					"compression": "gzip",
					"compression_params": map[string]any{
						"level": 4,
					},
					"max_message_bytes": 1000000,
					"required_acks":     1,
				},
				"protocol_version": "2.1.0",
				"retry_on_failure": map[string]any{
					"initial_interval": 1 * time.Second,
					"max_interval":     60 * time.Second,
				},
				"sending_queue": map[string]any{
					"batch": map[string]any{
						"flush_timeout": "10s",
						"max_size":      2048,
						"min_size":      1600,
						"sizer":         "items",
					},
					"queue_size": 3200,
				},
				"timeout": 10 * time.Second,
				"record_partitioner": map[string]any{
					"extension": "kafkapartitioner/_agent-component/default",
				},
			},
			expectedQueueSettings: nil,
			expectedExtensionCfg: map[string]any{
				"kafkapartitioner/_agent-component/default": map[string]interface{}{
					"random": map[string]interface{}{
						"group_events": float64(1),
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exportersCfg, queueSettings, extensionCfg, processorConfig, err := unitToExporterConfig(tt.unit, tt.outputName, tt.exporterType, logger)

			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.expectedExporterCfg, exportersCfg)
			assert.Equal(t, tt.expectedQueueSettings, queueSettings)
			assert.Equal(t, tt.expectedExtensionCfg, extensionCfg)
			if processorConfig != nil {
				assert.Equal(t, 1, len(processorConfig))
			}
		})
	}
}

func TestLogLevelConversion(t *testing.T) {
	tests := []struct {
		name    string
		logpLvl logp.Level
	}{
		{
			name:    "debug",
			logpLvl: logp.DebugLevel,
		},
		{
			name:    "info",
			logpLvl: logp.InfoLevel,
		},
		{
			name:    "warn",
			logpLvl: logp.WarnLevel,
		},
		{
			name:    "error",
			logpLvl: logp.ErrorLevel,
		},
		{
			name:    "unknown",
			logpLvl: logp.Level(-128),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.logpLvl >= logp.DebugLevel {
				otelLogpLvl, err := LogpLevelToOTel(tt.logpLvl)
				require.NoError(t, err)

				logpLvl, err := OTelLevelToLogp(otelLogpLvl)
				require.NoError(t, err)
				require.Equal(t, tt.logpLvl, logpLvl)
			} else {
				unknownOTel, err := LogpLevelToOTel(tt.logpLvl)
				require.Error(t, err)

				_, err = OTelLevelToLogp(unknownOTel)
				require.Error(t, err)
			}
		})
	}
}

func TestResolveStreamID(t *testing.T) {
	tests := []struct {
		name         string
		streamID     string
		streamSource map[string]any
		unitID       string
		index        int
		expected     string
	}{
		{
			name:     "uses proto stream ID when set",
			streamID: "my-stream-id",
			unitID:   "my-unit",
			index:    0,
			expected: "my-stream-id",
		},
		{
			name:         "falls back to source id when proto stream ID is empty",
			streamID:     "",
			streamSource: map[string]any{"id": "source-id"},
			unitID:       "my-unit",
			index:        0,
			expected:     "source-id",
		},
		{
			name:         "generates ID when both proto and source are empty",
			streamID:     "",
			streamSource: map[string]any{},
			unitID:       "system/metrics-default-unique-system-metrics-input",
			index:        0,
			expected:     "system/metrics-default-unique-system-metrics-input-0",
		},
		{
			name:     "generates ID when source is nil",
			streamID: "",
			unitID:   "my-unit",
			index:    2,
			expected: "my-unit-2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := resolveStreamID(tt.streamID, tt.streamSource, tt.unitID, tt.index)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestStripDefaultProcessors(t *testing.T) {
	filebeatDefaults := GetDefaultProcessors("filebeat")
	tests := []struct {
		name     string
		defaults []map[string]any
		raw      any
		want     []any
	}{
		{
			name:     "nil input returns nil",
			defaults: filebeatDefaults,
			raw:      nil,
			want:     nil,
		},
		{
			name:     "non-list input returns nil",
			defaults: filebeatDefaults,
			raw:      "not a list",
			want:     nil,
		},
		{
			name:     "empty defaults, list is unchanged",
			defaults: nil,
			raw: []any{
				map[string]any{"add_cloud_metadata": nil},
			},
			want: []any{
				map[string]any{"add_cloud_metadata": nil},
			},
		},
		{
			name:     "add_cloud_metadata null matches default and is stripped",
			defaults: filebeatDefaults,
			raw: []any{
				map[string]any{"add_agent_metadata": map[string]any{"stream_id": "s1"}},
				map[string]any{"add_cloud_metadata": nil},
				map[string]any{"timestamp": map[string]any{"field": "datetime"}},
			},
			want: []any{
				map[string]any{"add_agent_metadata": map[string]any{"stream_id": "s1"}},
				map[string]any{"timestamp": map[string]any{"field": "datetime"}},
			},
		},
		{
			name:     "add_cloud_metadata with custom config is preserved",
			defaults: filebeatDefaults,
			raw: []any{
				map[string]any{"add_cloud_metadata": map[string]any{"overwrite": true}},
			},
			want: []any{
				map[string]any{"add_cloud_metadata": map[string]any{"overwrite": true}},
			},
		},
		{
			name:     "add_host_metadata null does not match default (default has when.not.contains.tags) and is preserved",
			defaults: filebeatDefaults,
			raw: []any{
				map[string]any{"add_host_metadata": nil},
			},
			want: []any{
				map[string]any{"add_host_metadata": nil},
			},
		},
		{
			name:     "add_host_metadata exact-match default config is stripped",
			defaults: filebeatDefaults,
			raw: []any{
				map[string]any{"add_host_metadata": map[string]any{"when.not.contains.tags": "forwarded"}},
			},
			want: []any{},
		},
		{
			name:     "multi-key processor entry is not a valid single-name proc and is preserved",
			defaults: filebeatDefaults,
			raw: []any{
				map[string]any{"add_cloud_metadata": nil, "extra_key": "value"},
			},
			want: []any{
				map[string]any{"add_cloud_metadata": nil, "extra_key": "value"},
			},
		},
		{
			name:     "all default processors with null config are stripped",
			defaults: filebeatDefaults,
			raw: []any{
				map[string]any{"add_cloud_metadata": nil},
				map[string]any{"add_docker_metadata": nil},
				map[string]any{"add_kubernetes_metadata": nil},
			},
			want: []any{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripDefaultProcessors(tt.defaults, tt.raw)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestInjectOsqueryConfig verifies that injectOsqueryConfig mirrors the stream ordering
// produced by osquerybeatCfgFromStreams: the osquery_manager.result stream is always moved
// to position 0, and all other streams follow in their original relative order.
func TestInjectOsqueryConfig(t *testing.T) {
	makeStream := func(id string, isResult bool) receiverInput {
		dataset := "osquery_manager.action.responses"
		if isResult {
			dataset = "osquery_manager.result"
		}
		return receiverInput{
			streamID: id,
			config: map[string]any{
				"data_stream": map[string]any{
					"dataset": dataset,
				},
			},
		}
	}

	makeStreamWithNamespace := func(id string, isResult bool, ns string) receiverInput {
		dataset := "osquery_manager.action.responses"
		if isResult {
			dataset = "osquery_manager.result"
		}
		return receiverInput{
			streamID: id,
			config: map[string]any{
				"data_stream": map[string]any{
					"dataset":   dataset,
					"namespace": ns,
				},
			},
		}
	}

	// unit carries the input-level osquery config, mirroring what osquerybeatCfgFromStreams
	// receives as rawIn.Source when the integration has scheduled queries.
	unit := component.Unit{
		Config: component.MustExpectedConfig(map[string]interface{}{
			"osquery": map[string]interface{}{
				"queries": map[string]interface{}{},
			},
		}),
	}

	unitWithCustomNS := component.Unit{
		Config: component.MustExpectedConfig(map[string]interface{}{
			"data_stream": map[string]interface{}{
				"namespace": "custom-ns",
			},
			"osquery": map[string]interface{}{
				"queries": map[string]interface{}{},
			},
		}),
	}

	tests := []struct {
		name              string
		inputs            []receiverInput
		unit              component.Unit
		wantStreamIDs     []string
		wantNamespaceByID map[string]string // non-nil: verify data_stream.namespace per stream id
	}{
		{
			name:          "1 stream: result only",
			inputs:        []receiverInput{makeStream("result", true)},
			unit:          unit,
			wantStreamIDs: []string{"result"},
		},
		{
			name:          "2 streams: result first",
			inputs:        []receiverInput{makeStream("result", true), makeStream("action", false)},
			unit:          unit,
			wantStreamIDs: []string{"result", "action"},
		},
		{
			name:          "2 streams: result second",
			inputs:        []receiverInput{makeStream("action", false), makeStream("result", true)},
			unit:          unit,
			wantStreamIDs: []string{"result", "action"},
		},
		{
			// swap(0,2) gives [result, other, action] — wrong relative order of non-result streams
			name: "3 streams: result last",
			inputs: []receiverInput{
				makeStream("action", false),
				makeStream("other", false),
				makeStream("result", true),
			},
			unit:          unit,
			wantStreamIDs: []string{"result", "action", "other"},
		},
		{
			// swap(0,3) gives [result, other1, other2, action] — wrong
			name: "4 streams: result last",
			inputs: []receiverInput{
				makeStream("action", false),
				makeStream("other1", false),
				makeStream("other2", false),
				makeStream("result", true),
			},
			unit:          unit,
			wantStreamIDs: []string{"result", "action", "other1", "other2"},
		},
		{
			name: "default namespace propagates when unit has no data_stream namespace",
			inputs: []receiverInput{
				makeStream("action", false),
				makeStream("result", true),
			},
			unit:          unit,
			wantStreamIDs: []string{"result", "action"},
			wantNamespaceByID: map[string]string{
				"result": "default",
				"action": "default",
			},
		},
		{
			name: "custom namespace from unit propagates to all streams",
			inputs: []receiverInput{
				makeStream("action", false),
				makeStream("result", true),
			},
			unit:          unitWithCustomNS,
			wantStreamIDs: []string{"result", "action"},
			wantNamespaceByID: map[string]string{
				"result": "custom-ns",
				"action": "custom-ns",
			},
		},
		{
			name: "explicit stream namespace is preserved",
			inputs: []receiverInput{
				makeStream("action", false),
				makeStreamWithNamespace("result", true, "stream-ns"),
			},
			unit:          unitWithCustomNS,
			wantStreamIDs: []string{"result", "action"},
			wantNamespaceByID: map[string]string{
				"result": "stream-ns",
				"action": "custom-ns",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := injectOsqueryConfig(tt.inputs, tt.unit)
			require.Len(t, got, len(tt.wantStreamIDs))
			gotIDs := make([]string, len(got))
			for i, ri := range got {
				gotIDs[i] = ri.streamID
			}
			assert.Equal(t, tt.wantStreamIDs, gotIDs,
				"stream ordering must match osquerybeatCfgFromStreams: result stream first, others in original relative order")
			assert.NotNil(t, got[0].config["osquery"], "result stream must have osquery config injected")

			for _, ri := range got {
				wantNS, ok := tt.wantNamespaceByID[ri.streamID]
				if !ok {
					continue
				}
				ds, ok := ri.config["data_stream"].(map[string]any)
				require.True(t, ok, "stream %q: data_stream must be a map", ri.streamID)
				assert.Equal(t, wantNS, ds["namespace"],
					"stream %q: data_stream.namespace must be propagated from unit level", ri.streamID)
			}
		})
	}
}

func TestGetReceiversConfigHostnameOverride(t *testing.T) {
	comp := &component.Component{
		ID:        "filestream-hostname-test",
		InputType: "filestream",
		InputSpec: &component.InputRuntimeSpec{
			BinaryName: "elastic-otel-collector",
			Spec: component.InputSpec{
				Name: "filestream",
				Command: &component.CommandSpec{
					Args: []string{"filebeat"},
				},
			},
		},
		Units: []component.Unit{
			{
				ID:   "filestream-hostname-unit",
				Type: client.UnitTypeInput,
				Config: component.MustExpectedConfig(map[string]any{
					"streams": []any{
						map[string]any{
							"id":    "stream-1",
							"paths": []any{"/var/log/*.log"},
						},
					},
				}),
			},
		},
	}

	t.Run("env_set", func(t *testing.T) {
		t.Setenv(util.EnvHostName, "override-node")

		result, err := getReceiversConfigForComponent(comp, &info.AgentInfo{}, nil, nil)
		require.NoError(t, err)
		require.NotEmpty(t, result)

		for id, raw := range result {
			cfg, ok := raw.(map[string]any)
			require.True(t, ok, "receiver %s: config is not a map", id)
			assert.Equal(t, "override-node", cfg["hostname"],
				"receiver %s: hostname should be injected into receiver config", id)
		}
	})

	t.Run("env_set_whitespace_trimmed", func(t *testing.T) {
		t.Setenv(util.EnvHostName, "  override-node  ")

		result, err := getReceiversConfigForComponent(comp, &info.AgentInfo{}, nil, nil)
		require.NoError(t, err)
		require.NotEmpty(t, result)

		for id, raw := range result {
			cfg, ok := raw.(map[string]any)
			require.True(t, ok, "receiver %s: config is not a map", id)
			assert.Equal(t, "override-node", cfg["hostname"],
				"receiver %s: hostname should be trimmed before injection", id)
		}
	})

	t.Run("env_unset", func(t *testing.T) {
		t.Setenv(util.EnvHostName, "")
		result, err := getReceiversConfigForComponent(comp, &info.AgentInfo{}, nil, nil)
		require.NoError(t, err)
		require.NotEmpty(t, result)

		for id, raw := range result {
			cfg, ok := raw.(map[string]any)
			require.True(t, ok, "receiver %s: config is not a map", id)
			assert.NotContains(t, cfg, "hostname",
				"receiver %s: hostname should not be present when env var is unset", id)
		}
	})
}
