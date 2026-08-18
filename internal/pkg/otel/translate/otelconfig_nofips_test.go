// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package translate

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/component"
)

func TestBeatsAuthExtensionKerberos(t *testing.T) {
	tests := []struct {
		name          string
		outputCfg     map[string]any
		expected      map[string]any
		expectedError string
	}{
		{
			name: "with kerberos enabled",
			outputCfg: map[string]any{
				"kerberos": map[string]any{
					"enabled":     true,
					"auth_type":   "password",
					"config_path": "temp/krb5.conf",
					"username":    "beats",
					"password":    "testing",
					"realm":       "elastic",
				},
			},
			expected: map[string]any{
				"continue_on_error":       true,
				"idle_connection_timeout": "3s",
				"timeout":                 "1m30s",
				"kerberos": map[string]any{
					"enabled":          true,
					"auth_type":        "password",
					"config_path":      "temp/krb5.conf",
					"username":         "beats",
					"password":         "testing",
					"realm":            "elastic",
					"enable_krb5_fast": false,
					"service_name":     "",
					"keytab":           "",
				},
				"proxy_disable": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(tt.outputCfg)
			require.NoError(t, err)

			actual, err := getBeatsAuthExtensionConfig(cfg)
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tt.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, actual)
			}
		})
	}
}

func TestGetOtelConfigKafkaOAuth2(t *testing.T) {
	agentInfo := &info.AgentInfo{}
	beatProcessorID := "beat/_agent-component/beat-metrics-monitoring"
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
					"processors": []any{
						mapstr.M{
							"add_agent_metadata": mapstr.M{
								"data_stream": mapstr.M{
									"dataset":   "generic-1",
									"namespace": "default",
									"type":      "metrics",
								},
								"elastic_agent": mapstr.M{
									"id":       agentInfo.AgentID(),
									"snapshot": agentInfo.Snapshot(),
									"version":  agentInfo.Version(),
								},
								"input_id":  "test",
								"stream_id": "test-1",
							},
						},
					},
					"module": "beat",
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

	model := &component.Model{
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
							"sasl.mechanism":             "OAUTHBEARER",
							"oauth2client": map[string]any{
								"client_id":     "my-client",
								"client_secret": "my-secret",
								"token_url":     "https://example.com/oauth2/token",
							},
						}),
					},
				},
			},
		},
	}

	expectedConfig := confmap.NewFromStringMap(map[string]any{
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
				"auth": map[string]any{
					"sasl": map[string]any{
						"mechanism":                "OAUTHBEARER",
						"oauthbearer_token_source": "oauth2client/_agent-component/default",
					},
				},
				"record_partitioner": map[string]any{
					"extension": "kafkapartitioner/_agent-component/default",
				},
			},
		},
		"extensions": map[string]any{
			"kafkapartitioner/_agent-component/default": map[string]any{
				"kafkapartitioner/_agent-component/default": map[string]any{},
			},
			"oauth2client/_agent-component/default": map[string]any{
				"client_certificate_key":      "",
				"client_certificate_key_file": "",
				"client_certificate_key_id":   "",
				"client_id":                   "my-client",
				"client_id_file":              "",
				"client_secret":               "my-secret",
				"client_secret_file":          "",
				"endpoint_params":             "",
				"expiry_buffer":               "5m0s",
				"grant_type":                  "",
				"tls": map[string]any{
					"tpm": map[string]any{
						"auth":       "",
						"enabled":    false,
						"owner_auth": "",
						"path":       "",
					},
				},
				"token_url": "https://example.com/oauth2/token",
			},
		},
		"processors": map[string]any{
			beatProcessorID: map[string]any{
				"processors": GetDefaultProcessors("metricbeat"),
			},
		},
		"receivers": map[string]any{
			"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1": expectedBeatMetricConfig,
		},
		"service": map[string]any{
			"extensions": []any{"kafkapartitioner/_agent-component/default", "oauth2client/_agent-component/default"},
			"pipelines": map[string]any{
				"logs/_agent-component/beat-metrics-monitoring": map[string][]string{
					"exporters":  {"kafka/_agent-component/default"},
					"processors": {beatProcessorID},
					"receivers":  {"metricbeatreceiver/_agent-component/beat-metrics-monitoring/test-1"},
				},
			},
		},
	})

	actualConf, err := GetOtelConfig(model, agentInfo, logp.NewNopLogger())
	require.NoError(t, err)
	assert.Equal(t, expectedConfig.ToStringMap(), actualConf.ToStringMap())
}
