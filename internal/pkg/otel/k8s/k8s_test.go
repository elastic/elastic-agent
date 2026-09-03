// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package k8s_test

import (
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/stretchr/testify/assert"

	k8sutil "github.com/elastic/elastic-agent/internal/pkg/otel/k8s"
	"github.com/elastic/elastic-agent/pkg/component"
)

// k8sContainerLogUnit builds a minimal input unit with a kubernetes.container_logs stream.
func k8sContainerLogUnit(unitID string) component.Unit {
	return component.Unit{
		ID:   unitID,
		Type: client.UnitTypeInput,
		Config: component.MustExpectedConfig(map[string]any{
			"id":   unitID,
			"type": "filestream",
			"streams": []any{
				map[string]any{
					"id": unitID + "-stream",
					"data_stream": map[string]any{
						"dataset":   "kubernetes.container_logs",
						"type":      "logs",
						"namespace": "default",
					},
				},
			},
		}),
	}
}

func k8sOutputUnit(unitID string) component.Unit {
	return component.Unit{
		ID:   unitID,
		Type: client.UnitTypeOutput,
		Config: component.MustExpectedConfig(map[string]any{
			"hosts":    []any{"https://localhost:9200"},
			"username": "elastic",
			"password": "changeme",
		}),
	}
}

func TestIsContainerLogComponent(t *testing.T) {
	tests := []struct {
		name     string
		comp     component.Component
		expected bool
	}{
		{
			name: "k8s container-log component",
			comp: component.Component{
				InputType: "filestream",
				Units: []component.Unit{
					k8sContainerLogUnit("input-unit"),
					k8sOutputUnit("output-unit"),
				},
			},
			expected: true,
		},
		{
			name: "non-k8s filestream component",
			comp: component.Component{
				InputType: "filestream",
				Units: []component.Unit{
					{
						ID:   "other-input",
						Type: client.UnitTypeInput,
						Config: component.MustExpectedConfig(map[string]any{
							"id":   "other-input",
							"type": "filestream",
							"streams": []any{
								map[string]any{
									"id": "other-stream",
									"data_stream": map[string]any{
										"dataset": "system.syslog",
										"type":    "logs",
									},
								},
							},
						}),
					},
					k8sOutputUnit("output-unit"),
				},
			},
			expected: false,
		},
		{
			name: "no input units",
			comp: component.Component{
				InputType: "filestream",
				Units:     []component.Unit{k8sOutputUnit("output-unit")},
			},
			expected: false,
		},
		{
			name: "mixed datasets - not all k8s",
			comp: component.Component{
				InputType: "filestream",
				Units: []component.Unit{
					k8sContainerLogUnit("k8s-unit"),
					{
						ID:   "other-input",
						Type: client.UnitTypeInput,
						Config: component.MustExpectedConfig(map[string]any{
							"id":   "other-input",
							"type": "filestream",
							"streams": []any{
								map[string]any{
									"id": "other-stream",
									"data_stream": map[string]any{
										"dataset": "system.syslog",
									},
								},
							},
						}),
					},
					k8sOutputUnit("output-unit"),
				},
			},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, k8sutil.IsContainerLogComponent(&tt.comp))
		})
	}
}

func TestIsContainerLogStream(t *testing.T) {
	t.Run("matching dataset", func(t *testing.T) {
		stream := map[string]interface{}{
			"data_stream": map[string]interface{}{
				"dataset": "kubernetes.container_logs",
			},
		}
		assert.True(t, k8sutil.IsContainerLogStream(stream))
	})

	t.Run("non-matching dataset", func(t *testing.T) {
		stream := map[string]interface{}{
			"data_stream": map[string]interface{}{
				"dataset": "system.syslog",
			},
		}
		assert.False(t, k8sutil.IsContainerLogStream(stream))
	})

	t.Run("missing data_stream", func(t *testing.T) {
		assert.False(t, k8sutil.IsContainerLogStream(map[string]interface{}{}))
	})
}

func TestStripVarsFromInputPaths(t *testing.T) {
	t.Run("strips kubernetes vars from container_logs stream paths", func(t *testing.T) {
		m := map[string]interface{}{
			"inputs": []interface{}{
				map[string]interface{}{
					"streams": []interface{}{
						map[string]interface{}{
							"data_stream": map[string]interface{}{
								"dataset": "kubernetes.container_logs",
							},
							"paths": []interface{}{
								"/var/log/containers/*${kubernetes.container.id}.log",
							},
						},
					},
				},
			},
		}
		k8sutil.StripVarsFromInputPaths(m)
		inputs := m["inputs"].([]interface{})
		stream := inputs[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})
		paths := stream["paths"].([]interface{})
		assert.Equal(t, "/var/log/containers/*.log", paths[0])
	})

	t.Run("does not touch non-k8s streams", func(t *testing.T) {
		m := map[string]interface{}{
			"inputs": []interface{}{
				map[string]interface{}{
					"streams": []interface{}{
						map[string]interface{}{
							"data_stream": map[string]interface{}{
								"dataset": "system.syslog",
							},
							"paths": []interface{}{
								"/var/log/syslog/${host.name}.log",
							},
						},
					},
				},
			},
		}
		k8sutil.StripVarsFromInputPaths(m)
		inputs := m["inputs"].([]interface{})
		stream := inputs[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})
		paths := stream["paths"].([]interface{})
		assert.Equal(t, "/var/log/syslog/${host.name}.log", paths[0], "non-k8s vars must not be stripped")
	})
}

func TestTranslateVarPathToGlob(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "container symlink path (default Helm)",
			input:    "/var/log/containers/*${kubernetes.container.id}.log",
			expected: "/var/log/containers/*.log",
		},
		{
			name:     "pod path with rotated logs (Helm rotated_logs=true)",
			input:    "/var/log/pods/${kubernetes.namespace}_${kubernetes.pod.name}_${kubernetes.pod.uid}/${kubernetes.container.name}/*.log*",
			expected: "/var/log/pods/*_*_*/*/*.log*",
		},
		{
			name:     "no variables — passes through unchanged",
			input:    "/var/log/pods/*/*/*.log",
			expected: "/var/log/pods/*/*/*.log",
		},
		{
			name:     "custom path with variable",
			input:    "/custom/logs/${kubernetes.pod.name}/app.log",
			expected: "/custom/logs/*/app.log",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, k8sutil.TranslateVarPathToGlob(tt.input))
		})
	}
}
