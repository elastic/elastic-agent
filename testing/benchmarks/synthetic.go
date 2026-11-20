// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package benchmarks contains micro-benchmarks for the elastic-agent partial-reload
// hot paths, plus the synthetic inputs they share.
//
// The synthetic filestream component here models the filestream-default component
// of a Kubernetes container-log deployment with n active pods, as rendered by the
// Helm chart. Its structure was captured from a diagnostics bundle of the 80-pod
// k8s benchmark (testing/integration/k8s/otel_partial_reload_test.go) so that the
// micro-benchmarks exercise the same config shape the coordinator handles in
// production.
package benchmarks

import (
	"fmt"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent/pkg/component"
)

// FilestreamComponent builds the component.Component that represents the
// filestream-default component from a kubernetes container-log deployment with n
// active pods, running under the OTel runtime manager.
func FilestreamComponent(n int) component.Component {
	inputConfig := FilestreamInputConfig(n)

	esOutputConfig := map[string]any{
		"type":             "elasticsearch",
		"hosts":            []any{"https://my-es.elastic.cloud:443"},
		"api_key":          "id:secret",
		"preset":           "balanced",
		"queue.mem.events": 3200,
	}

	return component.Component{
		ID:             "filestream-default",
		RuntimeManager: component.OtelRuntimeManager,
		InputType:      "filestream",
		OutputType:     "elasticsearch",
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
				ID:     "filestream-default",
				Type:   client.UnitTypeInput,
				Config: component.MustExpectedConfig(inputConfig),
			},
			{
				ID:     "filestream-default-output",
				Type:   client.UnitTypeOutput,
				Config: component.MustExpectedConfig(esOutputConfig),
			},
		},
	}
}

// FilestreamInputConfig returns the map[string]any that the coordinator passes to
// ExpectedConfig for a filestream input with n container-log streams. Per-stream
// content mirrors the real per-container stream from the Helm chart.
func FilestreamInputConfig(n int) map[string]any {
	streams := make([]any, n)
	for i := range n {
		containerID := fmt.Sprintf("%040x", i)
		podUID := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", i, i, i, i, i)
		streams[i] = map[string]any{
			"id": fmt.Sprintf("kubernetes-container-logs-log-emitter-%s-container", podUID),
			"paths": []any{
				fmt.Sprintf("/var/log/containers/*%s.log", containerID),
			},
			"data_stream": map[string]any{
				"dataset": "kubernetes.container_logs",
				"type":    "logs",
			},
			"prospector.scanner.symlinks": true,
			"read_until_eof":              map[string]any{"enabled": false},
			"parsers": []any{
				map[string]any{
					"container": map[string]any{"format": "auto", "stream": "all"},
				},
			},
			"processors": []any{
				map[string]any{
					"add_fields": map[string]any{
						"target": "kubernetes",
						"fields": map[string]any{
							"annotations": map[string]any{
								"elastic_co/dataset":                 `${kubernetes.annotations.elastic.co/dataset|""}`,
								"elastic_co/namespace":               `${kubernetes.annotations.elastic.co/namespace|""}`,
								"elastic_co/preserve_original_event": `${kubernetes.annotations.elastic.co/preserve_original_event|""}`,
							},
						},
					},
				},
				map[string]any{
					"drop_fields": map[string]any{
						"fields":         []any{"kubernetes.annotations.elastic_co/dataset"},
						"ignore_missing": true,
						"when":           map[string]any{"equals": map[string]any{"kubernetes.annotations.elastic_co/dataset": ""}},
					},
				},
				map[string]any{
					"drop_fields": map[string]any{
						"fields":         []any{"kubernetes.annotations.elastic_co/namespace"},
						"ignore_missing": true,
						"when":           map[string]any{"equals": map[string]any{"kubernetes.annotations.elastic_co/namespace": ""}},
					},
				},
				map[string]any{
					"drop_fields": map[string]any{
						"fields":         []any{"kubernetes.annotations.elastic_co/preserve_original_event"},
						"ignore_missing": true,
						"when":           map[string]any{"equals": map[string]any{"kubernetes.annotations.elastic_co/preserve_original_event": ""}},
					},
				},
				map[string]any{
					"add_tags": map[string]any{
						"tags": []any{"preserve_original_event"},
						"when": map[string]any{
							"and": []any{
								map[string]any{"has_fields": []any{"kubernetes.annotations.elastic_co/preserve_original_event"}},
								map[string]any{"regexp": map[string]any{"kubernetes.annotations.elastic_co/preserve_original_event": `^(?i)true$`}},
							},
						},
					},
				},
			},
			"add_kubernetes_metadata": map[string]any{},
		}
	}

	return map[string]any{
		"id":         "filestream-container-logs",
		"use_output": "default",
		"streams":    streams,
	}
}
