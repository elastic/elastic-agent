// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"strings"
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/pkg/component"
)

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

func k8sContainerLogUnitWithPaths(unitID string, paths []string, followSymlinks bool) component.Unit {
	pathsAny := make([]any, len(paths))
	for i, p := range paths {
		pathsAny[i] = p
	}
	return component.Unit{
		ID:   unitID,
		Type: client.UnitTypeInput,
		Config: component.MustExpectedConfig(map[string]any{
			"id":   unitID,
			"type": "filestream",
			"streams": []any{
				map[string]any{
					"id":    unitID + "-stream",
					"paths": pathsAny,
					"prospector.scanner.symlinks": followSymlinks,
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

func TestGetKubernetesContainerLogConfig(t *testing.T) {
	// In production the coordinator strips ${kubernetes.*} before AST rendering, so
	// paths arrive here already as stable globs. In this unit test we pass the raw
	// template; TranslateVarPathToGlob inside ExtractIncludePaths handles it either way.
	configuredPath := "/var/log/containers/*${kubernetes.container.id}.log"
	expectedGlob := "/var/log/containers/*.log"

	comp := component.Component{
		ID:         "k8s-container-logs-default",
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
			k8sContainerLogUnitWithPaths("k8s-input-unit", []string{configuredPath}, true),
			{
				ID:   "k8s-container-logs-default",
				Type: client.UnitTypeOutput,
				Config: component.MustExpectedConfig(map[string]any{
					"hosts":    []any{"https://localhost:9200"},
					"username": "elastic",
					"password": "changeme",
				}),
			},
		},
	}

	cfg, err := getKubernetesContainerLogConfig(&comp, &info.AgentInfo{}, logp.NewNopLogger())
	require.NoError(t, err)
	require.NotNil(t, cfg)

	cfgMap := cfg.ToStringMap()

	// Verify a filelog receiver is generated (not a filebeatreceiver).
	receivers, ok := cfgMap["receivers"].(map[string]any)
	require.True(t, ok, "expected receivers map")
	assert.Len(t, receivers, 1)
	var receiverKey string
	for k := range receivers {
		receiverKey = k
	}
	assert.Contains(t, receiverKey, "filelog/")
	assert.Contains(t, receiverKey, "k8s-container-logs-default")

	receiverCfg, ok := receivers[receiverKey].(map[string]any)
	require.True(t, ok, "expected receiver config map")

	// The integration stream path is translated to a stable glob.
	include, ok := receiverCfg["include"].([]string)
	require.True(t, ok, "expected include as []string")
	assert.Equal(t, []string{expectedGlob}, include, "include must be the collapsed static glob")

	followSymlinks, ok := receiverCfg["follow_symlinks"].(bool)
	require.True(t, ok, "expected follow_symlinks bool")
	assert.True(t, followSymlinks)

	// Verify both the ECS-mode transform and k8sattributes processors are generated.
	processors, ok := cfgMap["processors"].(map[string]any)
	require.True(t, ok, "expected processors map")
	var k8sAttrKey, transformKey string
	for k := range processors {
		if strings.Contains(k, "k8sattributes/") {
			k8sAttrKey = k
		}
		if strings.Contains(k, "transform/") {
			transformKey = k
		}
	}
	assert.NotEmpty(t, k8sAttrKey, "expected k8sattributes processor")
	assert.NotEmpty(t, transformKey, "expected transform processor for ECS mapping mode")

	// Verify elasticsearch exporter is present.
	exporters, ok := cfgMap["exporters"].(map[string]any)
	require.True(t, ok, "expected exporters map")
	assert.Contains(t, exporters, "elasticsearch/_agent-component/default")

	// Verify the pipeline wires receiver → k8sattributes → transform → exporter.
	svc, ok := cfgMap["service"].(map[string]any)
	require.True(t, ok)
	pipelines, ok := svc["pipelines"].(map[string]any)
	require.True(t, ok)
	assert.Len(t, pipelines, 1)
	for _, p := range pipelines {
		pipeline, ok := p.(map[string]any)
		require.True(t, ok)
		proc, ok := pipeline["processors"].([]string)
		require.True(t, ok)
		require.GreaterOrEqual(t, len(proc), 2)
		assert.Contains(t, proc[0], "k8sattributes/", "k8sattributes must run first")
		assert.Contains(t, proc[1], "transform/", "ECS-mode transform must follow k8sattributes")
	}
}
