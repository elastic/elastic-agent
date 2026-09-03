// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package k8s_test

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	k8sutil "github.com/elastic/elastic-agent/internal/pkg/otel/k8s"
	"github.com/elastic/elastic-agent/pkg/component"
)

// k8sContainerLogUnitWithPaths builds a unit whose stream has explicit paths and
// symlinks settings, mirroring what the Helm chart / Fleet policy delivers.
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

func TestExtractIncludePaths(t *testing.T) {
	outputUnit := k8sOutputUnit("output-unit")

	t.Run("paths from stream config are translated", func(t *testing.T) {
		comp := component.Component{
			Units: []component.Unit{
				k8sContainerLogUnitWithPaths("u1", []string{
					"/var/log/containers/*${kubernetes.container.id}.log",
				}, true),
				outputUnit,
			},
		}
		assert.Equal(t, []string{"/var/log/containers/*.log"}, k8sutil.ExtractIncludePaths(&comp))
	})

	t.Run("rotated log path is translated", func(t *testing.T) {
		comp := component.Component{
			Units: []component.Unit{
				k8sContainerLogUnitWithPaths("u1", []string{
					"/var/log/pods/${kubernetes.namespace}_${kubernetes.pod.name}_${kubernetes.pod.uid}/${kubernetes.container.name}/*.log*",
				}, true),
				outputUnit,
			},
		}
		assert.Equal(t, []string{"/var/log/pods/*_*_*/*/*.log*"}, k8sutil.ExtractIncludePaths(&comp))
	})

	t.Run("duplicate paths across streams are deduplicated", func(t *testing.T) {
		comp := component.Component{
			Units: []component.Unit{
				k8sContainerLogUnitWithPaths("u1", []string{"/var/log/containers/*${kubernetes.container.id}.log"}, true),
				k8sContainerLogUnitWithPaths("u2", []string{"/var/log/containers/*${kubernetes.container.id}.log"}, true),
				outputUnit,
			},
		}
		assert.Equal(t, []string{"/var/log/containers/*.log"}, k8sutil.ExtractIncludePaths(&comp))
	})

	t.Run("no paths configured falls back to default pod log glob", func(t *testing.T) {
		comp := component.Component{
			Units: []component.Unit{
				k8sContainerLogUnit("u1"),
				outputUnit,
			},
		}
		assert.Equal(t, []string{k8sutil.DefaultPodLogGlob}, k8sutil.ExtractIncludePaths(&comp))
	})
}

func TestUsesContainersPath(t *testing.T) {
	assert.True(t, k8sutil.UsesContainersPath([]string{"/var/log/containers/*.log"}))
	assert.True(t, k8sutil.UsesContainersPath([]string{"/other/*.log", "/var/log/containers/*.log"}))
	assert.False(t, k8sutil.UsesContainersPath([]string{"/var/log/pods/*/*/*.log"}))
	assert.False(t, k8sutil.UsesContainersPath(nil))
}

func TestBuildFilelogOperators(t *testing.T) {
	t.Run("pods path — only container operator", func(t *testing.T) {
		ops := k8sutil.BuildFilelogOperators([]string{"/var/log/pods/*/*/*.log"})
		require.Len(t, ops, 1)
		assert.Equal(t, "container-parser", ops[0]["id"])
		assert.Equal(t, "container", ops[0]["type"])
	})

	t.Run("containers path — regex, move, then container operator", func(t *testing.T) {
		ops := k8sutil.BuildFilelogOperators([]string{"/var/log/containers/*.log"})
		require.Len(t, ops, 3)
		assert.Equal(t, "extract-container-id", ops[0]["id"])
		assert.Equal(t, "regex_parser", ops[0]["type"])
		assert.Equal(t, "move-container-id", ops[1]["id"])
		assert.Equal(t, "move", ops[1]["type"])
		assert.Equal(t, "container-parser", ops[2]["id"])
		assert.Equal(t, "container", ops[2]["type"])
	})

	t.Run("regex extracts container ID from canonical filename", func(t *testing.T) {
		ops := k8sutil.BuildFilelogOperators([]string{"/var/log/containers/*.log"})
		re := regexp.MustCompile(ops[0]["regex"].(string))
		path := "/var/log/containers/coredns-5d78c9869d-abc12_kube-system_coredns-a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2.log"
		match := re.FindStringSubmatch(path)
		require.NotNil(t, match, "regex must match canonical containers filename")
		idx := re.SubexpIndex("container_id")
		assert.Equal(t, "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", match[idx])
	})
}

func TestBuildEcsMappingTransformConfig(t *testing.T) {
	agentInfo := &info.AgentInfo{}
	cfg := k8sutil.BuildEcsMappingTransformConfig(agentInfo)

	stmts, ok := cfg["log_statements"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, stmts, 3, "expected scope, resource, and log contexts")

	byCtx := make(map[string][]string)
	for _, s := range stmts {
		ctx := s["context"].(string)
		ss := s["statements"].([]string)
		byCtx[ctx] = ss
	}

	require.Contains(t, byCtx, "scope")
	assert.Contains(t, byCtx["scope"][0], "elastic.mapping.mode")
	assert.Contains(t, byCtx["scope"][0], "ecs")

	require.Contains(t, byCtx, "resource")
	resourceJoined := strings.Join(byCtx["resource"], "\n")
	assert.Contains(t, resourceJoined, "kubernetes.pod.start_time")
	assert.Contains(t, resourceJoined, "k8s.pod.start_time")
	assert.Contains(t, resourceJoined, "orchestrator.type")
	assert.Contains(t, resourceJoined, "kubernetes")
	assert.Contains(t, resourceJoined, "ecs.version")
	assert.Contains(t, resourceJoined, "agent.type")
	assert.Contains(t, resourceJoined, "elastic-agent")

	require.Contains(t, byCtx, "log")
	logJoined := strings.Join(byCtx["log"], "\n")
	assert.Contains(t, logJoined, "event.dataset")
	assert.Contains(t, logJoined, "kubernetes.container_logs")
	assert.Contains(t, logJoined, "event.module")
}

func TestBuildK8sAttributesProcessorConfig(t *testing.T) {
	cfg := k8sutil.BuildK8sAttributesProcessorConfig()

	extract, ok := cfg["extract"].(map[string]any)
	require.True(t, ok)

	metadata, ok := extract["metadata"].([]string)
	require.True(t, ok)
	assert.Contains(t, metadata, "k8s.replicaset.name")
	assert.Contains(t, metadata, "container.id")
	assert.Contains(t, metadata, "container.image.name")
	assert.Contains(t, metadata, "container.image.tag")

	labels, ok := extract["labels"].([]map[string]any)
	require.True(t, ok)
	require.Len(t, labels, 2)
	var fromPod, fromNS bool
	for _, l := range labels {
		switch l["from"] {
		case "pod":
			fromPod = true
			assert.Equal(t, "kubernetes.labels.$$1", l["tag_name"])
		case "namespace":
			fromNS = true
			assert.Equal(t, "kubernetes.namespace_labels.$$1", l["tag_name"])
		}
	}
	assert.True(t, fromPod, "labels must include a pod entry")
	assert.True(t, fromNS, "labels must include a namespace entry")

	annotations, ok := extract["annotations"].([]map[string]any)
	require.True(t, ok)
	assert.Len(t, annotations, 2)

	assoc, ok := cfg["pod_association"].([]map[string]any)
	require.True(t, ok)
	var hasNameNS bool
	for _, a := range assoc {
		srcs, ok := a["sources"].([]map[string]any)
		if !ok {
			continue
		}
		if len(srcs) == 2 {
			names := []string{srcs[0]["name"].(string), srcs[1]["name"].(string)}
			if slices.Contains(names, "k8s.pod.name") && slices.Contains(names, "k8s.namespace.name") {
				hasNameNS = true
			}
		}
	}
	assert.True(t, hasNameNS, "pod_association must have a k8s.pod.name+k8s.namespace.name entry")
}
