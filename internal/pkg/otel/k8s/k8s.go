// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package k8s provides utilities for the native Kubernetes filelog receiver path.
// It is the single source of truth for:
//   - Identifying kubernetes container-log streams/components
//   - Stripping kubernetes provider variable references from raw policy config
//     maps before AST rendering (preventing config churn in the OTel manager)
//   - Translating policy path templates into stable file-glob patterns
package k8s

import (
	"regexp"
	"strings"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/elastic/elastic-agent/pkg/component"
)

const (
	// ContainerLogsDataset is the data_stream.dataset value that identifies the
	// Kubernetes container-logs integration stream.
	ContainerLogsDataset = "kubernetes.container_logs"
)

// k8sVarPattern matches elastic-agent variable references scoped to the
// kubernetes provider, e.g. ${kubernetes.container.id}. Used to strip
// per-pod values from input path templates before AST rendering so that the
// OTel manager sees a stable glob regardless of how many pods are running.
var k8sVarPattern = regexp.MustCompile(`\$\{kubernetes\.[^}]*\}`)

// anyVarPattern matches any elastic-agent variable reference of the form
// ${provider.key}. Used as a defensive fallback when translating path templates
// that may still contain non-kubernetes provider references.
var anyVarPattern = regexp.MustCompile(`\$\{[^}]+\}`)

// consecutiveStarsPattern matches two or more consecutive * characters produced
// when a path contains a literal wildcard adjacent to a variable reference
// (e.g. *${kubernetes.container.id}).
var consecutiveStarsPattern = regexp.MustCompile(`\*{2,}`)

// TranslateVarPathToGlob replaces all ${...} variable references with *
// wildcards, converting a policy path template into a stable file-glob pattern.
// Adjacent wildcards are collapsed to a single * to avoid double-star globs.
func TranslateVarPathToGlob(path string) string {
	withWildcards := anyVarPattern.ReplaceAllString(path, "*")
	return consecutiveStarsPattern.ReplaceAllString(withWildcards, "*")
}

// StripVarsFromInputPaths rewrites ${kubernetes.*} variable references in the
// "paths" field of every kubernetes.container_logs stream to * wildcards. It
// operates on the raw config map produced by cfg.ToMapStr() before the
// coordinator passes it to generateAST. Only streams identified by
// IsContainerLogStream are touched; all other streams and all non-path fields
// are left unchanged.
//
// Without this, the transpiler renders per-container-ID path templates on every
// pod-discovery event, producing a different OTel config hash each time and
// triggering hot reloads that lose the filelog receiver's in-memory read-position
// checkpoints.
func StripVarsFromInputPaths(m map[string]interface{}) {
	inputs, _ := m["inputs"]
	inputList, ok := inputs.([]interface{})
	if !ok {
		return
	}
	for _, input := range inputList {
		inputMap, ok := input.(map[string]interface{})
		if !ok {
			continue
		}
		streams, _ := inputMap["streams"]
		streamList, ok := streams.([]interface{})
		if !ok {
			continue
		}
		for _, stream := range streamList {
			streamMap, ok := stream.(map[string]interface{})
			if !ok {
				continue
			}
			if !IsContainerLogStream(streamMap) {
				continue
			}
			paths, _ := streamMap["paths"]
			pathList, ok := paths.([]interface{})
			if !ok {
				continue
			}
			for i, path := range pathList {
				pathStr, ok := path.(string)
				if !ok {
					continue
				}
				transformed := k8sVarPattern.ReplaceAllString(pathStr, "*")
				transformed = strings.ReplaceAll(transformed, "**", "*")
				pathList[i] = transformed
			}
		}
	}
}

// IsContainerLogStream reports whether a raw stream config map (as produced by
// cfg.ToMapStr()) belongs to the Kubernetes container-logs integration by
// checking data_stream.dataset.
func IsContainerLogStream(stream map[string]interface{}) bool {
	ds, ok := stream["data_stream"].(map[string]interface{})
	if !ok {
		return false
	}
	return ds["dataset"] == ContainerLogsDataset
}

// IsContainerLogComponent reports whether comp represents a kubernetes
// container-logs filestream input. Every input unit in the component must have
// at least one stream with data_stream.dataset == ContainerLogsDataset. A
// component with no input units returns false.
func IsContainerLogComponent(comp *component.Component) bool {
	inputUnitCount := 0
	for _, unit := range comp.Units {
		if unit.Type != client.UnitTypeInput {
			continue
		}
		inputUnitCount++
		hasK8sStream := false
		for _, stream := range unit.Config.GetStreams() {
			ds := stream.GetDataStream()
			if ds != nil && ds.GetDataset() == ContainerLogsDataset {
				hasK8sStream = true
				break
			}
		}
		if !hasK8sStream {
			return false
		}
	}
	return inputUnitCount > 0
}
