// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package k8s

import (
	"fmt"
	"os"
	"strings"

	"github.com/elastic/elastic-agent-client/v7/pkg/client"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/pkg/component"
)

const (
	// k8sNodeNameEnvVar is the standard env var injected into elastic-agent pods
	// that holds the Kubernetes node name. The filelog receiver and k8sattributes
	// processor both use it to scope collection to the current node.
	k8sNodeNameEnvVar = "NODE_NAME"

	// DefaultPodLogGlob is the fallback glob used when no paths are configured
	// in the integration streams. It covers all pod logs on the node.
	DefaultPodLogGlob = "/var/log/pods/*/*/*.log"
)

// ExtractIncludePaths collects stable file-glob patterns from all input unit
// streams in the component. Each stream's configured paths are translated from
// policy variable syntax to glob wildcards via TranslateVarPathToGlob.
// Duplicates are removed. If no paths are found, DefaultPodLogGlob is returned.
//
// When the coordinator has already stripped ${kubernetes.*} references before
// AST rendering, the paths arrive here as ready-made globs and TranslateVarPathToGlob
// becomes a no-op safety net for any other provider references.
func ExtractIncludePaths(comp *component.Component) []string {
	seen := make(map[string]struct{})
	var include []string

	for _, unit := range comp.Units {
		if unit.Type != client.UnitTypeInput {
			continue
		}
		for _, stream := range unit.Config.GetStreams() {
			src := stream.GetSource().AsMap()
			rawPaths, ok := src["paths"].([]any)
			if !ok {
				continue
			}
			for _, p := range rawPaths {
				s, ok := p.(string)
				if !ok || s == "" {
					continue
				}
				glob := TranslateVarPathToGlob(s)
				if _, exists := seen[glob]; !exists {
					seen[glob] = struct{}{}
					include = append(include, glob)
				}
			}
		}
	}

	if len(include) == 0 {
		return []string{DefaultPodLogGlob}
	}
	return include
}

// ExtractFollowSymlinks reads prospector.scanner.symlinks from the first stream
// that defines it. Defaults to true to match the Helm chart default.
func ExtractFollowSymlinks(comp *component.Component) bool {
	for _, unit := range comp.Units {
		if unit.Type != client.UnitTypeInput {
			continue
		}
		for _, stream := range unit.Config.GetStreams() {
			src := stream.GetSource().AsMap()
			if v, ok := src["prospector.scanner.symlinks"].(bool); ok {
				return v
			}
		}
	}
	return true
}

// UsesContainersPath reports whether any of the include globs points to the
// /var/log/containers/ symlink tree. When true the symlink filename encodes the
// container ID and an extra regex operator is needed to extract it, because the
// /var/log/pods/ path format (which the container operator understands for uid
// lookup) is not present.
func UsesContainersPath(include []string) bool {
	for _, p := range include {
		if strings.Contains(p, "/var/log/containers/") {
			return true
		}
	}
	return false
}

// BuildFilelogOperators builds the stanza operator chain for the filelog receiver.
// When the include paths use the /var/log/containers/ symlink schema a regex operator
// is prepended to extract the container ID from the symlink filename:
//
//	/var/log/containers/<pod-name>_<namespace>_<container-name>-<container-id>.log
//
// The extracted value is placed in resource["container.id"] so that k8sattributes
// can use it for metadata enrichment. The container operator is always the final
// step and handles both Docker-JSON and CRI-O/containerd log formats.
func BuildFilelogOperators(include []string) []map[string]any {
	var operators []map[string]any
	if UsesContainersPath(include) {
		operators = append(operators,
			map[string]any{
				"id":         "extract-container-id",
				"type":       "regex_parser",
				"parse_from": `attributes["log.file.path"]`,
				"regex":      `-(?P<container_id>[a-f0-9]+)\.log$`,
				"on_error":   "send",
			},
			map[string]any{
				"id":       "move-container-id",
				"type":     "move",
				"from":     `attributes["container_id"]`,
				"to":       `resource["container.id"]`,
				"if":       `attributes["container_id"] != nil`,
				"on_error": "send",
			},
		)
	}
	operators = append(operators, map[string]any{
		"id":   "container-parser",
		"type": "container",
	})
	return operators
}

// BuildFilelogReceiverConfig returns the filelog receiver configuration for the
// native Kubernetes container-log path. The coordinator strips ${kubernetes.*}
// variable references from stream paths before AST rendering, so by the time the
// component reaches this layer the include paths are already stable glob patterns
// (e.g. /var/log/containers/*.log) that do not change when pods are added or removed.
func BuildFilelogReceiverConfig(comp *component.Component) map[string]any {
	include := ExtractIncludePaths(comp)
	followSymlinks := ExtractFollowSymlinks(comp)

	// Exclude the collector's own logs to prevent a log-explosion loop.
	collectorNamespace := os.Getenv("POD_NAMESPACE")
	collectorPodName := os.Getenv("POD_NAME")
	var exclude []string
	if collectorNamespace != "" && collectorPodName != "" {
		exclude = []string{
			fmt.Sprintf("/var/log/pods/%s_%s_*/*/*.log*", collectorNamespace, collectorPodName),
			fmt.Sprintf("/var/log/containers/*_%s_*.log", collectorPodName),
		}
	}

	cfg := map[string]any{
		"include":           include,
		"start_at":          "end",
		"include_file_path": true,
		"include_file_name": false,
		"follow_symlinks":   followSymlinks,
		"operators":         BuildFilelogOperators(include),
	}
	if len(exclude) > 0 {
		cfg["exclude"] = exclude
	}
	return cfg
}

// BuildK8sAttributesProcessorConfig returns a k8sattributes processor config
// that enriches log records with Kubernetes metadata by calling the Kubernetes API.
// The processor is scoped to the current node via NODE_NAME to avoid unnecessary
// API calls for pods on other nodes.
func BuildK8sAttributesProcessorConfig() map[string]any {
	return map[string]any{
		"auth_type":   "serviceAccount",
		"passthrough": false,
		"filter": map[string]any{
			"node_from_env_var": k8sNodeNameEnvVar,
		},
		"pod_association": []map[string]any{
			{"sources": []map[string]any{{"from": "resource_attribute", "name": "k8s.pod.uid"}}},
			{"sources": []map[string]any{
				{"from": "resource_attribute", "name": "k8s.pod.name"},
				{"from": "resource_attribute", "name": "k8s.namespace.name"},
			}},
			{"sources": []map[string]any{{"from": "resource_attribute", "name": "k8s.pod.ip"}}},
			{"sources": []map[string]any{{"from": "connection"}}},
		},
		"extract": map[string]any{
			"metadata": []string{
				"k8s.namespace.name",
				"k8s.pod.name",
				"k8s.pod.uid",
				"k8s.pod.start_time",
				"k8s.node.name",
				"k8s.deployment.name",
				"k8s.replicaset.name",
				"k8s.daemonset.name",
				"k8s.statefulset.name",
				"k8s.job.name",
				"k8s.cronjob.name",
				"container.id",
				"container.image.name",
				"container.image.tag",
			},
			"labels": []map[string]any{
				{"from": "pod", "key_regex": "(.*)", "tag_name": "kubernetes.labels.$$1"},
				{"from": "namespace", "key_regex": "(.*)", "tag_name": "kubernetes.namespace_labels.$$1"},
			},
			"annotations": []map[string]any{
				{"from": "pod", "key_regex": "(.*)", "tag_name": "kubernetes.annotations.$$1"},
				{"from": "namespace", "key_regex": "(.*)", "tag_name": "kubernetes.namespace_annotations.$$1"},
			},
		},
	}
}

// BuildEcsMappingTransformConfig returns an OTTL transform processor config that:
//  1. Sets elastic.mapping.mode = ecs on the scope so the ES exporter translates
//     OTel semconv resource attributes to the ECS field paths previously produced
//     by the filebeatreceiver.
//  2. Renames OTel attributes the ES exporter ECS mode does not remap
//     (k8s.pod.start_time → kubernetes.pod.start_time).
//  3. Adds static ECS fields: orchestrator.type, ecs.version, event.dataset,
//     event.module, and agent.* fields from agentInfo.
func BuildEcsMappingTransformConfig(agentInfo info.Agent) map[string]any {
	resourceStmts := []string{
		`set(attributes["kubernetes.pod.start_time"], attributes["k8s.pod.start_time"]) where attributes["k8s.pod.start_time"] != nil`,
		`delete_key(attributes, "k8s.pod.start_time")`,
		`set(attributes["orchestrator.type"], "kubernetes")`,
		`set(attributes["ecs.version"], "8.0.0")`,
		`set(attributes["agent.type"], "elastic-agent")`,
	}
	if id := agentInfo.AgentID(); id != "" {
		resourceStmts = append(resourceStmts, fmt.Sprintf(`set(attributes["agent.id"], %q)`, id))
	}
	if v := agentInfo.Version(); v != "" {
		resourceStmts = append(resourceStmts, fmt.Sprintf(`set(attributes["agent.version"], %q)`, v))
	}
	// agent.name is the hostname of the node. In a DaemonSet the pod hostname
	// equals the node name, so os.Hostname() is the right source.
	if hostname, err := os.Hostname(); err == nil && hostname != "" {
		resourceStmts = append(resourceStmts, fmt.Sprintf(`set(attributes["agent.name"], %q)`, hostname))
	}

	return map[string]any{
		"log_statements": []map[string]any{
			{
				"context":    "scope",
				"statements": []string{`set(attributes["elastic.mapping.mode"], "ecs")`},
			},
			{
				"context":    "resource",
				"statements": resourceStmts,
			},
			{
				"context": "log",
				"statements": []string{
					`set(attributes["event.dataset"], "kubernetes.container_logs")`,
					`set(attributes["event.module"], "kubernetes")`,
				},
			},
		},
	}
}
