// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import "strings"

const (
	// addKubernetesMetadataProcessor is the name of the beats processor that
	// enriches events with Kubernetes metadata looked up from the Kubernetes API.
	addKubernetesMetadataProcessor = "add_kubernetes_metadata"

	// containerLogsPath is the kubelet symlink tree whose filenames encode the
	// container ID: <pod-name>_<namespace>_<container-name>-<container-id>.log
	containerLogsPath = "/var/log/containers/"

	// podLogsPath holds the real container log files, laid out as
	// <namespace>_<pod-name>_<pod-uid>/<container-name>/<n>.log
	podLogsPath = "/var/log/pods/"

	// kubeletPodLogsPath holds logs written into volumes mounted into a pod,
	// laid out as <pod-uid>/volumes/<volume-name>/...
	kubeletPodLogsPath = "/var/lib/kubelet/pods/"
)

// resourceLookup pairs a log path prefix with the add_kubernetes_metadata
// indexer/matcher combination able to resolve metadata for files under it.
type resourceLookup struct {
	logsPath     string
	resourceType string
	indexer      string
}

// resourceLookups is ordered most specific first, so that a stream watching both
// the symlink tree and the real files prefers container-level metadata.
var resourceLookups = []resourceLookup{
	// The container ID sits right before the ".log" suffix of the symlink name,
	// so metadata can be resolved down to the individual container.
	{logsPath: containerLogsPath, resourceType: "container", indexer: "container"},
	// Only the pod UID is recoverable from these paths, so enrichment stops at
	// the pod: no container.* or kubernetes.container.* fields.
	{logsPath: podLogsPath, resourceType: "pod", indexer: "pod_uid"},
	{logsPath: kubeletPodLogsPath, resourceType: "pod", indexer: "pod_uid"},
}

// buildAddKubernetesMetadataProcessor returns an add_kubernetes_metadata
// processor entry that restores the kubernetes.* fields the dynamic provider
// used to inject per container.
//
// The indexers and matchers are derived from paths: which identifier can be
// recovered from a log file depends on which kubelet directory it lives in.
// Paths outside the known kubelet directories fall back to the processor's own
// defaults. annotations lists the raw pod annotation keys to publish (dedotted)
// under kubernetes.annotations.*; the processor only publishes annotations it is
// explicitly asked for.
//
// The node to scope the Kubernetes watch to is deliberately left unset: the
// processor discovers it from the NODE_NAME environment variable, which is
// present in every DaemonSet the agent ships.
func buildAddKubernetesMetadataProcessor(paths []string, annotations []string) map[string]interface{} {
	cfg := map[string]interface{}{
		// Block input startup until the Kubernetes watcher is up. Without this the
		// processor initialises asynchronously and, if it gives up, every document
		// ships silently unenriched — whereas the dynamic provider it replaces
		// simply produced no input at all when the API was unreachable. Failing
		// loudly reproduces that dependency instead of degrading quietly.
		"wait_for_metadata": true,

		// Fill in only the fields an event is missing rather than skipping it.
		// By default the processor returns early from any event that already
		// carries a kubernetes field, so a single kubernetes.* key set upstream —
		// by a processor the policy configured, or by whatever else touched the
		// event first — suppresses the whole enrichment. Merging instead means a
		// partially annotated event still ends up with the same fields as every
		// other one, which is the property the per-container inputs gave for free.
		"append_fields": true,
	}

	var indexers, matchers []interface{}
	seenIndexers := make(map[string]struct{})
	for _, lookup := range resourceLookups {
		if !anyPathUnder(paths, lookup.logsPath) {
			continue
		}
		if _, exists := seenIndexers[lookup.indexer]; !exists {
			seenIndexers[lookup.indexer] = struct{}{}
			indexers = append(indexers, map[string]interface{}{lookup.indexer: nil})
		}
		matchers = append(matchers, map[string]interface{}{
			"logs_path": map[string]interface{}{
				"logs_path":     lookup.logsPath,
				"resource_type": lookup.resourceType,
			},
		})
	}
	if len(matchers) > 0 {
		// The defaults resolve container IDs under /var/lib/docker/containers/,
		// which never matches kubelet log paths. Disable them so a misconfigured
		// path fails loudly instead of silently producing unenriched documents.
		cfg["default_indexers"] = map[string]interface{}{"enabled": false}
		cfg["default_matchers"] = map[string]interface{}{"enabled": false}
		cfg["indexers"] = indexers
		cfg["matchers"] = matchers
	}

	if len(annotations) > 0 {
		includeAnnotations := make([]interface{}, 0, len(annotations))
		for _, annotation := range annotations {
			includeAnnotations = append(includeAnnotations, annotation)
		}
		cfg["include_annotations"] = includeAnnotations
	}

	return map[string]interface{}{addKubernetesMetadataProcessor: cfg}
}

// anyPathUnder reports whether any of paths is rooted at prefix.
func anyPathUnder(paths []string, prefix string) bool {
	for _, path := range paths {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
