// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

// Package kubernetes rewrites the Kubernetes container-logs integration from one
// filestream input per discovered container into a single static filestream
// input watching a glob path.
//
// The kubernetes dynamic provider renders the container-logs input once per
// container it discovers, because the input's paths, ids and processors are
// templated with ${kubernetes.*} variable references. That costs one filestream
// input (and one registry entry) per container, and re-renders the whole
// component model on every pod event.
//
// This package strips those variable references before AST rendering so the
// input renders exactly once, and adds an add_kubernetes_metadata processor to
// restore the kubernetes.* fields the dynamic provider used to inject.
package kubernetes

import (
	"regexp"
	"slices"
	"strings"
)

const (
	// containerLogsDataset is the data_stream.dataset value that identifies the
	// Kubernetes container-logs integration stream.
	containerLogsDataset = "kubernetes.container_logs"
)

// k8sVarPattern matches elastic-agent variable references scoped to the
// kubernetes provider, e.g. ${kubernetes.container.id}.
var k8sVarPattern = regexp.MustCompile(`\$\{kubernetes\.[^}]*\}`)

// k8sAnnotationVarPattern captures the annotation key out of a reference such as
// ${kubernetes.annotations.elastic.co/dataset|""}. Group 1 is the raw (not
// dedotted) annotation key as it appears on the pod.
var k8sAnnotationVarPattern = regexp.MustCompile(`\$\{kubernetes\.annotations\.([^}|\s]+)(?:\|[^}]*)?\}`)

// anyVarPattern matches any elastic-agent variable reference of the form
// ${provider.key}. Used as a defensive fallback when translating path templates
// that may still contain non-kubernetes provider references.
var anyVarPattern = regexp.MustCompile(`\$\{[^}]+\}`)

// consecutiveStarsPattern matches two or more consecutive * characters produced
// when a path contains a literal wildcard adjacent to a variable reference
// (e.g. *${kubernetes.container.id}).
var consecutiveStarsPattern = regexp.MustCompile(`\*{2,}`)

// separatorRunPattern matches a run of the separators used to join variable
// references into ids, left behind once the references are removed.
var separatorRunPattern = regexp.MustCompile(`[-_.]{2,}`)

// hintsVarPrefix is the variable prefix used by the hints-based autodiscovery
// templates. Inputs referencing it are genuinely per-container and must not be
// collapsed into a single glob input.
const hintsVarPrefix = "${kubernetes.hints."

// translateVarPathToGlob replaces all ${...} variable references with *
// wildcards, converting a policy path template into a stable file-glob pattern.
// Adjacent wildcards are collapsed to a single * to avoid double-star globs.
func translateVarPathToGlob(path string) string {
	withWildcards := anyVarPattern.ReplaceAllString(path, "*")
	return consecutiveStarsPattern.ReplaceAllString(withWildcards, "*")
}

// RewriteContainerLogInputs rewrites every eligible kubernetes.container_logs
// input in the raw config map produced by cfg.ToMapStr(), in place, before the
// coordinator passes it to generateAST. Each eligible input is turned into a
// static input by:
//
//   - translating ${kubernetes.*} references in stream paths into glob wildcards
//   - stripping ${kubernetes.*} references from input and stream ids
//   - dropping stream processors that reference ${kubernetes.*} (they can only
//     be resolved per-container) and replacing them with a single
//     add_kubernetes_metadata processor
//
// Inputs that are genuinely per-container — hints-based autodiscovery templates,
// or anything carrying a condition — are left untouched. Streams that do not
// belong to the container-logs integration are left untouched, and an input is
// only rewritten when all of its streams belong to it.
func RewriteContainerLogInputs(m map[string]interface{}) {
	inputList, ok := m["inputs"].([]interface{})
	if !ok {
		return
	}
	for _, input := range inputList {
		inputMap, ok := input.(map[string]interface{})
		if !ok {
			continue
		}
		if !isRewritableContainerLogInput(inputMap) {
			continue
		}
		rewriteContainerLogInput(inputMap)
	}
}

// isContainerLogStream reports whether a raw stream config map (as produced by
// cfg.ToMapStr()) belongs to the Kubernetes container-logs integration by
// checking data_stream.dataset.
func isContainerLogStream(stream map[string]interface{}) bool {
	ds, ok := stream["data_stream"].(map[string]interface{})
	if !ok {
		return false
	}
	return ds["dataset"] == containerLogsDataset
}

// isRewritableContainerLogInput reports whether the input can be collapsed into
// a single static filestream. Every stream must belong to the container-logs
// integration, nothing may carry a condition (conditions are evaluated per
// variable set, so a conditional input stays dynamic by design), and the input
// must not reference the hints provider.
func isRewritableContainerLogInput(input map[string]interface{}) bool {
	streams, ok := input["streams"].([]interface{})
	if !ok || len(streams) == 0 {
		return false
	}
	if _, hasCondition := input["condition"]; hasCondition {
		return false
	}
	for _, stream := range streams {
		streamMap, ok := stream.(map[string]interface{})
		if !ok {
			return false
		}
		if !isContainerLogStream(streamMap) {
			return false
		}
		if _, hasCondition := streamMap["condition"]; hasCondition {
			return false
		}
	}
	return !referencesHintsProvider(input)
}

// referencesHintsProvider reports whether any string anywhere in the input tree
// references the kubernetes hints provider.
func referencesHintsProvider(input map[string]interface{}) bool {
	found := false
	walkStrings(input, func(s string) {
		if strings.Contains(s, hintsVarPrefix) {
			found = true
		}
	})
	return found
}

// rewriteContainerLogInput performs the in-place rewrite described on
// RewriteContainerLogInputs for a single, already validated, input.
func rewriteContainerLogInput(input map[string]interface{}) {
	stripVarsFromIDField(input, "id")
	stripVarsFromIDField(input, "name")

	streams, _ := input["streams"].([]interface{})
	for _, stream := range streams {
		streamMap, _ := stream.(map[string]interface{})
		stripVarsFromIDField(streamMap, "id")
		paths := rewriteStreamPaths(streamMap)
		processors, annotations := filterVarProcessors(streamMap["processors"])
		streamMap["processors"] = append(
			[]interface{}{buildAddKubernetesMetadataProcessor(paths, annotations)},
			processors...,
		)
	}
}

// rewriteStreamPaths translates the stream's configured paths into stable globs
// and returns them. Returns nil when the stream has no usable paths.
func rewriteStreamPaths(stream map[string]interface{}) []string {
	pathList, ok := stream["paths"].([]interface{})
	if !ok {
		return nil
	}
	globs := make([]string, 0, len(pathList))
	for i, path := range pathList {
		pathStr, ok := path.(string)
		if !ok {
			continue
		}
		glob := translateVarPathToGlob(pathStr)
		pathList[i] = glob
		globs = append(globs, glob)
	}
	return globs
}

// filterVarProcessors splits a stream's processor list into the processors that
// survive the rewrite and the kubernetes annotation keys referenced by the ones
// that don't. A processor referencing ${kubernetes.*} can only be resolved for a
// specific container, so it cannot survive on a static input; the annotation
// keys it looked up are handed to add_kubernetes_metadata's include_annotations
// instead, which publishes them under the same dedotted field names.
//
// Any add_kubernetes_metadata already present is dropped too, so that rewriting
// an already rewritten config is a no-op rather than stacking a second copy of
// the processor.
//
// The returned annotation keys are sorted: they are collected by walking maps,
// and an unstable order here would change the rendered config hash on every
// policy change and trigger needless component restarts.
func filterVarProcessors(raw interface{}) (kept []interface{}, annotations []string) {
	processors, ok := raw.([]interface{})
	if !ok {
		return nil, nil
	}
	seen := make(map[string]struct{})
	kept = make([]interface{}, 0, len(processors))
	for _, processor := range processors {
		referencesVar := false
		walkStrings(processor, func(s string) {
			for _, match := range k8sAnnotationVarPattern.FindAllStringSubmatch(s, -1) {
				if _, exists := seen[match[1]]; !exists {
					seen[match[1]] = struct{}{}
					annotations = append(annotations, match[1])
				}
			}
			if k8sVarPattern.MatchString(s) {
				referencesVar = true
			}
		})
		if existing, isMetadata := addKubernetesMetadataConfig(processor); isMetadata {
			// Carry the annotation list of a processor we added on an earlier pass
			// across, so rewriting an already rewritten config keeps publishing the
			// same annotations.
			for _, annotation := range includedAnnotations(existing) {
				if _, exists := seen[annotation]; !exists {
					seen[annotation] = struct{}{}
					annotations = append(annotations, annotation)
				}
			}
			continue
		}
		if referencesVar {
			continue
		}
		kept = append(kept, processor)
	}
	slices.Sort(annotations)
	return kept, annotations
}

// addKubernetesMetadataConfig returns the configuration of the processor entry
// when it is an add_kubernetes_metadata processor.
func addKubernetesMetadataConfig(processor interface{}) (map[string]interface{}, bool) {
	processorMap, ok := processor.(map[string]interface{})
	if !ok {
		return nil, false
	}
	raw, ok := processorMap[addKubernetesMetadataProcessor]
	if !ok {
		return nil, false
	}
	cfg, _ := raw.(map[string]interface{})
	return cfg, true
}

// includedAnnotations reads the include_annotations list off an
// add_kubernetes_metadata configuration.
func includedAnnotations(cfg map[string]interface{}) []string {
	list, ok := cfg["include_annotations"].([]interface{})
	if !ok {
		return nil
	}
	annotations := make([]string, 0, len(list))
	for _, item := range list {
		if annotation, ok := item.(string); ok {
			annotations = append(annotations, annotation)
		}
	}
	return annotations
}

// stripVarsFromIDField removes ${kubernetes.*} references from an id-like field
// so that the input renders identically for every variable set. Separator runs
// left behind by the removed references are collapsed and trimmed. The field is
// left untouched when stripping would empty it.
func stripVarsFromIDField(m map[string]interface{}, key string) {
	value, ok := m[key].(string)
	if !ok {
		return
	}
	stripped := strings.TrimRight(k8sVarPattern.ReplaceAllString(value, ""), "-_.")
	stripped = separatorRunPattern.ReplaceAllStringFunc(stripped, func(run string) string {
		return run[:1]
	})
	if stripped == "" {
		return
	}
	m[key] = stripped
}

// walkStrings calls fn for every string found in the value tree, descending into
// maps and slices.
func walkStrings(value interface{}, fn func(string)) {
	switch v := value.(type) {
	case string:
		fn(v)
	case map[string]interface{}:
		for _, item := range v {
			walkStrings(item, fn)
		}
	case []interface{}:
		for _, item := range v {
			walkStrings(item, fn)
		}
	}
}
