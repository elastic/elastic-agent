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
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/elastic/elastic-agent-libs/logp"
)

const (
	// containerLogsDataset is the canonical data_stream.dataset value for the
	// Kubernetes container-logs integration.
	containerLogsDataset = "kubernetes.container_logs"

	// containerLogsSuffix is the suffix shared by renamed datasets
	// (e.g. "myteam.container_logs").
	containerLogsSuffix = ".container_logs"

	// fleetPackageName is the value of meta.package.name set by Fleet for every
	// input coming from the Kubernetes integration. It cannot be changed by the
	// user through the Fleet UI, so its presence is treated as certain.
	fleetPackageName = "kubernetes"
)

// containerLogConfidence is a score in the range [0, 100] expressing how
// certain we are that a stream belongs to the Kubernetes container-logs
// integration.
type containerLogConfidence int

const (
	// certainConfidence is assigned when Fleet's immutable meta.package.name
	// field identifies the Kubernetes integration. No further signals are needed.
	certainConfidence containerLogConfidence = 100

	// highConfidence is the minimum score required to rewrite an input without
	// any user-visible log message. Combinations of a kubelet log path and a
	// per-container kubernetes variable in the path each contribute enough to
	// reach this threshold independently.
	highConfidence containerLogConfidence = 70

	// suspectedConfidence is the minimum score at which the input is still
	// rewritten, but a warning is emitted so operators can verify the decision.
	suspectedConfidence containerLogConfidence = 40
)

// k8sVarPattern matches elastic-agent variable references scoped to the
// kubernetes provider, e.g. ${kubernetes.container.id}.
var k8sVarPattern = regexp.MustCompile(`\$\{kubernetes\.[^}]*\}`)

// k8sAnnotationVarPattern captures the annotation key out of a reference such as
// ${kubernetes.annotations.elastic.co/dataset|""}. Group 1 is the raw (not
// dedotted) annotation key as it appears on the pod.
var k8sAnnotationVarPattern = regexp.MustCompile(`\$\{kubernetes\.annotations\.([^}|\s]+)(?:\|[^}]*)?\}`)

// k8sStarAdjacentVarPattern is like starAdjacentVarPattern but only matches
// ${kubernetes.*} references. Used in path translation so that context-provider
// references (${env.*}, ${host.*}, …) are preserved and resolved by the AST.
var k8sStarAdjacentVarPattern = regexp.MustCompile(`\**(\$\{kubernetes\.[^}]+\})+\**`)

// separatorRunPattern matches a run of the separators used to join variable
// references into ids, left behind once the references are removed.
var separatorRunPattern = regexp.MustCompile(`[-_.]{2,}`)

// hintsVarPrefix is the variable prefix used by the hints-based autodiscovery
// templates. Inputs referencing it are genuinely per-container and must not be
// collapsed into a single glob input.
const hintsVarPrefix = "${kubernetes.hints."

// translateVarPathToGlob replaces ${kubernetes.*} variable references with *
// wildcards, converting a policy path template into a stable file-glob pattern.
// Stars immediately adjacent to a kubernetes variable reference are absorbed into
// the replacement so that *${kubernetes.var} becomes * rather than **. Pre-existing
// ** patterns and non-kubernetes provider references (${env.*}, ${host.*}, …) are
// preserved unchanged so the AST can resolve them to their actual values.
func translateVarPathToGlob(path string) string {
	return k8sStarAdjacentVarPattern.ReplaceAllString(path, "*")
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
// appear to belong to the container-logs integration (low confidence score) are
// left untouched, and an input is only rewritten when all of its streams clear
// the suspectedConfidence threshold.
//
// globInput false leaves the per-container inputs in place, but still annotates
// them so the setting can be toggled without losing read positions: see
// markContainerLogTakeOver. Eligibility is evaluated identically either way, so
// an input that would not be collapsed is also never annotated.
func RewriteContainerLogInputs(m map[string]interface{}, globInput bool, log *logp.Logger) {
	inputList, ok := m["inputs"].([]interface{})
	if !ok {
		return
	}
	for _, input := range inputList {
		inputMap, ok := input.(map[string]interface{})
		if !ok {
			continue
		}
		if !isRewritableContainerLogInput(inputMap, log) {
			continue
		}
		if globInput {
			rewriteContainerLogInput(inputMap)
			if log != nil {
				inputID, _ := inputMap["id"].(string)
				log.Infof(
					"Automatically collapsed kubernetes container-log input %q into a single "+
						"glob filestream input. To suppress this message, update your Fleet "+
						"integration to the latest version or update your standalone manifest "+
						"to use the recommended Kubernetes container-logs configuration.",
					inputID,
				)
			}
			continue
		}
		markContainerLogTakeOver(inputMap)
	}
}

// containerLogStreamConfidence returns a confidence score for how likely a
// stream is to be a kubernetes container-logs stream, along with a human-readable
// list of the signals that contributed to the score.
//
// The input map is passed alongside the stream so the Fleet meta.package signal
// (which lives at the input level, not the stream level) can be checked once.
//
// Score thresholds:
//   - certainConfidence  (100): Fleet-managed; meta.package.name == "kubernetes"
//   - highConfidence      (70): multiple strong path/id signals; apply silently
//   - suspectedConfidence (40): some signals; apply but emit a warning
//   - below suspectedConfidence: do not apply
func containerLogStreamConfidence(input, stream map[string]interface{}) (containerLogConfidence, []string) {
	var signals []string
	score := containerLogConfidence(0)

	// Fleet signal: meta.package.name is set by Fleet and is immutable.
	if pkg, ok := nestedString(input, "meta", "package", "name"); ok && pkg == fleetPackageName {
		return certainConfidence, []string{"meta.package.name=kubernetes (Fleet-managed)"}
	}

	// Path signals — check every path in the stream.
	kubeletPathSeen := false
	containerVarSeen := false
	podUIDSeen := false
	podVarSeen := false
	if pathList, ok := stream["paths"].([]interface{}); ok {
		for _, p := range pathList {
			path, ok := p.(string)
			if !ok {
				continue
			}
			if !kubeletPathSeen && isKubeletLogPath(path) {
				kubeletPathSeen = true
				signals = append(signals, fmt.Sprintf("path under kubelet log dir: %s", path))
				score += 40
			}
			if !containerVarSeen && containsAny(path, "${kubernetes.container.id}", "${kubernetes.container.name}") {
				containerVarSeen = true
				signals = append(signals, "path contains ${kubernetes.container.*} variable")
				score += 30
			}
			if !podUIDSeen && strings.Contains(path, "${kubernetes.pod.uid}") {
				podUIDSeen = true
				signals = append(signals, "path contains ${kubernetes.pod.uid}")
				score += 20
			}
			if !podVarSeen && containsAny(path, "${kubernetes.pod.name}", "${kubernetes.namespace}") {
				podVarSeen = true
				signals = append(signals, "path contains kubernetes pod/namespace variable")
				score += 10
			}
		}
	}

	// Dataset signals.
	if ds, ok := stream["data_stream"].(map[string]interface{}); ok {
		if dataset, ok := ds["dataset"].(string); ok {
			if dataset == containerLogsDataset {
				signals = append(signals, fmt.Sprintf("data_stream.dataset=%s (exact match)", dataset))
				score += 30
			} else if strings.HasSuffix(dataset, containerLogsSuffix) {
				signals = append(signals, fmt.Sprintf("data_stream.dataset=%s (suffix match)", dataset))
				score += 15
			}
		}
	}

	// Stream ID signals.
	if id, ok := stream["id"].(string); ok {
		if containsAny(id, "container-log", "container_log") {
			signals = append(signals, fmt.Sprintf("stream id contains container-log pattern: %s", id))
			score += 15
		}
		if k8sVarPattern.MatchString(id) {
			signals = append(signals, "stream id contains ${kubernetes.*} variable")
			score += 10
		}
	}

	return score, signals
}

// isKubeletLogPath reports whether path is rooted at one of the three kubelet-
// managed log directories. These directories are exclusive to container runtimes
// and are a strong signal that the stream is a container-log stream.
func isKubeletLogPath(path string) bool {
	return strings.HasPrefix(path, containerLogsPath) ||
		strings.HasPrefix(path, podLogsPath) ||
		strings.HasPrefix(path, kubeletPodLogsPath)
}

// containsAny reports whether s contains any of the provided substrings.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// nestedString walks a map tree following the given keys and returns the string
// value at the leaf, or ("", false) if any step is missing or not a string.
func nestedString(m map[string]interface{}, keys ...string) (string, bool) {
	var cur interface{} = m
	for _, k := range keys {
		curMap, ok := cur.(map[string]interface{})
		if !ok {
			return "", false
		}
		cur = curMap[k]
	}
	s, ok := cur.(string)
	return s, ok
}

// isRewritableContainerLogInput reports whether the input can be collapsed into
// a single static filestream. Hard disqualifiers (conditions, hints provider)
// are checked first. Then every stream must score at or above suspectedConfidence.
// A warning is logged for streams that score below highConfidence so that
// operators can verify the heuristic decision.
func isRewritableContainerLogInput(input map[string]interface{}, log *logp.Logger) bool {
	streams, ok := input["streams"].([]interface{})
	if !ok || len(streams) == 0 {
		return false
	}
	if _, hasCondition := input["condition"]; hasCondition {
		return false
	}
	if referencesHintsProvider(input) {
		return false
	}

	inputID, _ := input["id"].(string)

	for _, stream := range streams {
		streamMap, ok := stream.(map[string]interface{})
		if !ok {
			return false
		}
		if _, hasCondition := streamMap["condition"]; hasCondition {
			return false
		}

		score, signals := containerLogStreamConfidence(input, streamMap)
		streamID, _ := streamMap["id"].(string)

		if score < suspectedConfidence {
			return false
		}
		if score < highConfidence && log != nil {
			log.Warnf(
				"applying kubernetes container-log glob rewrite to stream %q in input %q "+
					"with low confidence (score %d/%d); verify this is the container-logs integration. "+
					"Detected signals: %s",
				streamID, inputID, score, highConfidence, strings.Join(signals, "; "),
			)
		}
	}
	return true
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
		// The ids this input is replacing were generated per container, so they
		// cannot be enumerated here; from_any_id reclaims them without needing to.
		enableTakeOverFromAnyID(streamMap)
		stripVarsFromIDField(streamMap, "id")
		paths := rewriteStreamPaths(streamMap)
		processors, annotations := filterVarProcessors(streamMap["processors"])
		streamMap["processors"] = append(
			[]interface{}{buildAddKubernetesMetadataProcessor(paths, annotations)},
			processors...,
		)
	}
}

// markContainerLogTakeOver leaves an eligible input rendering per container, but
// has each of its streams reclaim whatever the glob input wrote.
//
// Turning the glob input on moves read positions from many per-container
// registry keys onto one; turning it back off has to move them the other way, or
// everything collected while it was on would be re-read from the start. Because
// the two directions are configured on different inputs, the reverse hand-off
// has to be declared here, while the setting is off, rather than at the moment
// it is switched.
func markContainerLogTakeOver(input map[string]interface{}) {
	streams, _ := input["streams"].([]interface{})
	for _, stream := range streams {
		streamMap, _ := stream.(map[string]interface{})
		id, isString := streamMap["id"].(string)
		if !isString {
			continue
		}
		if _, changes := containerLogGlobID(id); !changes {
			// A static id is unaffected by the glob rewrite, so both settings
			// produce the same input and there is nothing to reclaim.
			continue
		}
		enableTakeOverFromAnyID(streamMap)
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
			if transformed, ok := transformAddFieldsToFieldCopies(processor); ok {
				kept = append(kept, transformed...)
			} else if processorHasNonAnnotationKubernetesVarRef(processor) {
				// Has non-annotation ${kubernetes.*} refs that we cannot transform.
				// Keep the processor: context provider variable references
				// (${host.*}, ${env.*}, …) are resolved by the AST to a single
				// value. Kubernetes dynamic provider references are left for the
				// AST to handle on a best-effort basis — better than silently
				// dropping the processor or reverting the entire input to
				// per-container mode.
				kept = append(kept, processor)
			}
			// Processors whose only kubernetes references are annotation refs are
			// dropped here; add_kubernetes_metadata publishes those annotations via
			// include_annotations so dropping the original processor is correct.
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

// containerLogGlobID returns the id an id-like field takes once the glob rewrite
// removes its ${kubernetes.*} references. Separator runs left behind by the
// removed references are collapsed and trimmed, so
// "kubernetes-container-logs-${kubernetes.pod.name}-${kubernetes.container.id}"
// becomes "kubernetes-container-logs".
//
// Returns ok=false when the value has no references, or when stripping would
// empty it — in both cases the rewrite leaves the field alone, so there is no
// distinct glob id.
func containerLogGlobID(value string) (string, bool) {
	stripped := strings.TrimRight(k8sVarPattern.ReplaceAllString(value, ""), "-_.")
	stripped = separatorRunPattern.ReplaceAllStringFunc(stripped, func(run string) string {
		return run[:1]
	})
	if stripped == "" || stripped == value {
		return "", false
	}
	return stripped, true
}

// stripVarsFromIDField collapses an id-like field to its glob id so that the
// input renders identically for every variable set. The field is left untouched
// when there is no distinct glob id.
func stripVarsFromIDField(m map[string]interface{}, key string) {
	value, isString := m[key].(string)
	if !isString {
		return
	}
	stripped, ok := containerLogGlobID(value)
	if !ok {
		return
	}
	m[key] = stripped
}

const (
	takeOverField     = "take_over"
	takeOverEnabled   = "enabled"
	takeOverFromIDs   = "from_ids"
	takeOverFromAnyID = "from_any_id"
)

// ensureTakeOver returns the stream's take_over map, creating and enabling it if
// absent. A take_over set to the legacy boolean form is replaced by the map form,
// which is the only shape that can carry the settings below.
func ensureTakeOver(stream map[string]interface{}) map[string]interface{} {
	takeOver, _ := stream[takeOverField].(map[string]interface{})
	if takeOver == nil {
		takeOver = map[string]interface{}{}
		stream[takeOverField] = takeOver
	}
	takeOver[takeOverEnabled] = true
	return takeOver
}

// enableTakeOverFromAnyID makes the stream reclaim registry state from every
// previous filestream input, whatever its id was.
//
// The ids being reclaimed were generated one per discovered container, so they
// cannot be listed here — from_any_id exists precisely for that case.
//
// Filebeat rejects a take_over carrying both from_any_id and from_ids, so any
// list the policy configured is dropped. That loses nothing: reclaiming from any
// id is a superset of reclaiming from an enumerated set.
func enableTakeOverFromAnyID(stream map[string]interface{}) {
	takeOver := ensureTakeOver(stream)
	takeOver[takeOverFromAnyID] = true
	delete(takeOver, takeOverFromIDs)
}

// processorHasNonAnnotationKubernetesVarRef reports whether any string value in
// the processor contains a ${kubernetes.*} reference that is NOT an annotation
// reference. Annotation references are handled separately via include_annotations
// and do not need to survive in the processor itself.
func processorHasNonAnnotationKubernetesVarRef(processor interface{}) bool {
	found := false
	walkStrings(processor, func(s string) {
		stripped := k8sAnnotationVarPattern.ReplaceAllString(s, "")
		if k8sVarPattern.MatchString(stripped) {
			found = true
		}
	})
	return found
}

// isExactNonAnnotationKubernetesVarRef reports whether s is entirely a single
// ${kubernetes.*} variable reference that is NOT an annotation reference.
// Mixed or templated strings (surrounding text, multiple refs) return false.
func isExactNonAnnotationKubernetesVarRef(s string) bool {
	return k8sVarPattern.FindString(s) == s && !k8sAnnotationVarPattern.MatchString(s)
}

// transformAddFieldsToFieldCopies converts an add_fields processor whose field
// values are exact non-annotation ${kubernetes.*} variable references into
// copy_fields processors that copy from the event fields added by
// add_kubernetes_metadata. Fields with annotation or mixed variable references
// are omitted (the annotation-extraction pass in filterVarProcessors already
// handles annotation refs via include_annotations). Static fields are preserved
// in a residual add_fields.
//
// Returns the replacement processors and true when at least one field was
// transformed. Returns nil, false for any other processor type or when no field
// could be transformed.
func transformAddFieldsToFieldCopies(processor interface{}) ([]interface{}, bool) {
	processorMap, ok := processor.(map[string]interface{})
	if !ok {
		return nil, false
	}
	addFieldsCfg, ok := processorMap["add_fields"].(map[string]interface{})
	if !ok {
		return nil, false
	}
	fields, ok := addFieldsCfg["fields"].(map[string]interface{})
	if !ok || len(fields) == 0 {
		return nil, false
	}
	target, _ := addFieldsCfg["target"].(string)

	// Iterate in sorted key order for a stable config hash.
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var copySpecs []interface{}
	staticFields := make(map[string]interface{})

	for _, key := range keys {
		val := fields[key]
		strVal, isStr := val.(string)
		if !isStr || !isExactNonAnnotationKubernetesVarRef(strVal) {
			if isStr && k8sVarPattern.MatchString(strVal) {
				// Annotation ref or complex template — drop; annotation key was
				// already extracted by filterVarProcessors above.
				continue
			}
			staticFields[key] = val
			continue
		}
		// Strip ${ and } to get the event-field path, e.g. "kubernetes.pod.name".
		kubernetesField := strVal[2 : len(strVal)-1]
		destField := key
		if target != "" {
			destField = target + "." + key
		}
		copySpecs = append(copySpecs, map[string]interface{}{
			"from": kubernetesField,
			"to":   destField,
		})
	}

	if len(copySpecs) == 0 {
		return nil, false
	}

	var result []interface{}
	if len(staticFields) > 0 {
		result = append(result, map[string]interface{}{
			"add_fields": map[string]interface{}{
				"target": target,
				"fields": staticFields,
			},
		})
	}
	result = append(result, map[string]interface{}{
		"copy_fields": map[string]interface{}{
			"fields":         copySpecs,
			"fail_on_error":  false,
			"ignore_missing": true,
		},
	})
	return result, true
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
