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
// input per container (registry entries are per file, not per input), and
// re-renders the whole component model on every pod event.
//
// The integration marks its filestream input with the input-level setting
// single_input. When it is true, this package strips those variable references
// before AST rendering so the input renders exactly once, and adds an
// add_kubernetes_metadata processor to restore the kubernetes.* fields the
// dynamic provider used to inject. A dynamic provider variable anywhere other
// than the places the integration puts one by default keeps one input per
// container instead.
package kubernetes

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/elastic/beats/v7/pkg/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
)

const (
	// singleInputKey is the input-level setting the Kubernetes integration sets on
	// its filestream input to choose between one input for every container (true)
	// and one input per container (false).
	singleInputKey = "single_input"

	// filestreamInputType is the type of the input the integration collects
	// container logs with.
	filestreamInputType = "filestream"
)

// k8sVarPattern matches elastic-agent variable references scoped to the
// kubernetes provider, e.g. ${kubernetes.container.id}.
var k8sVarPattern = regexp.MustCompile(`\$\{kubernetes\.[^}]*\}`)

// k8sExactAnnotationVarPattern matches a value that is nothing but a single
// annotation reference, optionally with an empty-string fallback, such as
// ${kubernetes.annotations.elastic.co/dataset|""}. Group 1 is the raw (not
// dedotted) annotation key as it appears on the pod.
var k8sExactAnnotationVarPattern = regexp.MustCompile(`^\$\{kubernetes\.annotations\.([^}|\s]+)(?:\|\s*"")?\}$`)

// k8sStarAdjacentVarPattern is like starAdjacentVarPattern but only matches
// ${kubernetes.*} references. Used in path translation so that context-provider
// references (${env.*}, ${host.*}, …) are preserved and resolved by the AST.
var k8sStarAdjacentVarPattern = regexp.MustCompile(`\**(\$\{kubernetes\.[^}]+\})+\**`)

// separatorRunPattern matches a run of the separators used to join variable
// references into ids, left behind once the references are removed.
var separatorRunPattern = regexp.MustCompile(`[-_.]{2,}`)

// hintsVarPrefix is the variable prefix used by the hints-based autodiscovery
// templates. Those are genuinely per-container and must never be collapsed into
// a single glob input.
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

// RewriteContainerLogInputs rewrites every filestream input carrying the
// integration's single_input setting in the raw config map produced from
// the policy, in place, before the coordinator passes it to generateAST.
// The setting is consumed: it is removed from every input it is found on.
//
// An input with single_input true is turned into a static input by:
//
//   - translating ${kubernetes.*} references in stream paths into glob wildcards
//   - stripping ${kubernetes.*} references from input and stream ids
//   - dropping the add_fields processors that copy pod annotations into
//     kubernetes.annotations.* (add_kubernetes_metadata publishes those through
//     include_annotations) and prepending a single add_kubernetes_metadata
//     processor
//
// This only happens when the input can be made static without changing what it
// collects. A dynamic provider variable anywhere except the input and stream ids,
// the stream paths and the annotation processors above keeps one input per
// container, as do paths outside the kubelet log directories, where there is no
// way to look up the Kubernetes metadata.
//
// An input with single_input false, or one that cannot be made static, keeps one
// input per container. It is still annotated so the setting can be toggled
// without losing read positions: see markContainerLogTakeOver.
func RewriteContainerLogInputs(m map[string]interface{}, log *logp.Logger) {
	inputList, ok := m["inputs"].([]interface{})
	if !ok {
		return
	}
	for _, input := range inputList {
		inputMap, ok := input.(map[string]interface{})
		if !ok {
			continue
		}
		singleInput, found := singleInputSetting(inputMap)
		if !found {
			continue
		}
		delete(inputMap, singleInputKey)

		inputID, _ := inputMap["id"].(string)
		if singleInput {
			blocker := containerLogConversionBlocker(inputMap)
			if blocker == "" {
				rewriteContainerLogInput(inputMap)
				log.Infof("Collapsed kubernetes container-log input %q into a single glob filestream input", inputID)
				continue
			}
			log.Warnf(
				"Keeping one input per container for kubernetes container-log input %q although %s is enabled: %s",
				inputID, singleInputKey, blocker,
			)
		}
		markContainerLogTakeOver(inputMap)
	}
}

// singleInputSetting reports the value of the single_input setting of a filestream
// input. found is false for any other input type, and when the setting is absent
// or not a boolean.
func singleInputSetting(input map[string]interface{}) (value, found bool) {
	if inputType, _ := input["type"].(string); inputType != filestreamInputType {
		return false, false
	}
	value, found = input[singleInputKey].(bool)
	return value, found
}

// containerLogConversionBlocker returns why the input cannot be collapsed into a
// single static filestream, or "" when it can.
func containerLogConversionBlocker(input map[string]interface{}) string {
	streams, _ := input["streams"].([]interface{})
	if len(streams) == 0 {
		return "the input has no streams"
	}

	if location := firstDynamicVarOutside(input, "streams"); location != "" {
		return location
	}

	for i, stream := range streams {
		streamMap, ok := stream.(map[string]interface{})
		if !ok {
			return fmt.Sprintf("streams[%d] is not a map", i)
		}
		prefix := fmt.Sprintf("streams[%d]", i)

		if location := firstDynamicVarOutside(streamMap, "id", "paths", "processors"); location != "" {
			return prefix + "." + location
		}
		if blocker := idBlocker(streamMap["id"], prefix+".id"); blocker != "" {
			return blocker
		}
		if blocker := pathsBlocker(streamMap["paths"], prefix+".paths"); blocker != "" {
			return blocker
		}
		if blocker := processorsBlocker(streamMap["processors"], prefix+".processors"); blocker != "" {
			return blocker
		}
	}
	return ""
}

// kubernetesProvider is the name of the dynamic provider this rewrite exists for.
const kubernetesProvider = "kubernetes"

// dynamicVarNames returns the names of the dynamic provider variables a string
// references, such as "kubernetes.pod.name", in the order they appear. It reads
// variables the way the coordinator does when it decides which providers to
// start, so fallbacks like ${env.X|kubernetes.pod.name} are seen, and it asks
// the provider registry which providers are dynamic instead of keeping a list.
// The kubernetes provider always counts, so the check still holds for a registry
// that has not been populated.
func dynamicVarNames(value string) []string {
	if !strings.Contains(value, "${") {
		return nil
	}
	var names []string
	for _, name := range transpiler.NewStrVal(value).Vars(nil, "") {
		provider := composable.ProviderNameFromVarName(name)
		if provider == kubernetesProvider || composable.IsDynamic(provider) {
			names = append(names, name)
		}
	}
	return names
}

// firstDynamicVarOutside describes the first dynamic provider variable found in
// m under a key that is not in skip, or returns "".
func firstDynamicVarOutside(m map[string]interface{}, skip ...string) string {
	keys := make([]string, 0, len(m))
	for key := range m {
		if !slices.Contains(skip, key) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	for _, key := range keys {
		if ref, found := firstDynamicVar(m[key]); found {
			return fmt.Sprintf("%s references the dynamic provider variable %s", key, ref)
		}
	}
	return ""
}

// firstDynamicVar returns the first dynamic provider variable expression found
// anywhere in the value tree. Maps are walked in key order so the result is
// stable.
func firstDynamicVar(value interface{}) (string, bool) {
	switch v := value.(type) {
	case string:
		if names := dynamicVarNames(v); len(names) > 0 {
			return "${" + names[0] + "}", true
		}
	case map[string]interface{}:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if ref, found := firstDynamicVar(v[key]); found {
				return ref, true
			}
		}
	case []interface{}:
		for _, item := range v {
			if ref, found := firstDynamicVar(item); found {
				return ref, true
			}
		}
	}
	return "", false
}

// templatedValueBlocker checks a string that is allowed to reference the
// kubernetes provider (an id or a path). It may only contain ${kubernetes.*}
// references that are not hints, because those are the ones the rewrite replaces;
// a variable of any other dynamic provider would keep the input rendering per
// mapping.
func templatedValueBlocker(value, location string) string {
	if strings.Contains(value, hintsVarPrefix) {
		return fmt.Sprintf("%s references the kubernetes hints provider", location)
	}
	for _, name := range dynamicVarNames(value) {
		if !strings.HasPrefix(name, kubernetesProvider+".") {
			return fmt.Sprintf("%s references the dynamic provider variable ${%s}", location, name)
		}
	}
	return ""
}

// idBlocker checks an id-like value. An id made only of variables cannot be
// reduced to a distinct static id.
func idBlocker(value interface{}, location string) string {
	id, isString := value.(string)
	if !isString {
		return ""
	}
	if blocker := templatedValueBlocker(id, location); blocker != "" {
		return blocker
	}
	if k8sVarPattern.MatchString(id) {
		if _, ok := containerLogGlobID(id); !ok {
			return fmt.Sprintf("%s has no static part once its variables are removed", location)
		}
	}
	return ""
}

// pathsBlocker checks the stream paths: each may only reference the kubernetes
// provider, and at least one must be under a kubelet log directory so the
// Kubernetes metadata can be looked up from the file path.
func pathsBlocker(value interface{}, location string) string {
	pathList, _ := value.([]interface{})
	var paths []string
	for i, item := range pathList {
		path, isString := item.(string)
		if !isString {
			continue
		}
		if blocker := templatedValueBlocker(path, fmt.Sprintf("%s[%d]", location, i)); blocker != "" {
			return blocker
		}
		paths = append(paths, path)
	}
	for _, lookup := range resourceLookups {
		if anyPathUnder(paths, lookup.logsPath) {
			return ""
		}
	}
	return fmt.Sprintf("%s has no path under a kubelet log directory to look up Kubernetes metadata from", location)
}

// processorsBlocker checks the stream processors. The only dynamic provider
// variables the rewrite can reproduce are the annotation mappings the integration
// adds by default; anything else would be silently dropped or kept dynamic.
func processorsBlocker(value interface{}, location string) string {
	processors, _ := value.([]interface{})
	for i, processor := range processors {
		ref, found := firstDynamicVar(processor)
		if !found {
			continue
		}
		processorLocation := fmt.Sprintf("%s[%d]", location, i)
		processorMap, _ := processor.(map[string]interface{})
		addFields, _ := processorMap["add_fields"].(map[string]interface{})
		if addFields == nil {
			return fmt.Sprintf("%s references the dynamic provider variable %s", processorLocation, ref)
		}
		if outside := firstDynamicVarOutside(processorMap, "add_fields"); outside != "" {
			return processorLocation + "." + outside
		}
		if outside := firstDynamicVarOutside(addFields, "fields"); outside != "" {
			return processorLocation + ".add_fields." + outside
		}
		target, hasTarget := addFields["target"].(string)
		fields, _ := addFields["fields"].(map[string]interface{})
		for key, val := range fields {
			if _, found := firstDynamicVar(val); !found {
				continue
			}
			if _, ok := annotationMapping(target, hasTarget, key, val); !ok {
				return fmt.Sprintf("%s.add_fields.fields.%s references the dynamic provider variable %s",
					processorLocation, key, ref)
			}
		}
	}
	return ""
}

// annotationMapping reports whether an add_fields entry is exactly the mapping
// that add_kubernetes_metadata's include_annotations publishes on its own: the
// annotation "a.b/c" under kubernetes.annotations.a_b/c. It returns the raw
// annotation key. Any other destination, such as a custom target, is not
// reproducible and must not be treated as one.
func annotationMapping(target string, hasTarget bool, key string, val interface{}) (string, bool) {
	str, isString := val.(string)
	if !isString || !hasTarget || target != "kubernetes" {
		return "", false
	}
	match := k8sExactAnnotationVarPattern.FindStringSubmatch(str)
	if match == nil {
		return "", false
	}
	if key != "annotations."+strings.ReplaceAll(match[1], ".", "_") {
		return "", false
	}
	return match[1], true
}

// rewriteContainerLogInput performs the in-place rewrite described on
// RewriteContainerLogInputs for a single, already validated, input.
func rewriteContainerLogInput(input map[string]interface{}) {
	streams, _ := input["streams"].([]interface{})
	for _, stream := range streams {
		streamMap, _ := stream.(map[string]interface{})
		// The ids this input is replacing were generated per container, so they
		// cannot be enumerated here; from_any_id reclaims them without needing to.
		enableTakeOverFromAnyID(streamMap)
		stripVarsFromIDField(streamMap, "id")
		paths := rewriteStreamPaths(streamMap)
		processors, annotations := dropAnnotationProcessors(streamMap["processors"])
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

// dropAnnotationProcessors removes the processors the rewrite makes redundant and
// returns the rest, along with the pod annotation keys they looked up. The
// annotation mappings the integration adds to every event are handed to
// add_kubernetes_metadata's include_annotations instead, which publishes them
// under the same dedotted field names; an add_fields left with other fields keeps
// them.
//
// The returned annotation keys are sorted: they are collected by walking maps,
// and an unstable order here would change the rendered config hash on every
// policy change and trigger needless component restarts.
func dropAnnotationProcessors(raw interface{}) (kept []interface{}, annotations []string) {
	processors, ok := raw.([]interface{})
	if !ok {
		return nil, nil
	}
	seen := make(map[string]struct{})
	addAnnotation := func(annotation string) {
		if _, exists := seen[annotation]; !exists {
			seen[annotation] = struct{}{}
			annotations = append(annotations, annotation)
		}
	}
	kept = make([]interface{}, 0, len(processors))
	for _, processor := range processors {
		remaining, extracted := extractAnnotationMappings(processor)
		for _, annotation := range extracted {
			addAnnotation(annotation)
		}
		if remaining != nil {
			kept = append(kept, remaining)
		}
	}
	slices.Sort(annotations)
	return kept, annotations
}

// extractAnnotationMappings removes the annotation mappings from an add_fields
// processor. It returns the processor to keep, which is nil when nothing is left
// of it, and the annotation keys that were removed. Any other processor is
// returned as is.
func extractAnnotationMappings(processor interface{}) (interface{}, []string) {
	processorMap, ok := processor.(map[string]interface{})
	if !ok {
		return processor, nil
	}
	addFields, ok := processorMap["add_fields"].(map[string]interface{})
	if !ok {
		return processor, nil
	}
	fields, ok := addFields["fields"].(map[string]interface{})
	if !ok {
		return processor, nil
	}
	target, hasTarget := addFields["target"].(string)

	var annotations []string
	remaining := make(map[string]interface{}, len(fields))
	for key, val := range fields {
		if annotation, isMapping := annotationMapping(target, hasTarget, key, val); isMapping {
			annotations = append(annotations, annotation)
			continue
		}
		remaining[key] = val
	}
	if len(annotations) == 0 {
		return processor, nil
	}
	if len(remaining) == 0 {
		return nil, annotations
	}
	addFields["fields"] = remaining
	return processor, annotations
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
