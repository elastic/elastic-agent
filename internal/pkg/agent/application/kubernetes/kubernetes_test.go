// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/logp"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
	"github.com/elastic/elastic-agent/internal/pkg/composable"
)

// mustConfig parses a YAML document into the same shape config.Config.ToMapStr()
// hands the coordinator: map[string]interface{} all the way down.
func mustConfig(t *testing.T, doc string) map[string]interface{} {
	t.Helper()
	var raw map[interface{}]interface{}
	require.NoError(t, yaml.Unmarshal([]byte(doc), &raw))
	converted, ok := normalize(raw).(map[string]interface{})
	require.True(t, ok, "top level of the document must be a map")
	return converted
}

// normalize converts the map[interface{}]interface{} values produced by
// gopkg.in/yaml.v2 into map[string]interface{}.
func normalize(value interface{}) interface{} {
	switch v := value.(type) {
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, item := range v {
			out[key.(string)] = normalize(item)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			out[i] = normalize(item)
		}
		return out
	default:
		return v
	}
}

func TestRewriteContainerLogInputs_RotatedLogsPolicy(t *testing.T) {
	m := mustConfig(t, `
inputs:
  - id: filestream-container-logs
    type: filestream
    single_input: true
    streams:
      - id: kubernetes-container-logs-${kubernetes.pod.uid}-${kubernetes.container.name}
        compression: auto
        paths:
          - '/var/log/pods/${kubernetes.namespace}_${kubernetes.pod.name}_${kubernetes.pod.uid}/${kubernetes.container.name}/*.log*'
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
`)
	RewriteContainerLogInputs(m, logp.NewNopLogger())

	input := m["inputs"].([]interface{})[0].(map[string]interface{})
	stream := input["streams"].([]interface{})[0].(map[string]interface{})

	assert.Equal(t, []interface{}{"/var/log/pods/*_*_*/*/*.log*"}, stream["paths"])
	assert.Equal(t, "kubernetes-container-logs", stream["id"])
	assert.Equal(t, "auto", stream["compression"], "unrelated stream settings are preserved")

	metadata := stream["processors"].([]interface{})[0].(map[string]interface{})["add_kubernetes_metadata"].(map[string]interface{})
	assert.Equal(t, []interface{}{map[string]interface{}{"pod_uid": nil}}, metadata["indexers"])
	assert.Equal(t, []interface{}{
		map[string]interface{}{
			"logs_path": map[string]interface{}{
				"logs_path":     "/var/log/pods/",
				"resource_type": "pod",
			},
		},
	}, metadata["matchers"])
	assert.NotContains(t, metadata, "include_annotations")
}

// TestMarkContainerLogTakeOver_NonStringID covers the branch where a stream's
// id field is not a string, which must be skipped without panicking.
func TestMarkContainerLogTakeOver_NonStringID(t *testing.T) {
	input := map[string]interface{}{
		"streams": []interface{}{
			map[string]interface{}{
				"id": 42, // not a string
			},
		},
	}
	assert.NotPanics(t, func() { markContainerLogTakeOver(input) })
	// No take_over added for a non-string id.
	stream := input["streams"].([]interface{})[0].(map[string]interface{})
	_, hasTakeOver := stream[takeOverField]
	assert.False(t, hasTakeOver)
}

// TestMarkContainerLogTakeOver_StaticID covers the branch where the stream id
// has no ${kubernetes.*} references so containerLogGlobID returns changes=false
// and the stream is left without a take_over annotation.
func TestMarkContainerLogTakeOver_StaticID(t *testing.T) {
	input := map[string]interface{}{
		"streams": []interface{}{
			map[string]interface{}{
				"id": "static-stream-id", // no kubernetes var refs
			},
		},
	}
	markContainerLogTakeOver(input)
	stream := input["streams"].([]interface{})[0].(map[string]interface{})
	_, hasTakeOver := stream[takeOverField]
	assert.False(t, hasTakeOver, "static id must not get a take_over annotation")
}

// TestRewriteStreamPaths_NonStringPath covers the branch where a path list
// element is not a string; it must be skipped and not contribute to the result.
func TestRewriteStreamPaths_NonStringPath(t *testing.T) {
	stream := map[string]interface{}{
		"paths": []interface{}{
			42, // not a string
			"/var/log/containers/*${kubernetes.container.id}.log",
		},
	}
	globs := rewriteStreamPaths(stream)
	assert.Equal(t, []string{"/var/log/containers/*.log"}, globs)
	// The non-string entry must still be present in the slice unchanged.
	pathList := stream["paths"].([]interface{})
	assert.Equal(t, 42, pathList[0])
}

// TestRewriteStreamPaths_NoPaths covers the branch where the stream has no
// "paths" field (or it is not a list), returning nil.
func TestRewriteStreamPaths_NoPaths(t *testing.T) {
	assert.Nil(t, rewriteStreamPaths(map[string]interface{}{}))
	assert.Nil(t, rewriteStreamPaths(map[string]interface{}{"paths": "not-a-list"}))
}

// TestAddKubernetesMetadataConfig_NonMapProcessor covers the branch where the
// processor value is not a map[string]interface{}.
func TestAddKubernetesMetadataConfig_NonMapProcessor(t *testing.T) {
	cfg, ok := addKubernetesMetadataConfig("just a string")
	assert.False(t, ok)
	assert.Nil(t, cfg)
}

// TestIncludedAnnotations_NonList covers the branch where include_annotations
// is not a []interface{} (e.g. a string or absent), returning nil.
func TestIncludedAnnotations_NonList(t *testing.T) {
	assert.Nil(t, includedAnnotations(map[string]interface{}{}))
	assert.Nil(t, includedAnnotations(map[string]interface{}{
		"include_annotations": "not-a-list",
	}))
}

func TestRewriteContainerLogInputs_Idempotent(t *testing.T) {
	once := mustConfig(t, integrationContainerLogsPolicy)
	RewriteContainerLogInputs(once, logp.NewNopLogger())

	twice := mustConfig(t, integrationContainerLogsPolicy)
	RewriteContainerLogInputs(twice, logp.NewNopLogger())
	RewriteContainerLogInputs(twice, logp.NewNopLogger())

	assert.Equal(t, once, twice)
}

func TestTranslateVarPathToGlob(t *testing.T) {
	testcases := map[string]string{
		"/var/log/containers/*${kubernetes.container.id}.log":                                                                    "/var/log/containers/*.log",
		"/var/log/pods/${kubernetes.namespace}_${kubernetes.pod.name}_${kubernetes.pod.uid}/${kubernetes.container.name}/*.log*": "/var/log/pods/*_*_*/*/*.log*",
		"/var/log/containers/${kubernetes.container.id}.log":                                                                     "/var/log/containers/*.log",
		"/var/log/plain.log":                "/var/log/plain.log",
		"/var/log/pods/**/*.log":            "/var/log/pods/**/*.log",
		"/var/log/pods/**/containers/*.log": "/var/log/pods/**/containers/*.log",
		"${env.CONTAINER_LOG_DIR}/${kubernetes.namespace}_${kubernetes.pod.name}/*.log":       "${env.CONTAINER_LOG_DIR}/*_*/*.log",
		"${env.CONTAINER_LOG_DIR}/${kubernetes.namespace}/${kubernetes.container.name}/*.log": "${env.CONTAINER_LOG_DIR}/*/*/*.log",
	}
	for input, expected := range testcases {
		assert.Equal(t, expected, translateVarPathToGlob(input), "input: %s", input)
	}
}

func TestStripVarsFromIDField(t *testing.T) {
	testcases := []struct {
		name     string
		id       interface{}
		expected interface{}
	}{
		{"trailing references", "container-logs-${kubernetes.pod.name}-${kubernetes.container.id}", "container-logs"},
		{"embedded reference", "prefix-${kubernetes.container.id}-suffix", "prefix-suffix"},
		{"no references", "container-logs", "container-logs"},
		{"only a reference is left alone", "${kubernetes.container.id}", "${kubernetes.container.id}"},
		{"non-string is left alone", 42, 42},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			m := map[string]interface{}{"id": tc.id}
			stripVarsFromIDField(m, "id")
			assert.Equal(t, tc.expected, m["id"])
		})
	}
}

// containerVars builds the variable set the kubernetes dynamic provider emits
// for a single discovered container.
func containerVars(t *testing.T, id, podName, podUID, containerID string) *transpiler.Vars {
	t.Helper()
	mapping, err := transpiler.NewAST(map[string]interface{}{
		"kubernetes": map[string]interface{}{
			"namespace": "default",
			"pod":       map[string]interface{}{"name": podName, "uid": podUID},
			"container": map[string]interface{}{"id": containerID, "name": "app"},
		},
	})
	require.NoError(t, err)
	return transpiler.NewVarsWithProcessorsFromAst(
		id, mapping, "kubernetes", nil, nil, "", "kubernetes")
}

// TestRewriteContainerLogInputs_CollapsesRendering is the point of the whole
// rewrite: the container-logs input must render exactly once no matter how many
// containers the kubernetes provider has discovered.
func TestRewriteContainerLogInputs_CollapsesRendering(t *testing.T) {
	emptyMapping, err := transpiler.NewAST(map[string]interface{}{})
	require.NoError(t, err)
	varsArray := []*transpiler.Vars{
		// varsArray[0] is the context-provider set the composable controller
		// always emits first; it carries no kubernetes mapping.
		transpiler.NewVarsFromAst("", emptyMapping, nil, ""),
		containerVars(t, "kubernetes-1", "pod-a", "uid-a", "aaaa1111"),
		containerVars(t, "kubernetes-2", "pod-b", "uid-b", "bbbb2222"),
		containerVars(t, "kubernetes-3", "pod-c", "uid-c", "cccc3333"),
	}

	renderInputCount := func(m map[string]interface{}) int {
		ast, err := transpiler.NewAST(m)
		require.NoError(t, err)
		inputs, ok := transpiler.Lookup(ast, "inputs")
		require.True(t, ok, "policy must have inputs")
		rendered, _, err := transpiler.RenderInputs(inputs, varsArray)
		require.NoError(t, err)
		list, ok := rendered.Value().([]transpiler.Node)
		require.True(t, ok, "rendered inputs must be a list")
		return len(list)
	}

	withoutRewrite := mustConfig(t, integrationContainerLogsPolicy)
	assert.Equal(t, 3, renderInputCount(withoutRewrite),
		"without the rewrite the provider renders one input per container")

	withRewrite := mustConfig(t, integrationContainerLogsPolicy)
	RewriteContainerLogInputs(withRewrite, logp.NewNopLogger())
	assert.Equal(t, 1, renderInputCount(withRewrite),
		"after the rewrite the input renders once regardless of container count")
}

func TestRewriteContainerLogInputs_TakeOverWhenEnabled(t *testing.T) {
	m := mustConfig(t, integrationContainerLogsPolicy)
	RewriteContainerLogInputs(m, logp.NewNopLogger())

	input := m["inputs"].([]interface{})[0].(map[string]interface{})
	stream := input["streams"].([]interface{})[0].(map[string]interface{})
	takeOver := stream["take_over"].(map[string]interface{})

	assert.Equal(t, true, takeOver["enabled"])
	assert.Equal(t, true, takeOver["from_any_id"],
		"the collapsed input must reclaim the per-container registry keys, whose ids it cannot enumerate")
	// Filebeat rejects a take_over carrying both.
	assert.NotContains(t, takeOver, "from_ids")
}

func TestRewriteContainerLogInputs_TakeOverWhenDisabled(t *testing.T) {
	m := mustConfig(t, withSingleInput(integrationContainerLogsPolicy, false))
	before := mustConfig(t, integrationContainerLogsPolicy)
	RewriteContainerLogInputs(m, logp.NewNopLogger())

	input := m["inputs"].([]interface{})[0].(map[string]interface{})
	stream := input["streams"].([]interface{})[0].(map[string]interface{})
	beforeStream := before["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})

	t.Run("input stays per-container", func(t *testing.T) {
		assert.Equal(t, beforeStream["id"], stream["id"], "id must keep its variable references")
		assert.Equal(t, beforeStream["paths"], stream["paths"], "paths must keep their variable references")
		assert.Equal(t, beforeStream["processors"], stream["processors"], "processors must be untouched")
	})

	t.Run("reclaims the glob id", func(t *testing.T) {
		takeOver := stream["take_over"].(map[string]interface{})
		assert.Equal(t, true, takeOver["enabled"])
		assert.Equal(t, true, takeOver["from_any_id"],
			"switching back off must reclaim what the glob input wrote")
		assert.NotContains(t, takeOver, "from_ids")
	})
}

// TestRewriteContainerLogInputs_TakeOverRoundTrip checks the two directions line
// up: the id the disabled path reclaims is exactly the id the enabled path
// produces, and the pattern the enabled path reclaims matches an id the disabled
// path renders. If either side drifts, toggling the setting silently re-reads
// every file from the start.
func TestRewriteContainerLogInputs_TakeOverRoundTrip(t *testing.T) {
	enabled := mustConfig(t, integrationContainerLogsPolicy)
	RewriteContainerLogInputs(enabled, logp.NewNopLogger())
	enabledStream := enabled["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})

	disabled := mustConfig(t, withSingleInput(integrationContainerLogsPolicy, false))
	RewriteContainerLogInputs(disabled, logp.NewNopLogger())
	disabledStream := disabled["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})

	assert.Equal(t, true, enabledStream["take_over"].(map[string]interface{})["from_any_id"],
		"on must reclaim the per-container ids off renders")
	assert.Equal(t, true, disabledStream["take_over"].(map[string]interface{})["from_any_id"],
		"off must reclaim the single id on produces")

	// The two directions only line up if the id actually differs between them.
	assert.NotEqual(t, enabledStream["id"], disabledStream["id"])
}

func TestRewriteContainerLogInputs_TakeOverReplacesExistingFromIDs(t *testing.T) {
	m := mustConfig(t, `
inputs:
  - id: filestream-container-logs
    type: filestream
    single_input: true
    streams:
      - id: kubernetes-container-logs-${kubernetes.pod.name}-${kubernetes.container.id}
        paths:
          - '/var/log/containers/*${kubernetes.container.id}.log'
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        take_over:
          enabled: true
          from_ids:
            - a-policy-configured-id
`)
	RewriteContainerLogInputs(m, logp.NewNopLogger())

	stream := m["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})
	takeOver := stream["take_over"].(map[string]interface{})
	assert.Equal(t, true, takeOver["from_any_id"])
	assert.NotContains(t, takeOver, "from_ids",
		"from_any_id and from_ids are mutually exclusive, and from_any_id subsumes the list")
}

func TestRewriteContainerLogInputs_NoTakeOverForIneligibleInputs(t *testing.T) {
	{
		t.Run("hints input", func(t *testing.T) {
			// Hints inputs stay per-container by design, so their state must never
			// be handed to or reclaimed from the glob input.
			policy := `
inputs:
  - id: hints-filestream-container-logs-${kubernetes.hints.container_id}
    type: filestream
    streams:
      - id: hints-filestream-container-logs-${kubernetes.hints.container_id}
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.hints.container_id}.log
`
			before := mustConfig(t, policy)
			after := mustConfig(t, policy)
			RewriteContainerLogInputs(after, logp.NewNopLogger())
			assert.Equal(t, before, after)
		})
	}
}

// TestRewriteContainerLogInputs_TakeOverNeverBothForms guards the one way this
// rewrite can produce a config Filebeat refuses outright: from_any_id and
// from_ids set on the same stream.
func TestRewriteContainerLogInputs_TakeOverNeverBothForms(t *testing.T) {
	policies := map[string]string{
		"no existing take_over": integrationContainerLogsPolicy,
		"policy set from_ids": `
inputs:
  - id: filestream-container-logs
    type: filestream
    single_input: true
    streams:
      - id: kubernetes-container-logs-${kubernetes.pod.name}-${kubernetes.container.id}
        paths: ['/var/log/containers/*${kubernetes.container.id}.log']
        data_stream: {dataset: kubernetes.container_logs, type: logs}
        take_over: {enabled: true, from_ids: [some-old-id]}
`,
		"policy set from_any_id": `
inputs:
  - id: filestream-container-logs
    type: filestream
    single_input: true
    streams:
      - id: kubernetes-container-logs-${kubernetes.pod.name}-${kubernetes.container.id}
        paths: ['/var/log/containers/*${kubernetes.container.id}.log']
        data_stream: {dataset: kubernetes.container_logs, type: logs}
        take_over: {enabled: true, from_any_id: true}
`,
		"legacy boolean take_over": `
inputs:
  - id: filestream-container-logs
    type: filestream
    single_input: true
    streams:
      - id: kubernetes-container-logs-${kubernetes.pod.name}-${kubernetes.container.id}
        paths: ['/var/log/containers/*${kubernetes.container.id}.log']
        data_stream: {dataset: kubernetes.container_logs, type: logs}
        take_over: true
`,
	}

	for name, policy := range policies {
		for _, singleInput := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/single_input=%t", name, singleInput), func(t *testing.T) {
				m := mustConfig(t, withSingleInput(policy, singleInput))
				RewriteContainerLogInputs(m, logp.NewNopLogger())

				stream := m["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})
				takeOver, isMap := stream["take_over"].(map[string]interface{})
				require.True(t, isMap, "take_over must be the map form")

				fromAnyID, _ := takeOver["from_any_id"].(bool)
				_, hasFromIDs := takeOver["from_ids"]
				assert.False(t, fromAnyID && hasFromIDs,
					"from_any_id and from_ids are mutually exclusive: %v", takeOver)
				assert.Equal(t, true, takeOver["enabled"])
			})
		}
	}
}

// observedProviders mirrors what Coordinator.observeASTVars feeds to the
// composable controller: the AST's referenced variables reduced to the provider
// names that must be started.
func observedProviders(t *testing.T, m map[string]interface{}) map[string]bool {
	t.Helper()
	ast, err := transpiler.NewAST(m)
	require.NoError(t, err)

	inputs, ok := transpiler.Lookup(ast, "inputs")
	require.True(t, ok, "policy must have inputs")

	providers := map[string]bool{}
	for _, v := range inputs.Vars(nil, "") {
		providers[composable.ProviderNameFromVarName(v)] = true
	}
	return providers
}

// TestRewriteContainerLogInputs_StopsObservingKubernetesProvider is the reason
// the rewrite happens before AST rendering rather than after.
//
// The composable controller starts a dynamic provider only when the AST still
// references it, and stops one that is no longer referenced. Collapsing the
// container-log input removes the last ${kubernetes.*} reference from a
// logs-only policy, so the kubernetes provider — and the pod watch it maintains
// against the API server — is never started at all.
func TestRewriteContainerLogInputs_StopsObservingKubernetesProvider(t *testing.T) {
	t.Run("observed while the per-container inputs remain", func(t *testing.T) {
		m := mustConfig(t, withSingleInput(integrationContainerLogsPolicy, false))
		RewriteContainerLogInputs(m, logp.NewNopLogger())
		assert.True(t, observedProviders(t, m)["kubernetes"],
			"the per-container inputs resolve ${kubernetes.*}, so the provider must run")
	})

	t.Run("not observed once collapsed", func(t *testing.T) {
		m := mustConfig(t, integrationContainerLogsPolicy)
		RewriteContainerLogInputs(m, logp.NewNopLogger())
		providers := observedProviders(t, m)
		assert.False(t, providers["kubernetes"],
			"no ${kubernetes.*} reference should survive the rewrite, so the provider must not be started: observed %v", providers)
	})

	t.Run("still observed when another input needs it", func(t *testing.T) {
		m := mustConfig(t, integrationContainerLogsPolicy+`
  - id: hints-filestream-container-logs-${kubernetes.hints.container_id}
    type: filestream
    streams:
      - id: hints-filestream-container-logs-${kubernetes.hints.container_id}
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.hints.container_id}.log
`)
		RewriteContainerLogInputs(m, logp.NewNopLogger())
		assert.True(t, observedProviders(t, m)["kubernetes"],
			"hints inputs stay per-container, so the provider must keep running for them")
	})
}

// integrationContainerLogsPolicy mirrors what Fleet renders for the Kubernetes
// integration's container logs data stream with its defaults: single_input on,
// ${kubernetes.*} in the stream id and path, and the three annotation mappings
// the integration adds to every event.
const integrationContainerLogsPolicy = `
inputs:
  - id: filestream-container-logs
    type: filestream
    single_input: true
    data_stream:
      namespace: default
    use_output: default
    meta:
      package:
        name: kubernetes
    streams:
      - id: kubernetes-container-logs-${kubernetes.pod.name}-${kubernetes.container.id}
        paths:
          - '/var/log/containers/*${kubernetes.container.id}.log'
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        prospector.scanner.symlinks: true
        parsers:
          - container:
              stream: all
              format: auto
        processors:
          - add_fields:
              target: kubernetes
              fields:
                annotations.elastic_co/dataset: '${kubernetes.annotations.elastic.co/dataset|""}'
                annotations.elastic_co/namespace: '${kubernetes.annotations.elastic.co/namespace|""}'
                annotations.elastic_co/preserve_original_event: '${kubernetes.annotations.elastic.co/preserve_original_event|""}'
          - drop_fields:
              fields:
                - kubernetes.annotations.elastic_co/dataset
              when:
                equals:
                  kubernetes.annotations.elastic_co/dataset: ''
              ignore_missing: true
          - drop_fields:
              fields:
                - kubernetes.annotations.elastic_co/namespace
              when:
                equals:
                  kubernetes.annotations.elastic_co/namespace: ''
              ignore_missing: true
          - add_tags:
              tags: ["preserve_original_event"]
              when:
                and:
                  - has_fields:
                      - kubernetes.annotations.elastic_co/preserve_original_event
                  - regexp:
                      kubernetes.annotations.elastic_co/preserve_original_event: "^(?i)true$"
`

// withSingleInput returns the policy with the integration's single_input setting
// set to enabled.
func withSingleInput(policy string, enabled bool) string {
	return strings.ReplaceAll(policy, "single_input: true", fmt.Sprintf("single_input: %t", enabled))
}

func inputOf(m map[string]interface{}) map[string]interface{} {
	return m["inputs"].([]interface{})[0].(map[string]interface{})
}

func streamOf(m map[string]interface{}) map[string]interface{} {
	return inputOf(m)["streams"].([]interface{})[0].(map[string]interface{})
}

func hasAddKubernetesMetadata(stream map[string]interface{}) bool {
	processors, _ := stream["processors"].([]interface{})
	for _, processor := range processors {
		if _, ok := addKubernetesMetadataConfig(processor); ok {
			return true
		}
	}
	return false
}

// assertKeptPerContainer verifies that the input still renders once per
// container: the id, paths and processors are exactly what the policy carried,
// and the single_input setting has been consumed.
func assertKeptPerContainer(t *testing.T, before, after map[string]interface{}) {
	t.Helper()
	beforeStream, afterStream := streamOf(before), streamOf(after)
	assert.Equal(t, beforeStream["id"], afterStream["id"], "id must keep its variable references")
	assert.Equal(t, beforeStream["paths"], afterStream["paths"], "paths must keep their variable references")
	assert.Equal(t, beforeStream["processors"], afterStream["processors"], "processors must be untouched")
	assert.False(t, hasAddKubernetesMetadata(afterStream), "add_kubernetes_metadata must not be added")
	assert.NotContains(t, inputOf(after), singleInputKey, "single_input is consumed")
}

func TestRewriteContainerLogInputs_IntegrationPolicy(t *testing.T) {
	m := mustConfig(t, integrationContainerLogsPolicy)
	before := mustConfig(t, integrationContainerLogsPolicy)
	RewriteContainerLogInputs(m, logp.NewNopLogger())

	input := inputOf(m)
	stream := streamOf(m)

	t.Run("single_input is consumed", func(t *testing.T) {
		assert.NotContains(t, input, singleInputKey)
	})

	t.Run("path becomes a stable glob", func(t *testing.T) {
		assert.Equal(t, []interface{}{"/var/log/containers/*.log"}, stream["paths"])
	})

	t.Run("stream id loses its per-container suffix", func(t *testing.T) {
		assert.Equal(t, "kubernetes-container-logs", stream["id"])
	})

	t.Run("unrelated settings are untouched", func(t *testing.T) {
		assert.Equal(t, true, stream["prospector.scanner.symlinks"])
		assert.NotNil(t, stream["parsers"])
		assert.Equal(t, "filestream-container-logs", input["id"])
		assert.Equal(t, streamOf(before)["data_stream"], stream["data_stream"])
	})

	processors := stream["processors"].([]interface{})

	t.Run("add_kubernetes_metadata replaces the annotation mappings", func(t *testing.T) {
		require.Len(t, processors, 4, "add_fields dropped, two drop_fields and add_tags kept, add_kubernetes_metadata prepended")

		metadata := processors[0].(map[string]interface{})["add_kubernetes_metadata"].(map[string]interface{})
		assert.Equal(t, []interface{}{map[string]interface{}{"container": nil}}, metadata["indexers"])
		assert.Equal(t, []interface{}{
			map[string]interface{}{
				"logs_path": map[string]interface{}{
					"logs_path":     "/var/log/containers/",
					"resource_type": "container",
				},
			},
		}, metadata["matchers"])
		assert.Equal(t, map[string]interface{}{"enabled": false}, metadata["default_indexers"])
		assert.Equal(t, map[string]interface{}{"enabled": false}, metadata["default_matchers"])
		assert.Equal(t, true, metadata["wait_for_metadata"],
			"enrichment must fail loudly rather than shipping unenriched documents")
		assert.Equal(t, true, metadata["append_fields"],
			"an event that already carries a kubernetes field must still be filled in, not skipped")
	})

	t.Run("every annotation the integration maps is published instead", func(t *testing.T) {
		metadata := processors[0].(map[string]interface{})["add_kubernetes_metadata"].(map[string]interface{})
		assert.Equal(t,
			[]interface{}{"elastic.co/dataset", "elastic.co/namespace", "elastic.co/preserve_original_event"},
			metadata["include_annotations"])
	})

	t.Run("processors without variable references survive in order", func(t *testing.T) {
		original := streamOf(before)["processors"].([]interface{})
		assert.Equal(t, original[1:], processors[1:])
	})
}

func TestRewriteContainerLogInputs_RequiresSingleInput(t *testing.T) {
	const withSetting = `
inputs:
  - id: filestream-container-logs
    type: %s
    %s
    streams:
      - id: kubernetes-container-logs-${kubernetes.container.id}
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.container.id}.log
`

	untouched := map[string]string{
		"setting absent":               fmt.Sprintf(withSetting, "filestream", "use_output: default"),
		"setting is not a boolean":     fmt.Sprintf(withSetting, "filestream", "single_input: 'true'"),
		"not a filestream input":       fmt.Sprintf(withSetting, "logfile", "single_input: true"),
		"a static input from the user": "inputs:\n  - id: x\n    type: filestream\n    streams:\n      - id: s\n        paths: [/var/log/pods/**/*.log]\n",
	}
	for name, policy := range untouched {
		t.Run(name, func(t *testing.T) {
			before := mustConfig(t, policy)
			after := mustConfig(t, policy)
			RewriteContainerLogInputs(after, logp.NewNopLogger())
			assert.Equal(t, before, after, "without single_input: true or false on a filestream input nothing may change")
		})
	}

	t.Run("single_input false keeps one input per container", func(t *testing.T) {
		policy := fmt.Sprintf(withSetting, "filestream", "single_input: false")
		before := mustConfig(t, policy)
		after := mustConfig(t, policy)
		RewriteContainerLogInputs(after, logp.NewNopLogger())
		assertKeptPerContainer(t, before, after)

		takeOver := streamOf(after)["take_over"].(map[string]interface{})
		assert.Equal(t, true, takeOver["from_any_id"],
			"per-container inputs must reclaim what the glob input wrote, so toggling loses no read positions")
	})
}

type fallbackCase struct {
	name        string
	inputExtra  string // lines at input level, indented four spaces
	streamID    string
	path        string
	streamExtra string // lines at stream level, indented eight spaces
	processors  string // list items indented ten spaces
	want        string // expected part of the logged reason
}

func (c fallbackCase) yaml() string {
	streamID := c.streamID
	if streamID == "" {
		streamID = "kubernetes-container-logs-${kubernetes.container.id}"
	}
	path := c.path
	if path == "" {
		path = "/var/log/containers/*${kubernetes.container.id}.log"
	}
	processors := c.processors
	if processors == "" {
		processors = "          - add_tags:\n              tags: [static]"
	}
	return fmt.Sprintf(`
inputs:
  - id: filestream-container-logs
    type: filestream
    single_input: true
%s
    streams:
      - id: %s
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        paths:
          - %s
%s
        processors:
%s
`, c.inputExtra, streamID, path, c.streamExtra, processors)
}

// TestRewriteContainerLogInputs_FallsBackOnDynamicVariable verifies the rule that
// makes the rewrite safe: a dynamic provider variable anywhere except the ids,
// the paths and the annotation mappings means the input cannot be made static, so
// it keeps one input per container and says why.
func TestRewriteContainerLogInputs_FallsBackOnDynamicVariable(t *testing.T) {
	cases := []fallbackCase{
		{
			name:        "stream field",
			streamExtra: "        fields:\n          source_pod: '${kubernetes.pod.name}'",
			want:        "streams[0].fields references the dynamic provider variable ${kubernetes.pod.name}",
		},
		{
			name:       "input field",
			inputExtra: "    meta:\n      pod: '${kubernetes.pod.name}'",
			want:       "meta references the dynamic provider variable ${kubernetes.pod.name}",
		},
		{
			name:        "parsers",
			streamExtra: "        parsers:\n          - container:\n              stream: '${kubernetes.pod.name}'",
			want:        "streams[0].parsers references",
		},
		{
			name:        "stream condition on a kubernetes variable",
			streamExtra: "        condition: ${kubernetes.labels.collect} == true",
			want:        "streams[0].condition references the dynamic provider variable ${kubernetes.labels.collect}",
		},
		{
			name:       "input condition on another dynamic provider",
			inputExtra: "    condition: ${local_dynamic.enabled} == true",
			want:       "condition references the dynamic provider variable ${local_dynamic.enabled}",
		},
		{
			name:       "processor that is not add_fields",
			processors: "          - add_tags:\n              tags: ['${kubernetes.labels.app}']",
			want:       "streams[0].processors[0] references the dynamic provider variable ${kubernetes.labels.app}",
		},
		{
			name:       "add_fields value",
			processors: "          - add_fields:\n              target: foo\n              fields:\n                pod: '${kubernetes.pod.name}'",
			want:       "processors[0].add_fields.fields.pod references",
		},
		{
			name:       "add_fields value mixed with text",
			processors: "          - add_fields:\n              target: foo\n              fields:\n                pod: 'pod-${kubernetes.pod.name}'",
			want:       "processors[0].add_fields.fields.pod references",
		},
		{
			name:       "add_fields value with a fallback",
			processors: "          - add_fields:\n              target: custom\n              fields:\n                pod: '${kubernetes.pod.name|\"\"}'",
			want:       "processors[0].add_fields.fields.pod references",
		},
		{
			name:       "add_fields nested value",
			processors: "          - add_fields:\n              target: custom\n              fields:\n                nested:\n                  pod: '${kubernetes.pod.name}'",
			want:       "processors[0].add_fields.fields.nested references",
		},
		{
			name:       "annotation mapped to a custom target",
			processors: "          - add_fields:\n              target: custom\n              fields:\n                team: '${kubernetes.annotations.example.com/team|\"\"}'",
			want:       "processors[0].add_fields.fields.team references",
		},
		{
			name:       "annotation mapped to another field under kubernetes",
			processors: "          - add_fields:\n              target: kubernetes\n              fields:\n                annotations.team: '${kubernetes.annotations.example.com/team|\"\"}'",
			want:       "processors[0].add_fields.fields.annotations.team references",
		},
		{
			name:       "add_fields without a target mapping an annotation",
			processors: "          - add_fields:\n              fields:\n                annotations.example_com/team: '${kubernetes.annotations.example.com/team|\"\"}'",
			want:       "processors[0].add_fields.fields.annotations.example_com/team references",
		},
		{
			name:       "when inside add_fields",
			processors: "          - add_fields:\n              target: foo\n              fields:\n                env: production\n              when:\n                equals:\n                  host.name: '${kubernetes.pod.name}'",
			want:       "processors[0].add_fields.when references",
		},
		{
			name:       "when beside add_fields",
			processors: "          - add_fields:\n              fields:\n                env: production\n            when:\n              equals:\n                host.name: '${kubernetes.pod.name}'",
			want:       "processors[0].when references",
		},
		{
			name: "another dynamic provider in the path",
			path: "/var/log/containers/*${docker.container.id}.log",
			want: "streams[0].paths[0] references the dynamic provider variable ${docker.container.id}",
		},
		{
			name:     "another dynamic provider in the stream id",
			streamID: "kubernetes-container-logs-${docker.container.id}",
			want:     "streams[0].id references the dynamic provider variable ${docker.container.id}",
		},
		{
			name: "hints provider in the path",
			path: "/var/log/containers/*${kubernetes.hints.container_id}.log",
			want: "streams[0].paths[0] references the kubernetes hints provider",
		},
		{
			name:     "id made only of a variable",
			streamID: "${kubernetes.container.id}",
			want:     "streams[0].id has no static part once its variables are removed",
		},
		{
			name: "path outside the kubelet log directories",
			path: "/var/log/custom/*${kubernetes.container.id}.log",
			want: "streams[0].paths has no path under a kubelet log directory",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			core, logs := observer.New(zap.WarnLevel)
			log := logp.NewLogger("test", zap.WrapCore(func(zapcore.Core) zapcore.Core { return core }))

			before := mustConfig(t, tc.yaml())
			after := mustConfig(t, tc.yaml())
			RewriteContainerLogInputs(after, log)

			assertKeptPerContainer(t, before, after)
			require.Equal(t, 1, logs.Len(), "the fallback must be logged once")
			assert.Contains(t, logs.All()[0].Message, "Keeping one input per container")
			assert.Contains(t, logs.All()[0].Message, tc.want)
		})
	}
}

// TestRewriteContainerLogInputs_ConvertsDespiteStaticSettings verifies the rule
// only reacts to dynamic provider variables: conditions and context provider
// variables are resolved identically for every container, so they survive.
func TestRewriteContainerLogInputs_ConvertsDespiteStaticSettings(t *testing.T) {
	m := mustConfig(t, fallbackCase{
		inputExtra:  "    condition: ${host.platform} == 'linux'",
		streamExtra: "        fields:\n          cluster: '${env.CLUSTER_NAME|\"\"}'",
		processors: "          - add_fields:\n              target: foo\n              fields:\n                cluster: '${env.CLUSTER_NAME|\"\"}'\n" +
			"              when:\n                equals:\n                  host.os.type: linux",
	}.yaml())
	RewriteContainerLogInputs(m, logp.NewNopLogger())

	input := inputOf(m)
	stream := streamOf(m)
	assert.Equal(t, "${host.platform} == 'linux'", input["condition"], "a condition without dynamic variables is kept")
	assert.Equal(t, []interface{}{"/var/log/containers/*.log"}, stream["paths"])
	assert.Equal(t, map[string]interface{}{"cluster": `${env.CLUSTER_NAME|""}`}, stream["fields"])

	processors := stream["processors"].([]interface{})
	require.Len(t, processors, 2)
	assert.True(t, hasAddKubernetesMetadata(stream))
	assert.Equal(t, map[string]interface{}{
		"add_fields": map[string]interface{}{
			"target": "foo",
			"fields": map[string]interface{}{"cluster": `${env.CLUSTER_NAME|""}`},
			"when":   map[string]interface{}{"equals": map[string]interface{}{"host.os.type": "linux"}},
		},
	}, processors[1])
}

// TestRewriteContainerLogInputs_AnnotationMappingKeepsStaticFields verifies the
// annotation mapping include_annotations reproduces is dropped without taking
// the static fields of the same add_fields along with it.
func TestRewriteContainerLogInputs_AnnotationMappingKeepsStaticFields(t *testing.T) {
	m := mustConfig(t, fallbackCase{
		processors: "          - add_fields:\n              target: kubernetes\n              fields:\n" +
			"                annotations.elastic_co/dataset: '${kubernetes.annotations.elastic.co/dataset|\"\"}'\n" +
			"                owner: platform\n" +
			"              when:\n                equals:\n                  host.os.type: linux",
	}.yaml())
	RewriteContainerLogInputs(m, logp.NewNopLogger())

	stream := streamOf(m)
	processors := stream["processors"].([]interface{})
	require.Len(t, processors, 2, "add_kubernetes_metadata and the residual add_fields")

	metadata := processors[0].(map[string]interface{})["add_kubernetes_metadata"].(map[string]interface{})
	assert.Equal(t, []interface{}{"elastic.co/dataset"}, metadata["include_annotations"])

	residual := processors[1].(map[string]interface{})["add_fields"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"owner": "platform"}, residual["fields"])
	assert.Equal(t, "kubernetes", residual["target"])
	assert.Equal(t, map[string]interface{}{"equals": map[string]interface{}{"host.os.type": "linux"}}, residual["when"])
}

func TestRewriteContainerLogInputs_ConvertsEveryStreamOrNone(t *testing.T) {
	const policy = `
inputs:
  - id: filestream-container-logs
    type: filestream
    single_input: true
    streams:
      - id: first-${kubernetes.container.id}
        paths: ['/var/log/containers/*${kubernetes.container.id}.log']
      - id: second-${kubernetes.container.id}
        paths: ['/var/log/containers/*${kubernetes.container.id}.log']
        fields:
          pod: '${kubernetes.pod.name}'
`
	before := mustConfig(t, policy)
	after := mustConfig(t, policy)
	RewriteContainerLogInputs(after, logp.NewNopLogger())

	for i, stream := range after["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{}) {
		streamMap := stream.(map[string]interface{})
		beforeStream := before["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[i].(map[string]interface{})
		assert.Equal(t, beforeStream["id"], streamMap["id"], "stream %d must keep its id: a partial rewrite would duplicate ids", i)
		assert.False(t, hasAddKubernetesMetadata(streamMap), "stream %d", i)
	}
}

func TestRewriteContainerLogInputs_MalformedConfig(t *testing.T) {
	testcases := map[string]string{
		"no inputs":         `outputs: {default: {type: elasticsearch}}`,
		"inputs not a list": `inputs: nope`,
		"input not a map":   `inputs: ["nope"]`,
		"no streams":        `inputs: [{id: x, type: filestream, single_input: true}]`,
		"empty streams":     `inputs: [{id: x, type: filestream, single_input: true, streams: []}]`,
		"stream not a map":  `inputs: [{id: x, type: filestream, single_input: true, streams: [nope]}]`,
		"paths not a list":  `inputs: [{id: x, type: filestream, single_input: true, streams: [{id: s, paths: nope}]}]`,
		"id not a string":   `inputs: [{id: 42, type: filestream, single_input: true, streams: [{id: 7, paths: [/var/log/containers/*.log]}]}]`,
	}

	for name, policy := range testcases {
		t.Run(name, func(t *testing.T) {
			m := mustConfig(t, policy)
			assert.NotPanics(t, func() { RewriteContainerLogInputs(m, logp.NewNopLogger()) })
		})
	}
}
