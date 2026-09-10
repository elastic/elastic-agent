// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

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

// chartContainerLogsPolicy mirrors what the elastic-agent Helm chart renders for
// kubernetes.containers.logs, including the annotation processors.
const chartContainerLogsPolicy = `
inputs:
  - id: filestream-container-logs
    type: filestream
    data_stream:
      namespace: default
    use_output: default
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
          - drop_fields:
              fields:
                - kubernetes.annotations.elastic_co/dataset
              when:
                equals:
                  kubernetes.annotations.elastic_co/dataset: ''
              ignore_missing: true
`

func TestRewriteContainerLogInputs_ChartPolicy(t *testing.T) {
	m := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(m, true)

	input := m["inputs"].([]interface{})[0].(map[string]interface{})
	stream := input["streams"].([]interface{})[0].(map[string]interface{})

	t.Run("path becomes a stable glob", func(t *testing.T) {
		assert.Equal(t, []interface{}{"/var/log/containers/*.log"}, stream["paths"])
	})

	t.Run("stream id loses its per-container suffix", func(t *testing.T) {
		assert.Equal(t, "kubernetes-container-logs", stream["id"])
	})

	t.Run("parsers and scanner settings are untouched", func(t *testing.T) {
		assert.Equal(t, true, stream["prospector.scanner.symlinks"])
		assert.NotNil(t, stream["parsers"])
	})

	processors := stream["processors"].([]interface{})

	t.Run("add_kubernetes_metadata replaces the templated add_fields", func(t *testing.T) {
		require.Len(t, processors, 2, "add_fields dropped, drop_fields kept, add_kubernetes_metadata prepended")

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

	t.Run("annotations referenced by the dropped processor are published instead", func(t *testing.T) {
		metadata := processors[0].(map[string]interface{})["add_kubernetes_metadata"].(map[string]interface{})
		assert.ElementsMatch(t,
			[]interface{}{"elastic.co/dataset", "elastic.co/namespace"},
			metadata["include_annotations"])
	})

	t.Run("processors without variable references survive", func(t *testing.T) {
		_, isDropFields := processors[1].(map[string]interface{})["drop_fields"]
		assert.True(t, isDropFields, "the drop_fields processor should be kept")
	})
}

func TestRewriteContainerLogInputs_RotatedLogsPolicy(t *testing.T) {
	m := mustConfig(t, `
inputs:
  - id: filestream-container-logs
    type: filestream
    streams:
      - id: kubernetes-container-logs-${kubernetes.pod.uid}-${kubernetes.container.name}
        compression: auto
        paths:
          - '/var/log/pods/${kubernetes.namespace}_${kubernetes.pod.name}_${kubernetes.pod.uid}/${kubernetes.container.name}/*.log*'
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
`)
	RewriteContainerLogInputs(m, true)

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

func TestRewriteContainerLogInputs_LeavesDynamicInputsAlone(t *testing.T) {
	testcases := map[string]string{
		"hints autodiscovery template": `
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
`,
		"stream carrying a condition": `
inputs:
  - id: filestream-container-logs
    type: filestream
    streams:
      - id: kubernetes-container-logs-${kubernetes.container.id}
        condition: ${kubernetes.labels.collect} == true
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.container.id}.log
`,
		"input carrying a condition": `
inputs:
  - id: filestream-container-logs
    type: filestream
    condition: ${host.platform} == 'linux'
    streams:
      - id: kubernetes-container-logs-${kubernetes.container.id}
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.container.id}.log
`,
		"another dataset": `
inputs:
  - id: filestream-audit-logs
    type: filestream
    streams:
      - id: kubernetes-audit-logs
        data_stream:
          dataset: kubernetes.audit_logs
          type: logs
        paths:
          - /var/log/kubernetes/kube-apiserver-audit.log
`,
		"input mixing container logs with another dataset": `
inputs:
  - id: filestream-mixed
    type: filestream
    streams:
      - id: kubernetes-container-logs-${kubernetes.container.id}
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.container.id}.log
      - id: kubernetes-audit-logs
        data_stream:
          dataset: kubernetes.audit_logs
          type: logs
        paths:
          - /var/log/kubernetes/kube-apiserver-audit.log
`,
	}

	for name, policy := range testcases {
		t.Run(name, func(t *testing.T) {
			before := mustConfig(t, policy)
			after := mustConfig(t, policy)
			RewriteContainerLogInputs(after, true)
			assert.Equal(t, before, after)
		})
	}
}

func TestRewriteContainerLogInputs_MalformedConfig(t *testing.T) {
	testcases := map[string]string{
		"no inputs":         `outputs: {default: {type: elasticsearch}}`,
		"inputs not a list": `inputs: nope`,
		"input not a map":   `inputs: ["nope"]`,
		"no streams":        `inputs: [{id: x, type: filestream}]`,
		"empty streams":     `inputs: [{id: x, type: filestream, streams: []}]`,
	}

	for name, policy := range testcases {
		t.Run(name, func(t *testing.T) {
			m := mustConfig(t, policy)
			assert.NotPanics(t, func() { RewriteContainerLogInputs(m, true) })
		})
	}
}

func TestRewriteContainerLogInputs_Idempotent(t *testing.T) {
	once := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(once, true)

	twice := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(twice, true)
	RewriteContainerLogInputs(twice, true)

	assert.Equal(t, once, twice)
}

func TestTranslateVarPathToGlob(t *testing.T) {
	testcases := map[string]string{
		"/var/log/containers/*${kubernetes.container.id}.log":                                                                    "/var/log/containers/*.log",
		"/var/log/pods/${kubernetes.namespace}_${kubernetes.pod.name}_${kubernetes.pod.uid}/${kubernetes.container.name}/*.log*": "/var/log/pods/*_*_*/*/*.log*",
		"/var/log/containers/${kubernetes.container.id}.log":                                                                     "/var/log/containers/*.log",
		"/var/log/plain.log": "/var/log/plain.log",
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

	withoutRewrite := mustConfig(t, chartContainerLogsPolicy)
	assert.Equal(t, 3, renderInputCount(withoutRewrite),
		"without the rewrite the provider renders one input per container")

	withRewrite := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(withRewrite, true)
	assert.Equal(t, 1, renderInputCount(withRewrite),
		"after the rewrite the input renders once regardless of container count")
}

func TestRewriteContainerLogInputs_TakeOverWhenEnabled(t *testing.T) {
	m := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(m, true)

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
	m := mustConfig(t, chartContainerLogsPolicy)
	before := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(m, false)

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
	enabled := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(enabled, true)
	enabledStream := enabled["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})

	disabled := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(disabled, false)
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
	RewriteContainerLogInputs(m, true)

	stream := m["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})
	takeOver := stream["take_over"].(map[string]interface{})
	assert.Equal(t, true, takeOver["from_any_id"])
	assert.NotContains(t, takeOver, "from_ids",
		"from_any_id and from_ids are mutually exclusive, and from_any_id subsumes the list")
}

func TestRewriteContainerLogInputs_NoTakeOverForIneligibleInputs(t *testing.T) {
	for _, globInput := range []bool{true, false} {
		t.Run(fmt.Sprintf("globInput=%t", globInput), func(t *testing.T) {
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
			RewriteContainerLogInputs(after, globInput)
			assert.Equal(t, before, after)
		})
	}
}

func TestRewriteContainerLogInputs_DisabledLeavesDynamicInputsAlone(t *testing.T) {
	policy := `
inputs:
  - id: filestream-audit-logs
    type: filestream
    streams:
      - id: kubernetes-audit-logs
        data_stream:
          dataset: kubernetes.audit_logs
          type: logs
        paths:
          - /var/log/kubernetes/kube-apiserver-audit.log
`
	before := mustConfig(t, policy)
	after := mustConfig(t, policy)
	RewriteContainerLogInputs(after, false)
	assert.Equal(t, before, after)
}

// TestRewriteContainerLogInputs_TakeOverNeverBothForms guards the one way this
// rewrite can produce a config Filebeat refuses outright: from_any_id and
// from_ids set on the same stream.
func TestRewriteContainerLogInputs_TakeOverNeverBothForms(t *testing.T) {
	policies := map[string]string{
		"no existing take_over": chartContainerLogsPolicy,
		"policy set from_ids": `
inputs:
  - id: filestream-container-logs
    type: filestream
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
    streams:
      - id: kubernetes-container-logs-${kubernetes.pod.name}-${kubernetes.container.id}
        paths: ['/var/log/containers/*${kubernetes.container.id}.log']
        data_stream: {dataset: kubernetes.container_logs, type: logs}
        take_over: true
`,
	}

	for name, policy := range policies {
		for _, globInput := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/globInput=%t", name, globInput), func(t *testing.T) {
				m := mustConfig(t, policy)
				RewriteContainerLogInputs(m, globInput)

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
		m := mustConfig(t, chartContainerLogsPolicy)
		RewriteContainerLogInputs(m, false)
		assert.True(t, observedProviders(t, m)["kubernetes"],
			"the per-container inputs resolve ${kubernetes.*}, so the provider must run")
	})

	t.Run("not observed once collapsed", func(t *testing.T) {
		m := mustConfig(t, chartContainerLogsPolicy)
		RewriteContainerLogInputs(m, true)
		providers := observedProviders(t, m)
		assert.False(t, providers["kubernetes"],
			"no ${kubernetes.*} reference should survive the rewrite, so the provider must not be started: observed %v", providers)
	})

	t.Run("still observed when another input needs it", func(t *testing.T) {
		m := mustConfig(t, chartContainerLogsPolicy+`
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
		RewriteContainerLogInputs(m, true)
		assert.True(t, observedProviders(t, m)["kubernetes"],
			"hints inputs stay per-container, so the provider must keep running for them")
	})
}
