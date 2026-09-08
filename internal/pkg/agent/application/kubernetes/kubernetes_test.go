// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/internal/pkg/agent/transpiler"
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
	RewriteContainerLogInputs(m)

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
	RewriteContainerLogInputs(m)

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
			RewriteContainerLogInputs(after)
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
			assert.NotPanics(t, func() { RewriteContainerLogInputs(m) })
		})
	}
}

func TestRewriteContainerLogInputs_Idempotent(t *testing.T) {
	once := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(once)

	twice := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(twice)
	RewriteContainerLogInputs(twice)

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
	RewriteContainerLogInputs(withRewrite)
	assert.Equal(t, 1, renderInputCount(withRewrite),
		"after the rewrite the input renders once regardless of container count")
}
