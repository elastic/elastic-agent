// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package kubernetes

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
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
	RewriteContainerLogInputs(m, true, logp.NewNopLogger())

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

// TestRewriteContainerLogInputs_UserProcessors covers the case reported by
// belimawr: user-defined processors that reference ${kubernetes.*} variables
// were silently dropped after the glob-input rewrite. Exact non-annotation
// ${kubernetes.*} field values in add_fields processors are now converted to
// copy_fields that read from the event fields added by add_kubernetes_metadata.
func TestRewriteContainerLogInputs_UserProcessors(t *testing.T) {
	m := mustConfig(t, `
inputs:
  - id: filestream-container-logs
    type: filestream
    streams:
      - id: 'audit-${kubernetes.container.id}'
        data_stream:
          type: logs
          dataset: kubernetes.container_logs
        paths:
          - '/var/log/containers/*${kubernetes.container.id}.log'
        processors:
          - add_fields:
              target: foo
              fields:
                pod: '${kubernetes.pod.name}'
                namespace: '${kubernetes.namespace}'
                static_label: production
          - add_fields:
              target: ''
              fields:
                myfield: '${kubernetes.container.name}'
`)
	RewriteContainerLogInputs(m, true, logp.NewNopLogger())

	stream := m["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})
	processors := stream["processors"].([]interface{})

	// Expected order:
	//   [0] add_kubernetes_metadata (prepended)
	//   [1] add_fields{target:foo, fields:{static_label:production}} (residual static fields)
	//   [2] copy_fields{foo.namespace, foo.pod} (transformed var refs, sorted by dest)
	//   [3] copy_fields{myfield} (second add_fields, single var ref, root target)
	require.Len(t, processors, 4)

	t.Run("add_kubernetes_metadata is first", func(t *testing.T) {
		_, isMetadata := processors[0].(map[string]interface{})["add_kubernetes_metadata"]
		assert.True(t, isMetadata)
	})

	t.Run("static fields in add_fields are preserved in a residual add_fields", func(t *testing.T) {
		afm := processors[1].(map[string]interface{})["add_fields"].(map[string]interface{})
		fields := afm["fields"].(map[string]interface{})
		assert.Equal(t, "production", fields["static_label"])
		assert.Equal(t, "foo", afm["target"])
		assert.NotContains(t, fields, "pod")
		assert.NotContains(t, fields, "namespace")
	})

	t.Run("kubernetes var refs in add_fields become copy_fields sorted by destination", func(t *testing.T) {
		cfm := processors[2].(map[string]interface{})["copy_fields"].(map[string]interface{})
		assert.Equal(t, false, cfm["fail_on_error"])
		assert.Equal(t, true, cfm["ignore_missing"])
		specs := cfm["fields"].([]interface{})
		require.Len(t, specs, 2)
		s0 := specs[0].(map[string]interface{})
		s1 := specs[1].(map[string]interface{})
		// sorted by destination: foo.namespace < foo.pod
		assert.Equal(t, "kubernetes.namespace", s0["from"])
		assert.Equal(t, "foo.namespace", s0["to"])
		assert.Equal(t, "kubernetes.pod.name", s1["from"])
		assert.Equal(t, "foo.pod", s1["to"])
	})

	t.Run("empty target add_fields with var ref becomes root-level copy_fields", func(t *testing.T) {
		cfm := processors[3].(map[string]interface{})["copy_fields"].(map[string]interface{})
		specs := cfm["fields"].([]interface{})
		require.Len(t, specs, 1)
		s := specs[0].(map[string]interface{})
		assert.Equal(t, "kubernetes.container.name", s["from"])
		assert.Equal(t, "myfield", s["to"])
	})
}

// TestRewriteContainerLogInputs_UntransformableK8sVarDisqualifiesInput verifies
// that a stream with a non-annotation ${kubernetes.*} reference in an
// untransformable location (e.g. add_tags tags, a non-fields add_fields key,
// any non-add_fields processor) causes the whole input to be left unchanged.
func TestRewriteContainerLogInputs_UntransformableK8sVarDisqualifiesInput(t *testing.T) {
	const cfg = `
inputs:
  - id: filestream-container-logs
    type: filestream
    streams:
      - id: kubernetes-container-logs-${kubernetes.container.id}
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.container.id}.log
        processors:
          - add_tags:
              tags: ['${kubernetes.labels.app}']
          - add_fields:
              target: host
              fields:
                name: '${host.name}'
`
	before := mustConfig(t, cfg)
	after := mustConfig(t, cfg)
	RewriteContainerLogInputs(after, true, logp.NewNopLogger())
	assert.Equal(t, before, after, "input with untransformable kubernetes var must not be rewritten")
}

// TestRewriteContainerLogInputs_KubernetesVarInWhenDisqualifiesInput verifies
// that a ${kubernetes.*} reference inside a processor's when: condition
// disqualifies the input from the glob rewrite.
func TestRewriteContainerLogInputs_KubernetesVarInWhenDisqualifiesInput(t *testing.T) {
	const cfg = `
inputs:
  - id: filestream-container-logs
    type: filestream
    streams:
      - id: kubernetes-container-logs-${kubernetes.container.id}
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.container.id}.log
        processors:
          - add_fields:
              target: labels
              fields:
                app: '${kubernetes.labels.app}'
            when:
              equals:
                host.name: '${kubernetes.pod.name}'
`
	before := mustConfig(t, cfg)
	after := mustConfig(t, cfg)
	RewriteContainerLogInputs(after, true, logp.NewNopLogger())
	assert.Equal(t, before, after, "input with kubernetes var in when: must not be rewritten")
}

// TestRewriteContainerLogInputs_StaticWhenCarriedToGeneratedProcessors verifies
// that a static when: condition on an add_fields processor is forwarded to
// the copy_fields (and residual add_fields) processors generated in its place.
func TestRewriteContainerLogInputs_StaticWhenCarriedToGeneratedProcessors(t *testing.T) {
	m := mustConfig(t, `
inputs:
  - id: filestream-container-logs
    type: filestream
    streams:
      - id: kubernetes-container-logs-${kubernetes.container.id}
        data_stream:
          dataset: kubernetes.container_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.container.id}.log
        processors:
          - add_fields:
              target: labels
              fields:
                app: '${kubernetes.labels.app}'
                env: production
            when:
              equals:
                host.os.type: linux
`)
	RewriteContainerLogInputs(m, true, logp.NewNopLogger())

	stream := m["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})
	processors := stream["processors"].([]interface{})

	// [0] add_kubernetes_metadata, [1] residual add_fields (env:production), [2] copy_fields (app)
	require.Len(t, processors, 3)

	wantWhen := map[string]interface{}{"equals": map[string]interface{}{"host.os.type": "linux"}}

	t.Run("residual add_fields carries when", func(t *testing.T) {
		pm := processors[1].(map[string]interface{})
		assert.Equal(t, wantWhen, pm["when"])
	})

	t.Run("copy_fields carries when", func(t *testing.T) {
		pm := processors[2].(map[string]interface{})
		assert.Equal(t, wantWhen, pm["when"])
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
	RewriteContainerLogInputs(m, true, logp.NewNopLogger())

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
			RewriteContainerLogInputs(after, true, logp.NewNopLogger())
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
			assert.NotPanics(t, func() { RewriteContainerLogInputs(m, true, logp.NewNopLogger()) })
		})
	}
}

// TestContainerLogStreamConfidence covers the scoring function directly.
func TestContainerLogStreamConfidence(t *testing.T) {
	cases := []struct {
		name      string
		inputYAML string // YAML for a single input; stream is the first stream
		wantMin   containerLogConfidence
		wantMax   containerLogConfidence
	}{
		{
			// meta.package.name contributes a bonus but does not short-circuit
			// to certainty. A stream with a container-log id pattern and a
			// kubernetes variable in the id lands between suspectedConfidence
			// and highConfidence (score=55: +30 package, +15 id pattern, +10 k8s var).
			name: "Fleet meta.package.name=kubernetes with non-standard path → suspected",
			inputYAML: `
meta:
  package:
    name: kubernetes
    version: 1.52.0
streams:
  - id: container-log-${kubernetes.pod.name}
    data_stream:
      dataset: myteam.custom_logs
    paths:
      - /custom/path/*.log
`,
			wantMin: suspectedConfidence,
			wantMax: highConfidence - 1,
		},
		{
			// An audit-log stream co-located in a kubernetes-package input must
			// NOT reach suspectedConfidence: its path and dataset produce no
			// signals, so the package bonus (30) leaves it below the threshold (40).
			name: "Fleet meta.package.name=kubernetes with audit-log stream → below threshold",
			inputYAML: `
meta:
  package:
    name: kubernetes
    version: 1.52.0
streams:
  - data_stream:
      dataset: kubernetes.audit_logs
    paths:
      - /var/log/kubernetes/kube-apiserver-audit.log
`,
			wantMin: 0,
			wantMax: suspectedConfidence - 1,
		},
		{
			name: "kubelet path + container.id var → high confidence",
			inputYAML: `
streams:
  - id: kubernetes-container-logs-${kubernetes.container.id}
    data_stream:
      dataset: kubernetes.container_logs
    paths:
      - /var/log/containers/*${kubernetes.container.id}.log
`,
			wantMin: highConfidence,
			wantMax: 999,
		},
		{
			name: "renamed dataset + kubelet path → high confidence",
			inputYAML: `
streams:
  - id: kubernetes-container-logs-${kubernetes.container.id}
    data_stream:
      dataset: myteam.container_logs
    paths:
      - /var/log/containers/*${kubernetes.container.id}.log
`,
			wantMin: highConfidence,
			wantMax: 999,
		},
		{
			name: "exact dataset + stream ID pattern + kubernetes var in id → suspected",
			inputYAML: `
streams:
  - id: kubernetes-container-logs-${kubernetes.pod.name}
    data_stream:
      dataset: kubernetes.container_logs
    paths:
      - /custom/app/logs/*.log
`,
			wantMin: suspectedConfidence,
			wantMax: highConfidence - 1,
		},
		{
			name: "unrelated audit log stream → below threshold",
			inputYAML: `
streams:
  - id: kubernetes-audit-logs
    data_stream:
      dataset: kubernetes.audit_logs
    paths:
      - /var/log/kubernetes/kube-apiserver-audit.log
`,
			wantMin: 0,
			wantMax: suspectedConfidence - 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := mustConfig(t, "inputs:\n  - "+indentYAML(tc.inputYAML, "    "))
			inputList := m["inputs"].([]interface{})
			input := inputList[0].(map[string]interface{})
			streams := input["streams"].([]interface{})
			stream := streams[0].(map[string]interface{})
			// Remove streams from input map to match function expectations
			inputWithoutStreams := make(map[string]interface{})
			for k, v := range input {
				if k != "streams" {
					inputWithoutStreams[k] = v
				}
			}
			score, signals := containerLogStreamConfidence(inputWithoutStreams, stream)
			assert.GreaterOrEqual(t, score, tc.wantMin, "signals: %v", signals)
			assert.LessOrEqual(t, score, tc.wantMax, "signals: %v", signals)
		})
	}
}

// TestRewriteContainerLogInputs_FleetManaged verifies that Fleet-managed inputs
// (with meta.package.name=kubernetes) are rewritten even when the dataset is
// renamed, without requiring any warning log.
func TestRewriteContainerLogInputs_FleetManaged(t *testing.T) {
	policy := `
inputs:
  - id: filestream-container-logs
    type: filestream
    meta:
      package:
        name: kubernetes
        version: 1.52.0
    streams:
      - id: container-log-${kubernetes.pod.name}-${kubernetes.container.id}
        data_stream:
          dataset: myteam.custom_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.container.id}.log
`
	log := logp.NewLogger("test")
	m := mustConfig(t, policy)
	RewriteContainerLogInputs(m, true, log)

	streams := m["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})
	stream := streams[0].(map[string]interface{})
	assert.Equal(t, []interface{}{"/var/log/containers/*.log"}, stream["paths"],
		"Fleet-managed input with renamed dataset must still be rewritten")
}

// TestRewriteContainerLogInputs_RenamedDataset verifies that standalone inputs
// with a renamed dataset are rewritten when other signals provide sufficient
// confidence (kubelet path + container variable).
func TestRewriteContainerLogInputs_RenamedDataset(t *testing.T) {
	policy := `
inputs:
  - id: filestream-container-logs
    type: filestream
    streams:
      - id: kubernetes-container-logs-${kubernetes.container.id}
        data_stream:
          dataset: myteam.container_logs
          type: logs
        paths:
          - /var/log/containers/*${kubernetes.container.id}.log
`
	log := logp.NewLogger("test")
	m := mustConfig(t, policy)
	RewriteContainerLogInputs(m, true, log)

	streams := m["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})
	stream := streams[0].(map[string]interface{})
	assert.Equal(t, []interface{}{"/var/log/containers/*.log"}, stream["paths"],
		"renamed dataset with kubelet path + container var must still be rewritten")
}

// TestContainerLogStreamConfidence_NonStringPath covers the branch where a path
// list element is not a string (e.g. an integer in the raw config map). The
// non-string entry must be silently skipped so other paths still contribute.
func TestContainerLogStreamConfidence_NonStringPath(t *testing.T) {
	input := map[string]interface{}{}
	stream := map[string]interface{}{
		"paths": []interface{}{
			42, // not a string — must be skipped
			"/var/log/containers/*${kubernetes.container.id}.log",
		},
		"data_stream": map[string]interface{}{"dataset": containerLogsDataset},
	}
	score, signals := containerLogStreamConfidence(input, stream)
	// kubelet path (40) + container var (30) + exact dataset (30) = 100
	assert.GreaterOrEqual(t, score, highConfidence, "non-string path skipped; remaining paths still scored: %v", signals)
}

// TestIsRewritableContainerLogInput_NonMapStream covers the branch where a
// stream list entry is not a map, which must make the input ineligible.
func TestIsRewritableContainerLogInput_NonMapStream(t *testing.T) {
	input := map[string]interface{}{
		"id": "test-input",
		"streams": []interface{}{
			"not-a-map", // stream entry is a plain string, not a map
		},
	}
	assert.False(t, isRewritableContainerLogInput(input, logp.NewNopLogger()))
}

// TestIsRewritableContainerLogInput_SuspectedWithLogger covers the Warnf branch:
// a stream that scores in [suspectedConfidence, highConfidence) triggers a
// warning and is still considered eligible.
func TestIsRewritableContainerLogInput_SuspectedWithLogger(t *testing.T) {
	// exact dataset (30) + stream ID prefix (15) + stream ID k8s var (10) = 55 → suspected
	input := map[string]interface{}{
		"id": "my-input",
		"streams": []interface{}{
			map[string]interface{}{
				"id":          "kubernetes-container-logs-${kubernetes.pod.name}",
				"data_stream": map[string]interface{}{"dataset": containerLogsDataset},
				"paths":       []interface{}{"/custom/app/logs/*.log"},
			},
		},
	}
	core, logs := observer.New(zap.WarnLevel)
	log, err := logp.NewZapLogger(zap.New(core))
	require.NoError(t, err)

	eligible := isRewritableContainerLogInput(input, log)
	assert.True(t, eligible, "suspected-confidence input must still be eligible")
	assert.Equal(t, 1, logs.Len(), "expected exactly one warning to be emitted")
	assert.Contains(t, logs.All()[0].Message, "low confidence", "warning must mention low confidence")
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

// TestRewriteContainerLogInputs_LeavesStaticPathInputAlone verifies that an
// input whose paths and ids contain no ${kubernetes.*} variable references is
// never rewritten, even when it otherwise looks like a container-log stream
// (matching dataset and a kubelet log path). Such inputs were never produced
// by the kubernetes dynamic provider and must be left untouched; in particular,
// ** glob patterns in their paths must not be collapsed to *.
func TestRewriteContainerLogInputs_LeavesStaticPathInputAlone(t *testing.T) {
	const cfg = `
inputs:
  - id: k8s-static-ingestion
    type: filestream
    streams:
      - id: k8s-static-ingestion
        data_stream:
          type: logs
          dataset: kubernetes.container_logs
        paths:
          - /var/log/pods/**/*.log
        prospector.scanner.symlinks: true
`
	before := mustConfig(t, cfg)
	after := mustConfig(t, cfg)
	RewriteContainerLogInputs(after, true, logp.NewNopLogger())
	assert.Equal(t, before, after, "static-path input (no kubernetes vars) must not be rewritten")
}

// TestRewriteContainerLogInputs_LeavesNonContainerLogKubernetesInputAlone
// verifies that an input from the kubernetes Fleet package whose streams are
// not container logs (e.g. audit logs) is left completely unchanged. The
// package signal alone (score=30) does not reach suspectedConfidence (40), so
// the input must not be rewritten at all.
func TestRewriteContainerLogInputs_LeavesNonContainerLogKubernetesInputAlone(t *testing.T) {
	policy := `
inputs:
  - id: audit-log
    type: filestream
    meta:
      package:
        name: kubernetes
        version: 1.52.0
    streams:
      - data_stream:
          dataset: kubernetes.audit_logs
          type: logs
        paths:
          - /var/log/kubernetes/kube-apiserver-audit.log
`
	before := mustConfig(t, policy)
	after := mustConfig(t, policy)
	RewriteContainerLogInputs(after, true, logp.NewNopLogger())
	assert.Equal(t, before, after, "non-container-log kubernetes input must not be rewritten")
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

// TestTransformAddFieldsToFieldCopies_NoTargetOmittedFromResidual verifies that
// when an add_fields processor has no target key, the residual add_fields also
// has no target key (not "target: """). Beats treats a missing target as root
// placement and "target: """ as a "fields" subkey.
func TestTransformAddFieldsToFieldCopies_NoTargetOmittedFromResidual(t *testing.T) {
	processor := map[string]interface{}{
		"add_fields": map[string]interface{}{
			// no "target" key — fields go to event root
			"fields": map[string]interface{}{
				"pod": "${kubernetes.pod.name}",
				"env": "production",
			},
		},
	}
	result, ok := transformAddFieldsToFieldCopies(processor)
	require.True(t, ok)
	require.Len(t, result, 2)

	// residual add_fields (for the static "env" field)
	residual := result[0].(map[string]interface{})["add_fields"].(map[string]interface{})
	assert.NotContains(t, residual, "target", "target must be absent, not empty string")
	assert.Equal(t, map[string]interface{}{"env": "production"}, residual["fields"])

	// copy_fields destination must be bare key (no "." prefix)
	copyFields := result[1].(map[string]interface{})["copy_fields"].(map[string]interface{})
	specs := copyFields["fields"].([]interface{})
	require.Len(t, specs, 1)
	assert.Equal(t, "pod", specs[0].(map[string]interface{})["to"])
}

// TestTransformAddFieldsToFieldCopies_NotAMap covers the branch where the
// processor argument is not a map.
func TestTransformAddFieldsToFieldCopies_NotAMap(t *testing.T) {
	result, ok := transformAddFieldsToFieldCopies("not-a-map")
	assert.False(t, ok)
	assert.Nil(t, result)
}

// TestTransformAddFieldsToFieldCopies_EmptyFields covers the branch where the
// add_fields processor has an empty fields map, returning (nil, false).
func TestTransformAddFieldsToFieldCopies_EmptyFields(t *testing.T) {
	processor := map[string]interface{}{
		"add_fields": map[string]interface{}{
			"target": "kubernetes",
			"fields": map[string]interface{}{},
		},
	}
	result, ok := transformAddFieldsToFieldCopies(processor)
	assert.False(t, ok)
	assert.Nil(t, result)
}

// indentYAML prefixes every non-empty line of s with indent.
func indentYAML(s, indent string) string {
	// simple line-by-line indent
	result := ""
	for _, line := range splitLines(s) {
		if line == "" {
			result += "\n"
		} else {
			result += indent + line + "\n"
		}
	}
	return result
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, ch := range s {
		if ch == '\n' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func TestRewriteContainerLogInputs_Idempotent(t *testing.T) {
	once := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(once, true, logp.NewNopLogger())

	twice := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(twice, true, logp.NewNopLogger())
	RewriteContainerLogInputs(twice, true, logp.NewNopLogger())

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

	withoutRewrite := mustConfig(t, chartContainerLogsPolicy)
	assert.Equal(t, 3, renderInputCount(withoutRewrite),
		"without the rewrite the provider renders one input per container")

	withRewrite := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(withRewrite, true, logp.NewNopLogger())
	assert.Equal(t, 1, renderInputCount(withRewrite),
		"after the rewrite the input renders once regardless of container count")
}

func TestRewriteContainerLogInputs_TakeOverWhenEnabled(t *testing.T) {
	m := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(m, true, logp.NewNopLogger())

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
	RewriteContainerLogInputs(m, false, logp.NewNopLogger())

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
	RewriteContainerLogInputs(enabled, true, logp.NewNopLogger())
	enabledStream := enabled["inputs"].([]interface{})[0].(map[string]interface{})["streams"].([]interface{})[0].(map[string]interface{})

	disabled := mustConfig(t, chartContainerLogsPolicy)
	RewriteContainerLogInputs(disabled, false, logp.NewNopLogger())
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
	RewriteContainerLogInputs(m, true, logp.NewNopLogger())

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
			RewriteContainerLogInputs(after, globInput, logp.NewNopLogger())
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
	RewriteContainerLogInputs(after, false, logp.NewNopLogger())
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
				RewriteContainerLogInputs(m, globInput, logp.NewNopLogger())

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
		RewriteContainerLogInputs(m, false, logp.NewNopLogger())
		assert.True(t, observedProviders(t, m)["kubernetes"],
			"the per-container inputs resolve ${kubernetes.*}, so the provider must run")
	})

	t.Run("not observed once collapsed", func(t *testing.T) {
		m := mustConfig(t, chartContainerLogsPolicy)
		RewriteContainerLogInputs(m, true, logp.NewNopLogger())
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
		RewriteContainerLogInputs(m, true, logp.NewNopLogger())
		assert.True(t, observedProviders(t, m)["kubernetes"],
			"hints inputs stay per-container, so the provider must keep running for them")
	})
}
