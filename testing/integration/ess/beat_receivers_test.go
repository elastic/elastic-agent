// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.
//go:build integration

package ess

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/elastic/elastic-agent/pkg/component"
	"github.com/elastic/elastic-agent/pkg/testing/tools/fleettools"
	"github.com/elastic/go-elasticsearch/v8"

	"github.com/gofrs/uuid/v5"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
	"github.com/elastic/go-elasticsearch/v8/esapi"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClassicAndReceiverAgentMonitoring is a test to compare documents ingested by
// elastic-agent monitoring classic mode vs otel mode
func TestClassicAndReceiverAgentMonitoring(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
			{Type: define.Windows},
		},
		Stack: &define.Stack{},
		Sudo:  true,
	})

	agentDocs := make(map[string]estools.Documents)
	otelDocs := make(map[string]estools.Documents)
	var agentStatus atesting.AgentStatusOutput
	var otelStatus atesting.AgentStatusOutput

	// Tests logs and metrics are present
	type test struct {
		dsType          string
		dsDataset       string
		query           []map[string]any
		onlyCompareKeys bool
		ignoreFields    []string
	}

	tests := []test{
		{
			dsType:    "logs",
			dsDataset: "elastic_agent",
			query: []map[string]any{
				{"match_phrase": map[string]any{"message": "Determined allowed capabilities"}},
			},
			onlyCompareKeys: false,
			ignoreFields:    genIgnoredFields(runtime.GOOS),
		},

		{
			dsType:    "metrics",
			dsDataset: "elastic_agent.filebeat",
			query: []map[string]any{
				{"match_phrase": map[string]any{"metricset.name": "stats"}},
				{"match_phrase": map[string]any{"component.id": "filestream-monitoring"}},
				{"exists": map[string]any{"field": "beat.stats.libbeat.pipeline.queue.acked"}},
			},
			onlyCompareKeys: true,
			ignoreFields: []string{
				"beat.elasticsearch.cluster.id",
				"beat.stats.cgroup",
				"beat.stats.cpu",
				"beat.stats.handles",
				"beat.stats.libbeat.config",
				"beat.stats.memstats",
				"beat.stats.runtime.goroutines",
			},
		},
		{
			dsType:    "metrics",
			dsDataset: "elastic_agent.metricbeat",
			query: []map[string]any{
				{"match_phrase": map[string]any{"metricset.name": "stats"}},
				{"match_phrase": map[string]any{"component.id": "http/metrics-monitoring"}},
				{"exists": map[string]any{"field": "beat.stats.libbeat.pipeline.queue.acked"}},
			},
			onlyCompareKeys: true,
			ignoreFields: []string{
				"beat.elasticsearch.cluster.id",
				"beat.stats.cgroup",
				"beat.stats.cpu",
				"beat.stats.handles",
				"beat.stats.libbeat.config",
				"beat.stats.memstats",
				"beat.stats.runtime.goroutines",
			},
		},
		{
			dsType:          "metrics",
			dsDataset:       "elastic_agent.elastic_agent",
			onlyCompareKeys: true,
			query: []map[string]any{
				{"match_phrase": map[string]any{"metricset.name": "json"}},
				{"match_phrase": map[string]any{"component.id": "elastic-agent"}},
				{"exists": map[string]any{"field": "system.process.memory.size"}},
			},
		},
		{
			dsType:          "metrics",
			dsDataset:       "elastic_agent.filebeat_input",
			onlyCompareKeys: true,
			query: []map[string]any{
				{"match_phrase": map[string]any{"metricset.name": "json"}},
				{"match_phrase": map[string]any{"component.id": "filestream-monitoring"}},
				{"exists": map[string]any{"field": "filebeat_input.bytes_processed_total"}},
			},
		},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Privileged:     true,
		Force:          true,
		Develop:        true,
	}

	// Flow
	// 1. Start elastic agent monitoring in classic mode (configure, install and wait for elastic-agent healthy)
	// 2. Assert monitoring logs and metrics are available on ES
	// 3. Uninstall

	// 4. Start elastic agent monitoring in otel mode
	// 5. Assert monitoring logs and metrics are available on ES (for otel mode)
	// 6. Uninstall

	// 7. Compare both documents are equivalent

	ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	t.Cleanup(cancel)

	// prepare the policy and marshalled configuration
	policyCtx, policyCancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
	t.Cleanup(policyCancel)

	// 1. Create and install policy with just monitoring
	createPolicyReq := kibana.AgentPolicy{
		Name:        fmt.Sprintf("%s-%s", t.Name(), uuid.Must(uuid.NewV4()).String()),
		Namespace:   info.Namespace,
		Description: fmt.Sprintf("%s policy", t.Name()),
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
	}
	policyResponse, err := info.KibanaClient.CreatePolicy(policyCtx, createPolicyReq)
	require.NoError(t, err, "error creating policy")

	// 2. Download the policy, add the API key
	downloadURL := fmt.Sprintf("/api/fleet/agent_policies/%s/download", policyResponse.ID)
	resp, err := info.KibanaClient.Connection.SendWithContext(policyCtx, http.MethodGet, downloadURL, nil, nil, nil)
	require.NoError(t, err, "error downloading policy")
	policyBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "error reading policy response")
	defer resp.Body.Close()

	apiKeyResponse, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "failed to get api key")
	require.True(t, len(apiKeyResponse.Encoded) > 1, "api key is invalid %q", apiKeyResponse)
	apiKey, err := getDecodedApiKey(apiKeyResponse)
	require.NoError(t, err, "error decoding api key")

	type PolicyOutputs struct {
		Type   string   `yaml:"type"`
		Hosts  []string `yaml:"hosts"`
		Preset string   `yaml:"preset"`
		ApiKey string   `yaml:"api_key"`
	}
	type PolicyStruct struct {
		ID                string                   `yaml:"id"`
		Revision          int                      `yaml:"revision"`
		Outputs           map[string]PolicyOutputs `yaml:"outputs"`
		Fleet             map[string]any           `yaml:"fleet"`
		OutputPermissions map[string]any           `yaml:"output_permissions"`
		Agent             struct {
			Monitoring map[string]any `yaml:"monitoring"`
			Rest       map[string]any `yaml:",inline"`
		} `yaml:"agent"`
		Inputs           []map[string]any `yaml:"inputs"`
		Signed           map[string]any   `yaml:"signed"`
		SecretReferences []map[string]any `yaml:"secret_references"`
		Namespaces       []string         `yaml:"namespaces"`
	}

	policy := PolicyStruct{}
	err = yaml.Unmarshal(policyBytes, &policy)
	require.NoError(t, err, "error unmarshalling policy: %s", string(policyBytes))
	d, prs := policy.Outputs["default"]
	require.True(t, prs, "default must be in outputs")
	d.ApiKey = apiKey
	policy.Outputs["default"] = d

	processNamespace := fmt.Sprintf("%s-%s", info.Namespace, "process")
	policy.Agent.Monitoring["namespace"] = processNamespace
	policy.Agent.Monitoring["_runtime_experimental"] = "process"

	updatedPolicyBytes, err := yaml.Marshal(policy)
	require.NoErrorf(t, err, "error marshalling policy, struct was %v", policy)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("policy was %s", string(updatedPolicyBytes))
		}
	})

	classicFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	err = classicFixture.Prepare(ctx)
	require.NoError(t, err, "error preparing fixture")

	err = classicFixture.Configure(ctx, updatedPolicyBytes)
	require.NoError(t, err, "error configuring fixture")

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	output, err := classicFixture.InstallWithoutEnroll(ctx, &installOpts)
	require.NoErrorf(t, err, "error install withouth enroll: %s\ncombinedoutput:\n%s", err, string(output))

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := classicFixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		assertBeatsHealthy(collect, &status, component.ProcessRuntimeManager, 3)
	}, 1*time.Minute, 1*time.Second)

	// 2. Assert monitoring logs and metrics are available on ES
	for _, tc := range tests {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(ctx, 10*time.Second)
			defer findCancel()
			mustClauses := []map[string]any{
				{"match": map[string]any{"data_stream.type": tc.dsType}},
				{"match": map[string]any{"data_stream.dataset": tc.dsDataset}},
				{"match": map[string]any{"data_stream.namespace": processNamespace}},
			}
			mustClauses = append(mustClauses, tc.query...)
			rawQuery := map[string]any{
				"query": map[string]any{
					"bool": map[string]any{
						"must":   mustClauses,
						"filter": map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": timestamp}}},
					},
				},
				"sort": []map[string]any{
					{"@timestamp": map[string]any{"order": "asc"}},
				},
			}

			docs, err := estools.PerformQueryForRawQuery(findCtx, rawQuery, tc.dsType+"-*", info.ESClient)
			require.NoError(collect, err)
			if docs.Hits.Total.Value != 0 {
				key := tc.dsType + "-" + tc.dsDataset + "-" + processNamespace
				agentDocs[key] = docs
			}
			require.Greater(collect, docs.Hits.Total.Value, 0)
		},
			2*time.Minute, 5*time.Second,
			"agent monitoring classic no documents found for timestamp: %s, type: %s, dataset: %s, namespace: %s, query: %v", timestamp, tc.dsType, tc.dsDataset, processNamespace, tc.query)
	}

	// 3. Uninstall
	combinedOutput, err := classicFixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
	require.NoErrorf(t, err, "error uninstalling classic agent monitoring, err: %s, combined output: %s", err, string(combinedOutput))

	// 4. switch monitoring to the otel runtime
	policy.Agent.Monitoring["_runtime_experimental"] = "otel"
	receiverNamespace := fmt.Sprintf("%s-%s", info.Namespace, "otel")
	policy.Agent.Monitoring["namespace"] = receiverNamespace
	updatedPolicyBytes, err = yaml.Marshal(policy)
	require.NoErrorf(t, err, "error marshalling policy, struct was %v", policy)
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("policy was %s", string(updatedPolicyBytes))
		}
	})

	beatReceiverFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)
	err = beatReceiverFixture.Prepare(ctx)
	require.NoError(t, err)
	err = beatReceiverFixture.Configure(ctx, updatedPolicyBytes)
	require.NoError(t, err)
	combinedOutput, err = beatReceiverFixture.InstallWithoutEnroll(ctx, &installOpts)
	require.NoErrorf(t, err, "error install without enroll: %s\ncombinedoutput:\n%s", err, string(combinedOutput))
	// store timestamp to filter otel docs with timestamp greater than this value
	timestampBeatReceiver := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := beatReceiverFixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		assertBeatsHealthy(collect, &status, component.OtelRuntimeManager, 3)
	}, 1*time.Minute, 1*time.Second)

	// 5. Assert monitoring logs and metrics are available on ES (for otel mode)
	for _, tc := range tests {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(ctx, 10*time.Second)
			defer findCancel()
			mustClauses := []map[string]any{
				{"match": map[string]any{"data_stream.type": tc.dsType}},
				{"match": map[string]any{"data_stream.dataset": tc.dsDataset}},
				{"match": map[string]any{"data_stream.namespace": receiverNamespace}},
			}
			mustClauses = append(mustClauses, tc.query...)

			rawQuery := map[string]any{
				"query": map[string]any{
					"bool": map[string]any{
						"must":   mustClauses,
						"filter": map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": timestampBeatReceiver}}},
					},
				},
				"sort": []map[string]any{
					{"@timestamp": map[string]any{"order": "asc"}},
				},
			}

			docs, err := estools.PerformQueryForRawQuery(findCtx, rawQuery, tc.dsType+"-*", info.ESClient)
			require.NoError(collect, err)
			if docs.Hits.Total.Value != 0 {
				key := tc.dsType + "-" + tc.dsDataset + "-" + receiverNamespace
				otelDocs[key] = docs
			}
			require.Greater(collect, docs.Hits.Total.Value, 0)
		},
			4*time.Minute, 5*time.Second,
			"agent monitoring beats receivers no documents found for timestamp: %s, type: %s, dataset: %s, namespace: %s, query: %v", timestampBeatReceiver, tc.dsType, tc.dsDataset, receiverNamespace, tc.query)
	}

	// 6. Uninstall
	combinedOutput, err = beatReceiverFixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
	require.NoErrorf(t, err, "error uninstalling beat receiver agent monitoring, err: %s, combined output: %s", err, string(combinedOutput))

	// 7. Compare both documents are equivalent
	for _, tc := range tests[:3] {
		agent := agentDocs[tc.dsType+"-"+tc.dsDataset+"-"+processNamespace].Hits.Hits[0].Source
		otel := otelDocs[tc.dsType+"-"+tc.dsDataset+"-"+receiverNamespace].Hits.Hits[0].Source
		ignoredFields := []string{
			// Expected to change between agentDocs and OtelDocs
			"@timestamp",
			"agent.ephemeral_id",
			// agent.id is different because it's the id of the underlying beat
			"agent.id",
			// for short periods of time, the beats binary version can be out of sync with the beat receiver version
			"agent.version",
			"data_stream.namespace",
			"elastic_agent.id",
			"event.ingested",
		}
		switch tc.onlyCompareKeys {
		case true:
			AssertMapstrKeysEqual(t, agent, otel, append(ignoredFields, tc.ignoreFields...), "expected document keys to be equal for "+tc.dsType+"-"+tc.dsDataset)
		case false:
			AssertMapsEqual(t, agent, otel, append(ignoredFields, tc.ignoreFields...), "expected document to be equal for "+tc.dsType+"-"+tc.dsDataset)
		}
	}

	// 8. Compare statuses
	zeroDifferingFields := func(status *atesting.AgentStatusOutput) {
		status.Info.ID = ""
		status.Info.PID = 0
		status.Collector = nil // we do get collector status with beats receivers, it's just empty
		for i := range len(status.Components) {
			status.Components[i].Message = ""
			status.Components[i].VersionInfo = atesting.AgentStatusOutputVersionInfo{}
		}
	}
	zeroDifferingFields(&agentStatus)
	zeroDifferingFields(&otelStatus)
	assert.Equal(t, agentStatus, otelStatus, "expected agent status to be equal to otel status")
}

// TestAgentMetricsInput is a test that compares documents ingested by
// agent system/metrics input in process and otel modes and asserts that they are
// equivalent.
func TestAgentMetricsInput(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})

	metricsets := []string{"cpu", "memory", "network", "filesystem"}

	type configOptions struct {
		HomeDir             string
		ESEndpoint          string
		BeatsESApiKey       string
		FBReceiverIndex     string
		Namespace           string
		RuntimeExperimental string
		Metricsets          []string
	}
	configTemplate := `agent:
  logging:
    level: debug
    to_stderr: true
  monitoring:
    _runtime_experimental: {{.RuntimeExperimental}}
  internal.runtime.metricbeat:
    system/metrics: {{.RuntimeExperimental}}
inputs:
  # Collecting system metrics
  - type: system/metrics
    id: unique-system-metrics-input
    data_stream.namespace: {{.Namespace}}
    use_output: default
    {{if ne .RuntimeExperimental "" }}
    {{end}}
    streams:
      {{range $mset := .Metricsets}}
      - metricsets:
        - {{$mset}}
        data_stream.dataset: system.{{$mset}}
      {{end}}
outputs:
  default:
    type: elasticsearch
    hosts: [{{.ESEndpoint}}]
    api_key: {{.BeatsESApiKey}}
`

	esEndpoint, err := integration.GetESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)

	beatsApiKey, err := base64.StdEncoding.DecodeString(esApiKey.Encoded)
	require.NoError(t, err, "error decoding api key")

	tableTests := []struct {
		name                string
		runtimeExperimental string
	}{
		{name: "agent", runtimeExperimental: "process"},
		{name: "otel", runtimeExperimental: "otel"},
	}

	// map of testcase -> metricset -> documents
	esDocs := make(map[string]map[string]estools.Documents)

	for _, tt := range tableTests {
		t.Run(tt.name, func(t *testing.T) {
			startedAt := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
			tmpDir := t.TempDir()

			if _, ok := esDocs[tt.name]; !ok {
				esDocs[tt.name] = make(map[string]estools.Documents)
			}

			var configBuffer bytes.Buffer
			require.NoError(t,
				template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
					configOptions{
						HomeDir:             tmpDir,
						ESEndpoint:          esEndpoint,
						BeatsESApiKey:       string(beatsApiKey),
						Namespace:           info.Namespace,
						RuntimeExperimental: tt.runtimeExperimental,
						Metricsets:          metricsets,
					}))
			configContents := configBuffer.Bytes()
			t.Cleanup(func() {
				if t.Failed() {
					t.Log("Contents of agent config file:\n")
					println(string(configContents))
				}
			})

			ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
			defer cancel()

			// set up a standalone agent
			fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
			require.NoError(t, err)

			err = fixture.Prepare(ctx)
			require.NoError(t, err)
			err = fixture.Configure(ctx, configContents)
			require.NoError(t, err)

			output, err := fixture.Install(ctx, &atesting.InstallOpts{Privileged: true, Force: true})
			require.NoError(t, err, "failed to install agent: %s", output)

			require.Eventually(t, func() bool {
				err = fixture.IsHealthy(ctx)
				if err != nil {
					t.Logf("waiting for agent healthy: %s", err.Error())
					return false
				}
				return true
			}, 1*time.Minute, 1*time.Second)

			mustClauses := []map[string]any{
				{"range": map[string]any{
					"@timestamp": map[string]string{
						"gte": startedAt,
					},
				}},
			}

			rawQuery := map[string]any{
				"query": map[string]any{
					"bool": map[string]any{
						"must": mustClauses,
					},
				},
			}

			for _, mset := range metricsets {
				index := fmt.Sprintf(".ds-metrics-system.%s-%s*", mset, info.Namespace)
				require.EventuallyWithTf(t,
					func(ct *assert.CollectT) {
						findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
						defer findCancel()

						docs, err := estools.PerformQueryForRawQuery(findCtx, rawQuery, index, info.ESClient)
						require.NoError(ct, err)

						if docs.Hits.Total.Value != 0 {
							esDocs[tt.name][mset] = docs
						}
						require.Greater(ct, docs.Hits.Total.Value, 0, "docs count")
					},
					30*time.Second, 1*time.Second,
					"Expected to find at least one document for metricset %s in index %s and runtime %q, got 0", mset, index, tt.runtimeExperimental)
			}
		})
	}

	t.Run("compare documents", func(t *testing.T) {
		require.Greater(t, len(esDocs), 0, "expected to find documents ingested")
		require.Greater(t, len(esDocs["agent"]), 0, "expected to find documents ingested by normal agent metrics input")
		require.Greater(t, len(esDocs["otel"]), 0, "expected to find documents ingested by beat receivers")

		agentDocs := esDocs["agent"]
		otelDocs := esDocs["otel"]

		// Fields that are present in both agent and otel documents, but are expected to change
		ignoredFields := []string{
			"@timestamp",
			"agent.id",
			"agent.ephemeral_id",
			"elastic_agent.id",
			"data_stream.namespace",
			"event.ingested",
			"event.duration",

			// for short periods of time, the beats binary version can be out of sync with the beat receiver version
			"agent.version",
		}

		stripNondeterminism := func(m mapstr.M, mset string) {
			// These metrics will change from run to run
			prefixes := []string{
				fmt.Sprintf("system.%s", mset),
				fmt.Sprintf("host.%s", mset),
			}

			for k := range m {
				for _, prefix := range prefixes {
					if strings.HasPrefix(k, prefix) {
						m[k] = nil
					}
				}
			}
		}

		testCases := []struct {
			metricset     string
			yieldDocsFunc func(agent []estools.ESDoc, otel []estools.ESDoc) (mapstr.M, mapstr.M)
		}{
			{
				metricset: "cpu",
				yieldDocsFunc: func(agent []estools.ESDoc, otel []estools.ESDoc) (mapstr.M, mapstr.M) {
					return agent[0].Source, otel[0].Source
				},
			},
			{
				metricset: "memory",
				yieldDocsFunc: func(agent []estools.ESDoc, otel []estools.ESDoc) (mapstr.M, mapstr.M) {
					return agent[0].Source, otel[0].Source
				},
			},
			{
				metricset: "network",
				yieldDocsFunc: func(agent []estools.ESDoc, otel []estools.ESDoc) (mapstr.M, mapstr.M) {
					// make sure we compare events from network interfaces and not host metrics
					var agentDoc, otelDoc mapstr.M
					for _, hit := range agent {
						agentDoc = hit.Source
						if ok, _ := agentDoc.Flatten().HasKey("system.network.name"); ok {
							break
						}
					}
					for _, hit := range otel {
						otelDoc = hit.Source
						if ok, _ := otelDoc.Flatten().HasKey("system.network.name"); ok {
							break
						}
					}
					return agentDoc, otelDoc
				},
			},
			{
				metricset: "filesystem",
				yieldDocsFunc: func(agent []estools.ESDoc, otel []estools.ESDoc) (mapstr.M, mapstr.M) {
					return agent[0].Source, otel[0].Source
				},
			},
		}

		for _, tt := range testCases {
			t.Run(tt.metricset, func(t *testing.T) {
				msetAgentDocs := agentDocs[tt.metricset].Hits.Hits
				msetOtelDocs := otelDocs[tt.metricset].Hits.Hits
				require.Greater(t, len(msetAgentDocs), 0, "expected to find agent documents for metricset %s", tt.metricset)
				require.Greater(t, len(msetOtelDocs), 0, "expected to find otel documents for metricset %s", tt.metricset)

				agentDoc, otelDoc := tt.yieldDocsFunc(msetAgentDocs, msetOtelDocs)
				agentDoc = agentDoc.Flatten()
				otelDoc = otelDoc.Flatten()

				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("agent document for metricset %s:\n%s", tt.metricset, agentDoc.StringToPrint())
						t.Logf("otel document for metricset %s:\n%s", tt.metricset, otelDoc.StringToPrint())
					}
				})

				stripNondeterminism(agentDoc, tt.metricset)
				stripNondeterminism(otelDoc, tt.metricset)

				AssertMapstrKeysEqual(t, agentDoc, otelDoc, ignoredFields, "expected documents keys to be equal for metricset "+tt.metricset)
				AssertMapsEqual(t, agentDoc, otelDoc, ignoredFields, "expected documents to be equal for metricset "+tt.metricset)
			})
		}
	})
}

// TestBeatsReceiverLogs is a test that compares logs emitted by beats processes to those emitted by beats receivers.
func TestBeatsReceiverLogs(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: nil,
	})

	type configOptions struct {
		RuntimeExperimental string
	}
	configTemplate := `agent.logging.level: info
agent.logging.to_stderr: true
agent.logging.to_files: false
agent.internal.runtime.metricbeat:
  system/metrics: {{.RuntimeExperimental}}
inputs:
  # Collecting system metrics
  - type: system/metrics
    id: unique-system-metrics-input
    streams:
      - metricsets:
        - cpu
outputs:
  default:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
agent.monitoring.enabled: false
`

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
			configOptions{
				RuntimeExperimental: string(component.ProcessRuntimeManager),
			}))
	processConfig := configBuffer.Bytes()
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
			configOptions{
				RuntimeExperimental: string(component.OtelRuntimeManager),
			}))
	receiverConfig := configBuffer.Bytes()
	// this is the context for the whole test, with a global timeout defined
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	// since we set the output to a nonexistent ES endpoint, we expect it to be degraded, but the input to be healthy
	assertBeatsReady := func(t *assert.CollectT, status *atesting.AgentStatusOutput, runtime component.RuntimeManager) {
		t.Helper()

		var componentVersionInfoName string
		switch runtime {
		case component.OtelRuntimeManager:
			componentVersionInfoName = "beats-receiver"
		default:
			componentVersionInfoName = "beat-v2-client"
		}

		// we don't actually care about anything here other than the receiver itself
		assert.Equal(t, 1, len(status.Components))

		// all the components should be degraded, their output units should be degraded, the input units should be healthy,
		// and should identify themselves appropriately via their version info
		for _, comp := range status.Components {
			assert.Equal(t, componentVersionInfoName, comp.VersionInfo.Name)
			for _, unit := range comp.Units {
				if unit.UnitType == int(cproto.UnitType_INPUT) {
					assert.Equal(t, int(cproto.State_HEALTHY), unit.State,
						"expected state of unit %s to be %s, got %s",
						unit.UnitID, cproto.State_HEALTHY.String(), cproto.State(unit.State).String())
				}
			}
		}
	}

	// set up a standalone agent
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	err = fixture.Prepare(ctx)
	require.NoError(t, err)
	err = fixture.Configure(ctx, processConfig)
	require.NoError(t, err)

	output, err := fixture.Install(ctx, &atesting.InstallOpts{Privileged: true, Force: true})
	require.NoError(t, err, "failed to install agent: %s", output)

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		require.NoError(collect, statusErr)
		assertBeatsReady(collect, &status, component.ProcessRuntimeManager)
	}, 2*time.Minute, 5*time.Second)

	// change configuration and wait until the beats receiver is healthy
	err = fixture.Configure(ctx, receiverConfig)
	require.NoError(t, err)

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		require.NoError(collect, statusErr)
		assertBeatsReady(collect, &status, component.OtelRuntimeManager)
	}, 2*time.Minute, 5*time.Second)

	logsBytes, err := fixture.Exec(ctx, []string{"logs", "-n", "1000", "--exclude-events"})
	require.NoError(t, err, "failed to read logs: %v", err)

	beatStartLogs := getBeatStartLogRecords(string(logsBytes))

	require.Len(t, beatStartLogs, 2, "expected to find one log line for each configuration")
	processLog, receiverLog := beatStartLogs[0], beatStartLogs[1]

	// Check that the process log is a subset of the receiver log
	for key, value := range processLog {
		assert.Contains(t, receiverLog, key)
		if key == "@timestamp" { // the timestamp value will be different
			continue
		}
		assert.Equal(t, value, receiverLog[key])
	}
}

// Log lines TestBeatsReceiverProcessRuntimeFallback checks for
const (
	otelRuntimeUnsupportedLogLineStart                 = "otel runtime is not supported for component"
	otelRuntimeMonitoringOutputUnsupportedLogLineStart = "otel runtime is not supported for monitoring output"
)

// TestBeatsReceiverProcessRuntimeFallback verifies that we fall back to the process runtime if the otel runtime
// does not support the requested configuration.
func TestBeatsReceiverProcessRuntimeFallback(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: nil,
	})

	config := `agent.logging.to_stderr: true
agent.logging.to_files: false
agent.internal.runtime.metricbeat:
  system/metrics: otel
inputs:
  - type: system/metrics
    id: unique-system-metrics-input
    streams:
      - metricsets:
        - cpu
  - type: system/metrics
    id: unique-system-metrics-input-2
    use_output: supported
    _runtime_experimental: otel
    streams:
      - metricsets:
        - cpu
outputs:
  default:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
    indices: [] # not supported by the elasticsearch exporter
    status_reporting:
      enabled: false
  supported:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
    status_reporting:
      enabled: false
`

	// this is the context for the whole test, with a global timeout defined
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	// set up a standalone agent
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	err = fixture.Prepare(ctx)
	require.NoError(t, err)
	err = fixture.Configure(ctx, []byte(config))
	require.NoError(t, err)

	installOutput, err := fixture.Install(ctx, &atesting.InstallOpts{Privileged: true, Force: true})
	require.NoError(t, err, "install failed, output: %s", string(installOutput))

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		// we should be running beats processes for components with default output even though the otel runtime was requested
		// agent should be healthy
		assert.Equal(collect, int(cproto.State_HEALTHY), status.State)
		assert.Equal(collect, 5, len(status.Components))

		// all the components should be healthy, their units should be healthy, and they should identify
		// themselves as running in the process runtime if they're using the default or monitoring outputs
		for _, comp := range status.Components {
			assert.Equal(collect, int(cproto.State_HEALTHY), comp.State)
			expectedComponentVersionInfoName := componentVersionInfoNameForRuntime(component.OtelRuntimeManager)
			if strings.HasSuffix(comp.ID, "default") || strings.HasSuffix(comp.ID, "monitoring") {
				expectedComponentVersionInfoName = componentVersionInfoNameForRuntime(component.ProcessRuntimeManager)
			}
			assert.Equal(collect, expectedComponentVersionInfoName, comp.VersionInfo.Name)
			for _, unit := range comp.Units {
				assert.Equal(collect, int(cproto.State_HEALTHY), unit.State)
			}
		}
	}, 1*time.Minute, 1*time.Second)
	logsBytes, err := fixture.Exec(ctx, []string{"logs", "-n", "1000", "--exclude-events"})
	require.NoError(t, err)

	// verify we've logged a warning about using the process runtime
	var unsupportedLogRecords []map[string]any
	var monitoringOutputUnsupportedLogRecord map[string]any
	for _, line := range strings.Split(string(logsBytes), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var logRecord map[string]any
		if unmarshalErr := json.Unmarshal([]byte(line), &logRecord); unmarshalErr != nil {
			continue
		}

		if message, ok := logRecord["message"].(string); ok {
			if strings.HasPrefix(message, otelRuntimeUnsupportedLogLineStart) {
				unsupportedLogRecords = append(unsupportedLogRecords, logRecord)
			}
			if strings.HasPrefix(message, otelRuntimeMonitoringOutputUnsupportedLogLineStart) {
				monitoringOutputUnsupportedLogRecord = logRecord
			}
		}
	}

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic-Agent logs seen by the test:")
			t.Log(string(logsBytes))
		}
	})

	assert.Len(t, unsupportedLogRecords, 1, "one log line for each component we try to run")
	assert.NotEmpty(t, monitoringOutputUnsupportedLogRecord, "should get a log line about monitoring output not being supported")
}

const (
	otelDynamicVariableLogLineTemplate = "Component %s uses dynamic variable providers, switching to process runtime"
)

// TestBeatsReceiverDynamicInputProcessRuntimeFallback verifies that we fall back to the process runtime if the input
// uses variables from a dynamic provider.
func TestBeatsReceiverDynamicInputProcessRuntimeFallback(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: nil,
	})

	config := `agent.logging.to_stderr: true
agent.logging.to_files: false
agent.monitoring.enabled: false
agent.internal.runtime.dynamic_inputs: process
inputs:
  - type: system/metrics
    id: "${local_dynamic.id}"
    streams:
      - metricsets:
        - cpu
outputs:
  default:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
    status_reporting:
      enabled: false
providers:
  local_dynamic:
    items:
    - vars:
        id: system-metrics-1
`

	// this is the context for the whole test, with a global timeout defined
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	// set up a standalone agent
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	err = fixture.Prepare(ctx)
	require.NoError(t, err)
	err = fixture.Configure(ctx, []byte(config))
	require.NoError(t, err)

	installOutput, err := fixture.Install(ctx, &atesting.InstallOpts{Privileged: true, Force: true})
	require.NoError(t, err, "install failed, output: %s", string(installOutput))

	var compId string
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		// we should be running a single component in a beat process
		assert.Equal(collect, int(cproto.State_HEALTHY), status.State)
		require.Equal(collect, 1, len(status.Components))
		comp := status.Components[0]

		assert.Equal(collect, int(cproto.State_HEALTHY), comp.State)
		expectedComponentVersionInfoName := componentVersionInfoNameForRuntime(component.ProcessRuntimeManager)
		assert.Equal(collect, expectedComponentVersionInfoName, comp.VersionInfo.Name)
		for _, unit := range comp.Units {
			assert.Equal(collect, int(cproto.State_HEALTHY), unit.State)
		}
		compId = comp.ID
	}, 1*time.Minute, 1*time.Second)
	logsBytes, err := fixture.Exec(ctx, []string{"logs", "-n", "1000", "--exclude-events"})
	require.NoError(t, err)

	// verify we've logged a warning about using the process runtime
	foundLogMessage := false
	expectedMessage := fmt.Sprintf(otelDynamicVariableLogLineTemplate, compId)
	for _, line := range strings.Split(string(logsBytes), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var logRecord struct {
			Message string
		}
		if unmarshalErr := json.Unmarshal([]byte(line), &logRecord); unmarshalErr != nil {
			continue
		}

		foundLogMessage = foundLogMessage || logRecord.Message == expectedMessage
	}

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic-Agent logs seen by the test:")
			t.Log(string(logsBytes))
		}
	})

	assert.True(t, foundLogMessage, "there should be a log line with a warning about falling back to process runtime")
}

// TestBeatsReceiverSubcomponentStatus verifies that we correctly reflect the status of beats inputs in the elastic
// agent component and unit statuses.
func TestBeatsReceiverSubcomponentStatus(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Default,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: nil,
	})

	// This configuration contains two system/metrics inputs, each with two identical metricsets:
	// * one for cpu, always healthy
	// * one for processes, can't read data for some processes if not running as root
	// The second metricset will emit a message about not being able to read process data. For the first input, this
	// results in a Healthy status, but the second input is configured to become degraded in that case. The test
	// verifies both of these conditions.
	config := `agent:
  logging:
    to_stderr: true
    to_files: false
    level: debug
  monitoring:
    enabled: false
inputs:
- data_stream:
    namespace: default
  id: unique-system-metrics-input
  streams:
  - data_stream:
      dataset: system.cpu
    metricsets:
    - cpu
    id: unique-system-metrics-input-cpu
  - data_stream:
      dataset: system.process
    metricsets:
    - process
    id: unique-system-metrics-input-process
  type: system/metrics
  use_output: default
- data_stream:
    namespace: default
  id: unique-system-metrics-input-2
  streams:
  - data_stream:
      dataset: system.cpu
    metricsets:
    - cpu
    id: unique-system-metrics-input-2-cpu
  - data_stream:
      dataset: system.process
    metricsets:
    - process
    id: unique-system-metrics-input-2-process
    degrade_on_partial: true
  type: system/metrics
  use_output: default
outputs:
  default:
    api_key: placeholder
    hosts:
    - 127.0.0.1:9200
    type: elasticsearch
    status_reporting:
      enabled: false
`

	// this is the context for the whole test, with a global timeout defined
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	// set up a standalone agent
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	err = fixture.Prepare(ctx)
	require.NoError(t, err)
	err = fixture.Configure(ctx, []byte(config))
	require.NoError(t, err)

	installOutput, err := fixture.Install(ctx, &atesting.InstallOpts{Privileged: false, Force: true})
	require.NoError(t, err, "install failed, output: %s", string(installOutput))

	expectedComponentCount := 1
	expectedUnitCountPerComponent := 3 // one unit per system/metrics input and one output
	assert.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		// we should be running beats processes for components, the whole agent should be degraded
		assert.Equal(collect, int(cproto.State_DEGRADED), status.State)
		require.Len(collect, status.Components, expectedComponentCount, "There should be one component")

		comp := status.Components[0]
		assert.Equal(collect, int(cproto.State_DEGRADED), comp.State)
		expectedComponentVersionInfoName := componentVersionInfoNameForRuntime(component.OtelRuntimeManager)
		assert.Equal(collect, expectedComponentVersionInfoName, comp.VersionInfo.Name)
		assert.Lenf(collect, comp.Units, expectedUnitCountPerComponent, "There should be %d units", expectedUnitCountPerComponent)
		for _, unit := range comp.Units {
			if unit.UnitType == int(cproto.UnitType_OUTPUT) {
				continue
			}
			var expectedUnitState int
			if unit.UnitID == "system/metrics-default-unique-system-metrics-input-2" {
				expectedUnitState = int(cproto.State_DEGRADED)
			} else {
				expectedUnitState = int(cproto.State_HEALTHY)
			}
			assert.Equalf(collect, expectedUnitState, unit.State,
				"Expected unit %s to be in state %d, got %d", unit.UnitID, expectedUnitState, unit.State)
			unitPayload := unit.Payload
			require.Lenf(collect, unitPayload.Streams, 2,
				"Expected unit %s to have 2 streams, got %d", unit.UnitID, len(unitPayload.Streams))
			for streamName, streamState := range unitPayload.Streams {
				if strings.Contains(streamName, "cpu") {
					assert.Equal(collect, streamState.Status, "HEALTHY")
					assert.Empty(collect, streamState.Error)
				} else if strings.Contains(streamName, "process") {
					var expectedStreamState string
					if streamName == "unique-system-metrics-input-2-process" {
						expectedStreamState = "DEGRADED"
					} else {
						expectedStreamState = "HEALTHY"
					}
					assert.Equalf(collect, streamState.Status, expectedStreamState,
						"Expected stream %s to be in state %s, got %s", streamName, expectedStreamState, streamState.Status)
					assert.Containsf(collect, streamState.Error, "Error fetching data for metricset system.process",
						"Invalid error message for stream %s: %s", streamName, streamState.Error)
				}
			}
		}
	}, 1*time.Minute, 1*time.Second)
}

// TestComponentWorkDir verifies that the component working directory is not deleted when moving the component from
// the process runtime to the otel runtime.
func TestComponentWorkDir(t *testing.T) {
	_ = define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: nil,
	})

	type configOptions struct {
		RuntimeExperimental string
	}
	configTemplate := `agent.logging.level: debug
agent.logging.to_stderr: true
agent.logging.to_files: false
agent.internal.runtime.metricbeat:
  system/metrics: {{.RuntimeExperimental}}
inputs:
  # Collecting system metrics
  - type: system/metrics
    id: unique-system-metrics-input
    streams:
      - metricsets:
        - cpu
outputs:
  default:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
agent.monitoring.enabled: false
`

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
			configOptions{
				RuntimeExperimental: string(component.ProcessRuntimeManager),
			}))
	processConfig := configBuffer.Bytes()
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
			configOptions{
				RuntimeExperimental: string(component.OtelRuntimeManager),
			}))
	receiverConfig := configBuffer.Bytes()
	// this is the context for the whole test, with a global timeout defined
	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	// set up a standalone agent
	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	err = fixture.Prepare(ctx)
	require.NoError(t, err)
	err = fixture.Configure(ctx, processConfig)
	require.NoError(t, err)

	output, err := fixture.Install(ctx, &atesting.InstallOpts{Privileged: true, Force: true})
	require.NoError(t, err, "failed to install agent: %s", output)

	var componentID, componentWorkDir string
	var workDirCreated time.Time

	// wait for component to appear in status and be healthy
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		require.NoError(collect, statusErr)
		require.Equal(collect, 1, len(status.Components))
		componentStatus := status.Components[0]
		assert.Equal(collect, cproto.State_HEALTHY, cproto.State(componentStatus.State))
		componentID = componentStatus.ID
	}, 2*time.Minute, 5*time.Second)

	runDir, err := atesting.FindRunDir(fixture)
	require.NoError(t, err)

	componentWorkDir = filepath.Join(runDir, componentID)
	stat, err := os.Stat(componentWorkDir)
	require.NoError(t, err, "component working directory should exist")
	assert.True(t, stat.IsDir(), "component working directory should exist")
	workDirCreated = stat.ModTime()

	// change configuration and wait until the beats receiver is present in status
	err = fixture.Configure(ctx, receiverConfig)
	require.NoError(t, err)

	// wait for component to appear in status and be healthy or degraded
	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		require.NoError(collect, statusErr)
		require.Equal(collect, 1, len(status.Components))
		componentStatus := status.Components[0]
		require.Equal(collect, "beats-receiver", componentStatus.VersionInfo.Name)
		componentState := cproto.State(componentStatus.State)
		assert.Truef(collect, componentState == cproto.State_HEALTHY || componentState == cproto.State_DEGRADED,
			"component state should be HEALTHY or DEGRADED, got %s", componentState.String())
	}, 2*time.Minute, 5*time.Second)

	// the component working directory should still exist
	stat, err = os.Stat(componentWorkDir)
	require.NoError(t, err, "component working directory should exist")
	assert.True(t, stat.IsDir(), "component working directory should exist")
	assert.Equal(t, workDirCreated, stat.ModTime(), "component working directory shouldn't have been modified")

	configNoComponents := `agent.logging.level: info
agent.logging.to_stderr: true
agent.logging.to_files: false
inputs: []
outputs:
  default:
    type: elasticsearch
    hosts: [http://localhost:9200]
    api_key: placeholder
agent.monitoring.enabled: false
`
	err = fixture.Configure(ctx, []byte(configNoComponents))
	require.NoError(t, err)

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		require.NoError(collect, statusErr)
		require.Equal(collect, 0, len(status.Components))
	}, 2*time.Minute, 5*time.Second)

	// the component working directory shouldn't exist anymore
	require.NoDirExists(t, componentWorkDir)
}

func assertCollectorComponentsHealthy(t *assert.CollectT, status *atesting.AgentStatusCollectorOutput) {
	assert.Equal(t, int(cproto.CollectorComponentStatus_StatusOK), status.Status, "component status should be ok")
	assert.Equal(t, "", status.Error, "component status should not have an error")
	for _, componentStatus := range status.ComponentStatusMap {
		assertCollectorComponentsHealthy(t, componentStatus)
	}
}

func assertBeatsHealthy(t *assert.CollectT, status *atesting.AgentStatusOutput, runtime component.RuntimeManager, componentCount int) {
	t.Helper()
	componentVersionInfoName := componentVersionInfoNameForRuntime(runtime)

	// agent should be healthy
	assert.Equal(t, int(cproto.State_HEALTHY), status.State)
	assert.Equal(t, componentCount, len(status.Components))

	// all the components should be healthy, their units should be healthy, and should identify themselves
	// as beats processes via their version info
	for _, comp := range status.Components {
		assert.Equal(t, int(cproto.State_HEALTHY), comp.State)
		assert.Equal(t, componentVersionInfoName, comp.VersionInfo.Name)
		for _, unit := range comp.Units {
			assert.Equal(t, int(cproto.State_HEALTHY), unit.State)
		}
	}
}

// getBeatStartLogRecords returns the log records for a particular log line emitted when the beat starts
// This log line is identical between beats processes and receivers, so it's a good point of comparison
func getBeatStartLogRecords(logs string) []map[string]any {
	var logRecords []map[string]any
	for _, line := range strings.Split(logs, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		logRecord := make(map[string]any)
		if unmarshalErr := json.Unmarshal([]byte(line), &logRecord); unmarshalErr != nil {
			continue
		}

		if message, ok := logRecord["message"].(string); ok && strings.HasPrefix(message, "Beat name:") {
			logRecords = append(logRecords, mapstr.M(logRecord).Flatten())
		}
	}
	return logRecords
}

func genIgnoredFields(goos string) []string {
	switch goos {
	case "windows":
		return []string{
			"log.file.fingerprint",
			"log.file.idxhi",
			"log.file.idxlo",
			"log.offset",
		}
	default:
		return []string{
			"log.file.device_id",
			"log.file.fingerprint",
			"log.file.inode",
			"log.file.path",
			"log.offset",
		}
	}
}

// TestSensitiveLogsESExporter tests sensitive logs from ex-exporter are not sent to fleet
func TestSensitiveLogsESExporter(t *testing.T) {

	// The ES exporter logs the original document on indexing failure only if
	// the "telemetry::log_failed_docs_input" setting is enabled and the log level is set to debug.
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})
	tmpDir := t.TempDir()
	numEvents := 50
	// Create the data file to ingest
	inputFile, err := os.CreateTemp(tmpDir, "input.txt")
	require.NoError(t, err, "failed to create temp file to hold data to ingest")
	inputFilePath := inputFile.Name()

	// these messages will fail to index as message is expected to be of integer type
	for i := 0; i < numEvents; i++ {
		_, err = inputFile.Write([]byte(fmt.Sprintf("Line %d\n", i)))
		require.NoErrorf(t, err, "failed to write line %d to temp file", i)
	}
	err = inputFile.Close()
	require.NoError(t, err, "failed to close data temp file")

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// Create the otel configuration file
	type otelConfigOptions struct {
		InputPath  string
		ESEndpoint string
		ESApiKey   string
		Namespace  string
	}
	esEndpoint, err := integration.GetESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	decodedApiKey, err := getDecodedApiKey(esApiKey)
	require.NoError(t, err)

	configTemplate := `
agent.internal.runtime.filebeat.filestream: otel
inputs:
  - type: filestream
    id: filestream-e2e
    use_output: default
    streams:
      - id: e2e
        data_stream:
          dataset: sensitive
          namespace: {{ .Namespace }}
        paths:
          - {{.InputPath}}
        prospector.scanner.fingerprint.enabled: false
        file_identity.native: ~
outputs:
  default:
    type: elasticsearch
    hosts: [{{.ESEndpoint}}]
    api_key: "{{.ESApiKey}}"
    otel:
      exporter:
        telemetry:
          log_failed_docs_input: true
agent:
  monitoring:
    enabled: true
    metrics: false
    logs: true
    _runtime_experimental: otel
agent.logging.level: debug
agent.logging.stderr: true
`
	index := "logs-sensitive-" + info.Namespace
	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
			otelConfigOptions{
				InputPath:  inputFilePath,
				ESEndpoint: esEndpoint,
				ESApiKey:   decodedApiKey,
				Namespace:  info.Namespace,
			}))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	err = fixture.Configure(ctx, configBuffer.Bytes())
	require.NoError(t, err)

	err = setStrictMapping(info.ESClient, index)
	require.NoError(t, err, "could not set strict mapping due to %v", err)

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	output, err := fixture.Install(ctx, &atesting.InstallOpts{Privileged: true, Force: true})
	require.NoError(t, err, "Elastic Agent installation failed with error: %w, output: %s", err, string(output))

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		assertBeatsHealthy(collect, &status, component.OtelRuntimeManager, 2)
	}, 1*time.Minute, 1*time.Second)

	// Check 1:
	// Ensure sensitive logs from ES exporter are not shipped to ES
	rawQuery := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": map[string]any{
					"match_phrase": map[string]any{
						// this message comes from ES exporter
						"message": "failed to index document; input may contain sensitive data",
					},
				},
				"filter": map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": timestamp}}},
			},
		},
		"sort": []map[string]any{
			{"@timestamp": map[string]any{"order": "asc"}},
		},
	}

	var monitoringDoc estools.Documents
	require.EventuallyWithT(t,
		func(ct *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer findCancel()

			monitoringDoc, err = estools.PerformQueryForRawQuery(findCtx, rawQuery, "logs-elastic_agent-default*", info.ESClient)
			require.NoError(ct, err)

			assert.GreaterOrEqual(ct, monitoringDoc.Hits.Total.Value, 1)
		},
		3*time.Minute, 5*time.Second,
		"Expected at least %d log, got %d", 1, monitoringDoc.Hits.Total.Value)

	inputField := monitoringDoc.Hits.Hits[0].Source["input"]
	inputFieldStr, ok := inputField.(string)
	if ok {
		// we check if it contains the original message line
		assert.NotContains(t, inputFieldStr, "message: Line", "monitoring logs contain original input")
	}

	// Check 2:
	// Ensure event logs from elastic owned components is not shipped i.e drop_processor works correctly
	rawQuery = map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": map[string]any{
					"match": map[string]any{
						// event logs contain a special field on them
						"log.type": "event",
					},
				},
				"filter": map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": timestamp}}},
			},
		},
		"sort": []map[string]any{
			{"@timestamp": map[string]any{"order": "asc"}},
		},
	}

	findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer findCancel()

	docs, err := estools.GetLogsForIndexWithContext(findCtx, info.ESClient, "logs-elastic_agent*", map[string]interface{}{
		"log.type": "event",
	})

	assert.NoError(t, err)
	assert.Zero(t, docs.Hits.Total.Value)
}

func TestSensitiveIncludeSourceOnError(t *testing.T) {
	// The ES exporter logs the original document on indexing failures
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		Sudo:  true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})
	tmpDir := t.TempDir()
	numEvents := 50
	// Create the data file to ingest
	inputFile, err := os.CreateTemp(tmpDir, "input.txt")
	require.NoError(t, err, "failed to create temp file to hold data to ingest")
	inputFilePath := inputFile.Name()

	// these messages will fail to index as message is expected to be of integer type
	for i := 0; i < numEvents; i++ {
		_, err = inputFile.Write([]byte(fmt.Sprintf("Line %d\n", i)))
		require.NoErrorf(t, err, "failed to write line %d to temp file", i)
	}
	err = inputFile.Close()
	require.NoError(t, err, "failed to close data temp file")

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	// Create the otel configuration file
	type otelConfigOptions struct {
		InputPath  string
		ESEndpoint string
		ESApiKey   string
		Namespace  string
	}
	esEndpoint, err := integration.GetESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)
	decodedApiKey, err := getDecodedApiKey(esApiKey)
	require.NoError(t, err)

	configTemplate := `
inputs:
  - type: filestream
    id: filestream-e2e
    use_output: default
    streams:
      - id: e2e
        data_stream:
          dataset: source.error
          namespace: {{ .Namespace }}
        paths:
          - {{.InputPath}}
        prospector.scanner.fingerprint.enabled: false
        file_identity.native: ~
outputs:
  default:
    type: elasticsearch
    hosts: [{{.ESEndpoint}}]
    api_key: "{{.ESApiKey}}"
agent:
  monitoring:
    enabled: true
    metrics: false
    logs: true
    _runtime_experimental: otel
agent.internal.runtime.filebeat.filestream: otel
agent.logging.level: debug
agent.logging.stderr: true
`
	index := "logs-source.error-" + info.Namespace
	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
			otelConfigOptions{
				InputPath:  inputFilePath,
				ESEndpoint: esEndpoint,
				ESApiKey:   decodedApiKey,
				Namespace:  info.Namespace,
			}))

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Minute)
	defer cancel()
	err = fixture.Prepare(ctx)
	require.NoError(t, err)

	err = fixture.Configure(ctx, configBuffer.Bytes())
	require.NoError(t, err)

	err = setStrictMapping(info.ESClient, index)
	require.NoError(t, err, "could not set strict mapping due to %v", err)

	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	output, err := fixture.Install(ctx, &atesting.InstallOpts{Privileged: true, Force: true})
	require.NoError(t, err, "Elastic Agent installation failed with error: %w, output: %s", err, string(output))

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		assertBeatsHealthy(collect, &status, component.OtelRuntimeManager, 2)
	}, 1*time.Minute, 1*time.Second)

	// Check 1:
	// Ensure fields containing sensitive data from ES exporter are not shipped to ES
	rawQuery := map[string]any{
		"query": map[string]any{
			"bool": map[string]any{
				"must": map[string]any{
					"match_phrase": map[string]any{
						// this message comes from ES exporter
						"message": "failed to index document",
					},
				},
				"filter": map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": timestamp}}},
			},
		},
		"sort": []map[string]any{
			{"@timestamp": map[string]any{"order": "asc"}},
		},
	}

	var monitoringDoc estools.Documents
	assert.EventuallyWithT(t,
		func(ct *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer findCancel()

			monitoringDoc, err = estools.PerformQueryForRawQuery(findCtx, rawQuery, "logs-elastic_agent-default*", info.ESClient)
			require.NoError(ct, err)

			assert.GreaterOrEqual(ct, monitoringDoc.Hits.Total.Value, 1)
		},
		2*time.Minute, 5*time.Second,
		"Expected at least %d log, got %d", 1, monitoringDoc.Hits.Total.Value)

	// assert that error.reason is not part of monitoring logs
	inputField := monitoringDoc.Hits.Hits[0].Source["error.reason"]
	assert.Nil(t, inputField)

}

// setStrictMapping takes es client and index name
// and sets strict mapping for that index.
// Useful to reproduce mapping conflicts required for testing
func setStrictMapping(client *elasticsearch.Client, index string) error {
	// Define the body
	body := map[string]interface{}{
		"index_patterns": []string{index + "*"},
		"template": map[string]interface{}{
			"mappings": map[string]interface{}{
				"dynamic": "strict",
				"properties": map[string]interface{}{
					"@timestamp": map[string]string{"type": "date"},
					"message":    map[string]string{"type": "integer"}, // we set message type to integer to cause mapping conflict
				},
			},
		},
		"priority": 500,
	}

	// Marshal body to JSON
	jsonData, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}

	esEndpoint, err := integration.GetESHost()
	if err != nil {
		return fmt.Errorf("error getting elasticsearch endpoint: %v", err)
	}

	// Create a context
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Build request
	url := fmt.Sprintf("%s/_index_template/%s", esEndpoint, index)
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("could not create http request to ES server: %v", err)
	}

	// Set content type header
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Perform(req)
	if err != nil {
		return fmt.Errorf("error performing request: %v", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		responseBody, readErr := io.ReadAll(resp.Body)
		if readErr != nil {
			return fmt.Errorf("unexpected status code: %d, error reading response body: %w", resp.StatusCode, readErr)
		}
		return fmt.Errorf("unexpected status code: %d, response body: %s", resp.StatusCode, responseBody)
	}
	return nil
}

// TestMonitoringNoDuplicates checks to see if switching to otel
// runtime re-ingests logs.  Also checks to make sure restarting
// elastic-agent when using otel runtime for monitoring doesn't
// re-ingest logs.
//
// Flow
//  1. Create policy in Kibana with just monitoring and "process" runtime
//  2. Install and Enroll
//  3. Switch to monitoring "otel" runtime
//  4. restart agent 3 times, making sure healthy between restarts
//  5. switch back to "process" runtime
//  6. query ES for monitoring logs with aggregation on fingerprint and line number,
//     ideally 0 duplicates but possible to have a small number
//  7. uninstall
func TestMonitoringNoDuplicates(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
			{Type: define.Windows},
		},
		Stack: &define.Stack{},
		Sudo:  true,
	})

	ctx, cancel := testcontext.WithDeadline(t,
		context.Background(),
		time.Now().Add(5*time.Minute))
	t.Cleanup(cancel)

	policyName := fmt.Sprintf("%s-%s", t.Name(), uuid.Must(uuid.NewV4()).String())
	createPolicyReq := kibana.AgentPolicy{
		Name:        policyName,
		Namespace:   info.Namespace,
		Description: fmt.Sprintf("%s policy", t.Name()),
		MonitoringEnabled: []kibana.MonitoringEnabledOption{
			kibana.MonitoringEnabledLogs,
			kibana.MonitoringEnabledMetrics,
		},
		Overrides: map[string]any{
			"agent": map[string]any{
				"monitoring": map[string]any{
					"_runtime_experimental": "process",
				},
			},
		},
	}
	policyResponse, err := info.KibanaClient.CreatePolicy(ctx, createPolicyReq)
	require.NoError(t, err, "error creating policy")

	enrollmentToken, err := info.KibanaClient.CreateEnrollmentAPIKey(ctx,
		kibana.CreateEnrollmentAPIKeyRequest{
			PolicyID: policyResponse.ID,
		})

	fut, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	err = fut.Prepare(ctx)
	require.NoError(t, err)

	fleetServerURL, err := fleettools.DefaultURL(ctx, info.KibanaClient)
	require.NoError(t, err, "failed getting Fleet Server URL")

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Privileged:     true,
		Force:          true,
		EnrollOpts: atesting.EnrollOpts{
			URL:             fleetServerURL,
			EnrollmentToken: enrollmentToken.APIKey,
		},
	}
	combinedOutput, err := fut.Install(ctx, &installOpts)
	require.NoErrorf(t, err, "error install with enroll: %s\ncombinedoutput:\n%s", err, string(combinedOutput))

	// store timestamp to filter duplicate docs with timestamp greater than this value
	installTimestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	healthCheck := func(ctx context.Context, message string, runtime component.RuntimeManager, componentCount int, timestamp string) {
		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			var statusErr error
			status, statusErr := fut.ExecStatus(ctx)
			assert.NoError(collect, statusErr)
			assertBeatsHealthy(collect, &status, runtime, componentCount)
		}, 1*time.Minute, 1*time.Second)
		require.Eventuallyf(t,
			func() bool {
				findCtx, findCancel := context.WithTimeout(ctx, 10*time.Second)
				defer findCancel()
				mustClauses := []map[string]any{
					{"match_phrase": map[string]any{"message": message}},
					{"match": map[string]any{"data_stream.type": "logs"}},
					{"match": map[string]any{"data_stream.dataset": "elastic_agent"}},
					{"match": map[string]any{"data_stream.namespace": info.Namespace}},
				}
				rawQuery := map[string]any{
					"query": map[string]any{
						"bool": map[string]any{
							"must":   mustClauses,
							"filter": map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": timestamp}}},
						},
					},
					"sort": []map[string]any{
						{"@timestamp": map[string]any{"order": "asc"}},
					},
				}
				docs, err := estools.PerformQueryForRawQuery(findCtx, rawQuery, "logs-*", info.ESClient)
				require.NoError(t, err)
				return docs.Hits.Total.Value > 0
			},
			4*time.Minute, 5*time.Second,
			"health check failed: timestamp: %s", timestamp)
	}

	// make sure running and logs are making it to ES
	healthCheck(ctx,
		"control checkin v2 protocol has chunking enabled",
		component.ProcessRuntimeManager,
		3,
		installTimestamp)

	// Switch to otel monitoring
	otelMonUpdateReq := kibana.AgentPolicyUpdateRequest{
		Name:      policyName,
		Namespace: info.Namespace,
		Overrides: map[string]any{
			"agent": map[string]any{
				"monitoring": map[string]any{
					"_runtime_experimental": "otel",
				},
			},
		},
	}

	otelMonResp, err := info.KibanaClient.UpdatePolicy(ctx,
		policyResponse.ID, otelMonUpdateReq)
	require.NoError(t, err)

	otelTimestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	// wait until policy is applied
	policyCheck := func(expectedRevision int) {
		require.Eventually(t, func() bool {
			inspectOutput, err := fut.ExecInspect(ctx)
			require.NoError(t, err)
			return expectedRevision == inspectOutput.Revision
		}, 3*time.Minute, 1*time.Second)
	}
	policyCheck(otelMonResp.Revision)

	// make sure running and logs are making it to ES
	healthCheck(ctx,
		"Everything is ready. Begin running and processing data.",
		component.OtelRuntimeManager,
		3,
		otelTimestamp)

	// restart 3 times, checks path definition is stable
	for range 3 {
		restartTimestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
		restartBytes, err := fut.Exec(ctx, []string{"restart"})
		require.NoErrorf(t,
			err,
			"Restart error: %s, output was: %s",
			err,
			string(restartBytes))
		healthCheck(ctx,
			"Everything is ready. Begin running and processing data.",
			component.OtelRuntimeManager,
			3,
			restartTimestamp)
	}

	// Switch back to process monitoring
	processMonUpdateReq := kibana.AgentPolicyUpdateRequest{
		Name:      policyName,
		Namespace: info.Namespace,
		Overrides: map[string]any{
			"agent": map[string]any{
				"monitoring": map[string]any{
					"_runtime_experimental": "process",
				},
			},
		},
	}

	processMonResp, err := info.KibanaClient.UpdatePolicy(ctx,
		policyResponse.ID, processMonUpdateReq)
	require.NoError(t, err)

	processTimestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	// wait until policy is applied
	policyCheck(processMonResp.Revision)

	// make sure running and logs are making it to ES
	healthCheck(ctx,
		"control checkin v2 protocol has chunking enabled",
		component.ProcessRuntimeManager,
		3,
		processTimestamp)

	// duplicate check
	rawQuery := map[string]any{
		"runtime_mappings": map[string]any{
			"log.offset": map[string]any{
				"type": "keyword",
			},
			"log.file.fingerprint": map[string]any{
				"type": "keyword",
			},
		},
		"query": map[string]any{
			"bool": map[string]any{
				"must": []map[string]any{
					{"match": map[string]any{"data_stream.type": "logs"}},
					{"match": map[string]any{"data_stream.dataset": "elastic_agent"}},
					{"match": map[string]any{"data_stream.namespace": info.Namespace}},
				},
				"filter": map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": installTimestamp}}},
			},
		},
		"aggs": map[string]any{
			"duplicates": map[string]any{
				"multi_terms": map[string]any{
					"size":          500,
					"min_doc_count": 2,
					"terms": []map[string]any{
						{"field": "log.file.fingerprint"},
						{"field": "log.offset"},
					},
				},
			},
		},
	}
	var buf bytes.Buffer
	err = json.NewEncoder(&buf).Encode(rawQuery)
	require.NoError(t, err)

	es := esapi.New(info.ESClient)
	res, err := es.Search(
		es.Search.WithIndex("logs-*"),
		es.Search.WithSize(0),
		es.Search.WithBody(&buf),
		es.Search.WithPretty(),
		es.Search.WithContext(ctx),
	)
	require.NoError(t, err)
	require.Falsef(t, (res.StatusCode >= http.StatusMultipleChoices || res.StatusCode < http.StatusOK), "status should be 2xx was: %d", res.StatusCode)
	resultBuf, err := io.ReadAll(res.Body)
	require.NoError(t, err)

	aggResults := map[string]any{}
	err = json.Unmarshal(resultBuf, &aggResults)
	aggs, ok := aggResults["aggregations"].(map[string]any)
	require.Truef(t, ok, "'aggregations' wasn't a map[string]any, result was %s", string(resultBuf))
	dups, ok := aggs["duplicates"].(map[string]any)
	require.Truef(t, ok, "'duplicates' wasn't a map[string]any, result was %s", string(resultBuf))
	buckets, ok := dups["buckets"].([]any)
	require.Truef(t, ok, "'buckets' wasn't a []any, result was %s", string(resultBuf))

	hits, ok := aggResults["hits"].(map[string]any)
	require.Truef(t, ok, "'hits' wasn't a map[string]any, result was %s", string(resultBuf))
	total, ok := hits["total"].(map[string]any)
	require.Truef(t, ok, "'total' wasn't a map[string]any, result was %s", string(resultBuf))
	value, ok := total["value"].(float64)
	require.Truef(t, ok, "'total' wasn't an int, result was %s", string(resultBuf))

	require.Equalf(t, 0, len(buckets), "len(buckets): %d, hits.total.value: %d, result was %s", len(buckets), value, string(resultBuf))

	// Uninstall
	combinedOutput, err = fut.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
	require.NoErrorf(t, err, "error uninstalling beat receiver agent monitoring, err: %s, combined output: %s", err, string(combinedOutput))
}

func componentVersionInfoNameForRuntime(runtime component.RuntimeManager) string {
	var componentVersionInfoName string
	switch runtime {
	case component.OtelRuntimeManager:
		componentVersionInfoName = "beats-receiver"
	case component.ProcessRuntimeManager:
		componentVersionInfoName = "beat-v2-client"
	default:
		componentVersionInfoName = componentVersionInfoNameForRuntime(component.DefaultRuntimeManager)
	}
	return componentVersionInfoName
}
