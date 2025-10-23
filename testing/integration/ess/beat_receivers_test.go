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
	"runtime"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/elastic/elastic-agent/pkg/component"
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

	output, err := classicFixture.InstallWithoutEnroll(ctx, &installOpts)
	require.NoErrorf(t, err, "error install withouth enroll: %s\ncombinedoutput:\n%s", err, string(output))
	timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := classicFixture.ExecStatus(ctx)
		assert.NoError(collect, statusErr)
		assertBeatsHealthy(collect, &status, component.ProcessRuntimeManager, 3)
		return
	}, 1*time.Minute, 1*time.Second)

	// 2. Assert monitoring logs and metrics are available on ES
	for _, tc := range tests {
		require.Eventuallyf(t,
			func() bool {
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
				require.NoError(t, err)
				if docs.Hits.Total.Value != 0 {
					key := tc.dsType + "-" + tc.dsDataset + "-" + processNamespace
					agentDocs[key] = docs
				}
				return docs.Hits.Total.Value > 0
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
		assertBeatsHealthy(collect, &status, component.OtelRuntimeManager, 4)
		return
	}, 1*time.Minute, 1*time.Second)

	// 5. Assert monitoring logs and metrics are available on ES (for otel mode)
	for _, tc := range tests {
		require.Eventuallyf(t,
			func() bool {
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
				require.NoError(t, err)
				if docs.Hits.Total.Value != 0 {
					key := tc.dsType + "-" + tc.dsDataset + "-" + receiverNamespace
					otelDocs[key] = docs
				}
				return docs.Hits.Total.Value > 0
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
			// agent.version is different because we force version 9.0.0 in CI
			"agent.version",
			"data_stream.namespace",
			"elastic_agent.id",
			"event.ingested",

			// only in receiver doc
			"agent.otelcol",
			"agent.otelcol.component.id",
			"agent.otelcol.component.kind",
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
inputs:
  # Collecting system metrics
  - type: system/metrics
    id: unique-system-metrics-input
    data_stream.namespace: {{.Namespace}}
    use_output: default
    {{if ne .RuntimeExperimental "" }}
    _runtime_experimental: {{.RuntimeExperimental}}
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
			// We ignore agent.version because a different version is forced in CI
			"agent.version",
			"agent.ephemeral_id",
			"elastic_agent.id",
			"data_stream.namespace",
			"event.ingested",
			"event.duration",

			// only in receiver doc
			"agent.otelcol.component.id",
			"agent.otelcol.component.kind",
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
inputs:
  # Collecting system metrics
  - type: system/metrics
    id: unique-system-metrics-input
    _runtime_experimental: {{.RuntimeExperimental}}
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
		return
	}, 2*time.Minute, 5*time.Second)

	// change configuration and wait until the beats receiver is healthy
	err = fixture.Configure(ctx, receiverConfig)
	require.NoError(t, err)

	require.EventuallyWithT(t, func(collect *assert.CollectT) {
		var statusErr error
		status, statusErr := fixture.ExecStatus(ctx)
		require.NoError(collect, statusErr)
		assertBeatsReady(collect, &status, component.OtelRuntimeManager)
		return
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
inputs:
  # Collecting system metrics
  - type: system/metrics
    id: unique-system-metrics-input
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
agent.monitoring.enabled: false
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
		// we should be running beats processes even though the otel runtime was requested
		assertBeatsHealthy(collect, &status, component.ProcessRuntimeManager, 1)
		return
	}, 1*time.Minute, 1*time.Second)
	logsBytes, err := fixture.Exec(ctx, []string{"logs", "-n", "1000", "--exclude-events"})
	require.NoError(t, err)

	// verify we've logged a warning about using the process runtime
	var unsupportedLogRecord map[string]any
	for _, line := range strings.Split(string(logsBytes), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var logRecord map[string]any
		if unmarshalErr := json.Unmarshal([]byte(line), &logRecord); unmarshalErr != nil {
			continue
		}

		if message, ok := logRecord["message"].(string); ok && strings.HasPrefix(message, "otel runtime is not supported") {
			unsupportedLogRecord = logRecord
			break
		}
	}

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic-Agent logs seen by the test:")
			t.Log(string(logsBytes))
		}
	})

	require.NotNil(t, unsupportedLogRecord, "unsupported log message should be present")
	message, ok := unsupportedLogRecord["message"].(string)
	require.True(t, ok, "log message field should be a string")
	expectedMessage := "otel runtime is not supported for component system/metrics-default, switching to process runtime, reason: unsupported configuration for system/metrics-default: error translating config for output: default, unit: system/metrics-default, error: indices is currently not supported: unsupported operation"
	assert.Equal(t, expectedMessage, message)
}

func assertCollectorComponentsHealthy(t *assert.CollectT, status *atesting.AgentStatusCollectorOutput) {
	assert.Equal(t, int(cproto.CollectorComponentStatus_StatusOK), status.Status, "component status should be ok")
	assert.Equal(t, "", status.Error, "component status should not have an error")
	for _, componentStatus := range status.ComponentStatusMap {
		assertCollectorComponentsHealthy(t, componentStatus)
	}
}

func assertBeatsHealthy(t *assert.CollectT, status *atesting.AgentStatusOutput, runtime component.RuntimeManager, componentCount int) {
	var componentVersionInfoName string
	switch runtime {
	case "otel":
		componentVersionInfoName = "beats-receiver"
	default:
		componentVersionInfoName = "beat-v2-client"
	}

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
			logRecords = append(logRecords, logRecord)
		}
	}
	return logRecords
}

func genIgnoredFields(goos string) []string {
	switch goos {
	case "windows":
		return []string{
			"log.file.idxhi",
			"log.file.idxlo",
			"log.offset",
		}
	default:
		return []string{
			"log.file.device_id",
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
inputs:
  - type: filestream
    id: filestream-e2e
    use_output: default
    _runtime_experimental: otel
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
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		esEndpoint+"/_index_template/no-dynamic-template",
		bytes.NewReader(jsonData))
	if err != nil {
		return fmt.Errorf("could not create http request to ES server: %v", err)
	}

	// Set content type header
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Perform(req)
	if err != nil {
		return fmt.Errorf("error performing request: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("incorrect response code: %v", err)
	}
	return nil
}
