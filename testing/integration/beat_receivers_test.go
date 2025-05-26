// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"maps"
	"net/http"
	"runtime"
	"slices"
	"strings"
	"testing"
	"text/template"
	"time"

	"github.com/stretchr/testify/assert"

	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
)

var (
	agentDocs        map[string]estools.Documents
	otelDocs         map[string]estools.Documents
	commonLogMessage = "Determined allowed capabilities"
)

// TestAgentMonitoring is a test to provide a baseline for what
// elastic-agent monitoring looks like with classic monitoring.  It
// will be expanded in the future to compare with beats receivers for
// elastic-agent monitoring.
func TestAgentMonitoring(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
			{Type: define.Windows},
		},
		Stack: &define.Stack{},
		Sudo:  true,
	})

	agentDocs = make(map[string]estools.Documents)
	otelDocs = make(map[string]estools.Documents)

	// Tests logs and metrics are present
	type test struct {
		dsType      string
		dsDataset   string
		dsNamespace string
		message     string
	}

	tests := []test{
		{dsType: "logs", dsDataset: "elastic_agent", dsNamespace: info.Namespace, message: commonLogMessage},
		{dsType: "metrics", dsDataset: "elastic_agent.elastic_agent", dsNamespace: info.Namespace},
		{dsType: "metrics", dsDataset: "elastic_agent.filebeat", dsNamespace: info.Namespace},
		{dsType: "metrics", dsDataset: "elastic_agent.filebeat_input", dsNamespace: info.Namespace},
		{dsType: "metrics", dsDataset: "elastic_agent.metricbeat", dsNamespace: info.Namespace},
	}

	installOpts := atesting.InstallOpts{
		NonInteractive: true,
		Privileged:     true,
		Force:          true,
	}

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
		Namespaces       []map[string]any `yaml:"namespaces"`
	}

	policy := PolicyStruct{}
	err = yaml.Unmarshal(policyBytes, &policy)
	require.NoError(t, err, "error unmarshalling policy")
	d, prs := policy.Outputs["default"]
	require.True(t, prs, "default must be in outputs")
	d.ApiKey = string(apiKey)
	policy.Outputs["default"] = d

	// Flow
	// 1. Create and install policy with just monitoring
	// 2. Download the policy, add the API key
	// 3. Install without enrolling in fleet
	// 4. Make sure logs and metrics for agent monitoring are being received
	t.Run("verify elastic-agent monitoring functionality", func(t *testing.T) {
		ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
		t.Cleanup(cancel)

		// beats processes and beats receivers should use a different namespace to ensure each test looks only at the
		// right data
		actualNamespace := fmt.Sprintf("%s-%s", info.Namespace, "process")
		policy.Agent.Monitoring["namespace"] = actualNamespace

		updatedPolicyBytes, err := yaml.Marshal(policy)
		require.NoErrorf(t, err, "error marshalling policy, struct was %v", policy)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("policy was %s", string(updatedPolicyBytes))
			}
		})

		// 3. Install without enrolling in fleet
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		err = fixture.Prepare(ctx)
		require.NoError(t, err, "error preparing fixture")

		err = fixture.Configure(ctx, updatedPolicyBytes)
		require.NoError(t, err, "error configuring fixture")

		output, err := fixture.InstallWithoutEnroll(ctx, &installOpts)
		require.NoErrorf(t, err, "error install withouth enroll: %s\ncombinedoutput:\n%s", err, string(output))

		require.Eventually(t, func() bool {
			err = fixture.IsHealthy(ctx)
			if err != nil {
				t.Logf("waiting for agent healthy: %s", err.Error())
				return false
			}
			return true
		}, 1*time.Minute, 1*time.Second)

		for _, tc := range tests {
			require.Eventuallyf(t,
				func() bool {
					findCtx, findCancel := context.WithTimeout(ctx, 10*time.Second)
					defer findCancel()
					mustClauses := []map[string]any{
						{"match": map[string]any{"data_stream.type": tc.dsType}},
						{"match": map[string]any{"data_stream.dataset": tc.dsDataset}},
						{"match": map[string]any{"data_stream.namespace": actualNamespace}},
					}

					// Only add the "message" match if tc.message is not empty
					// This conditional check will not be required when test for metrics is included
					if tc.message != "" {
						mustClauses = append(mustClauses, map[string]any{
							"match": map[string]any{"message": tc.message},
						})
					}

					rawQuery := map[string]any{
						"query": map[string]any{
							"bool": map[string]any{
								"must": mustClauses,
							},
						},
					}

					docs, err := estools.PerformQueryForRawQuery(findCtx, rawQuery, tc.dsType+"-*", info.ESClient)
					require.NoError(t, err)
					if docs.Hits.Total.Value != 0 {
						key := tc.dsType + "-" + tc.dsDataset + "-" + tc.dsNamespace
						agentDocs[key] = docs
					}
					return docs.Hits.Total.Value > 0
				},
				2*time.Minute, 5*time.Second,
				"No documents found for type: %s, dataset: %s, namespace: %s", tc.dsType, tc.dsDataset, tc.dsNamespace)
		}
	})

	t.Run("compare logs ingested by agent monitoring vs otel monitoring", func(t *testing.T) {
		// skipping this because the log-path should be handled differently in windows
		if runtime.GOOS == "windows" {
			t.Skip("skipping this test on windows for now")
		}

		// Not proceed with this test if monitoring logs from elastic-agent does not exist
		monitoringLogIndex := "logs-elastic_agent-" + info.Namespace
		require.NotPanics(
			t, func() {
				_ = agentDocs[monitoringLogIndex].Hits.Hits[0].Source
			}, "monitoring logs from elastic-agent should exist before proceeding",
		)

		ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
		t.Cleanup(cancel)

		// beats processes and beats receivers should use a different namespace to ensure each test looks only at the
		// right data
		actualNamespace := fmt.Sprintf("%s-%s", info.Namespace, "otel")
		policy.Agent.Monitoring["namespace"] = actualNamespace

		// switch monitoring to the otel runtime
		policy.Agent.Monitoring["_runtime_experimental"] = "otel"

		updatedPolicyBytes, err := yaml.Marshal(policy)
		require.NoErrorf(t, err, "error marshalling policy, struct was %v", policy)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("policy was %s", string(updatedPolicyBytes))
			}
		})

		// 3. Install without enrolling in fleet
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		err = fixture.Prepare(ctx)
		require.NoError(t, err, "error preparing fixture")

		err = fixture.Configure(ctx, updatedPolicyBytes)
		require.NoError(t, err, "error configuring fixture")

		output, err := fixture.InstallWithoutEnroll(ctx, &installOpts)
		require.NoErrorf(t, err, "error install without enroll: %s\ncombinedoutput:\n%s", err, string(output))

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, statusErr := fixture.ExecStatus(ctx)
			assert.NoError(collect, statusErr)
			// agent should be healthy
			assert.Equal(collect, int(cproto.State_HEALTHY), status.State)
			// we should have no normal components running
			assert.Zero(collect, len(status.Components))

			// we should have filebeatreceiver and metricbeatreceiver running
			otelCollectorStatus := status.Collector
			require.NotNil(collect, otelCollectorStatus)
			assert.Equal(collect, int(cproto.CollectorComponentStatus_StatusOK), otelCollectorStatus.Status)
			pipelineStatusMap := otelCollectorStatus.ComponentStatusMap

			// we should have 3 pipelines running: filestream for logs, http metrics and beats metrics
			assert.Equal(collect, 3, len(pipelineStatusMap))

			fileStreamPipeline := "pipeline:logs/_agent-component/filestream-monitoring"
			httpMetricsPipeline := "pipeline:logs/_agent-component/http/metrics-monitoring"
			beatsMetricsPipeline := "pipeline:logs/_agent-component/beat/metrics-monitoring"
			assert.Contains(collect, pipelineStatusMap, fileStreamPipeline)
			assert.Contains(collect, pipelineStatusMap, httpMetricsPipeline)
			assert.Contains(collect, pipelineStatusMap, beatsMetricsPipeline)

			// and all the components should be healthy
			assertCollectorComponentsHealthy(collect, otelCollectorStatus)

			return
		}, 1*time.Minute, 1*time.Second)

		// run this only for logs for now
		tc := tests[0]
		require.Eventuallyf(t,
			func() bool {
				findCtx, findCancel := context.WithTimeout(ctx, 10*time.Second)
				defer findCancel()
				mustClauses := []map[string]any{
					{"match": map[string]any{"message": tc.message}},
					{"match": map[string]any{"data_stream.type": tc.dsType}},
					{"match": map[string]any{"data_stream.dataset": tc.dsDataset}},
					{"match": map[string]any{"data_stream.namespace": actualNamespace}},
				}

				rawQuery := map[string]any{
					"query": map[string]any{
						"bool": map[string]any{
							"must": mustClauses,
						},
					},
				}

				docs, err := estools.PerformQueryForRawQuery(findCtx, rawQuery, ".ds-"+monitoringLogIndex+"*", info.ESClient)
				require.NoError(t, err)
				if docs.Hits.Total.Value != 0 {
					otelDocs[monitoringLogIndex] = docs
				}
				return docs.Hits.Total.Value > 0
			},
			2*time.Minute, 5*time.Second,
			"No documents found in otel mode for type : %s, dataset: %s, namespace: %s", tc.dsType, tc.dsDataset, tc.dsNamespace)

		agent := agentDocs[monitoringLogIndex].Hits.Hits[0].Source
		otel := otelDocs[monitoringLogIndex].Hits.Hits[0].Source
		ignoredFields := []string{
			// Expected to change between agentDocs and OtelDocs
			"@timestamp",
			"agent.ephemeral_id",
			// agent.id is different because it's the id of the underlying beat
			"agent.id",
			// agent.version is different because we force version 9.0.0 in CI
			"agent.version",
			// elastic_agent.id is different because we currently start a new agent in the second subtest
			// this should be fixed in the future
			"elastic_agent.id",
			"data_stream.namespace",
			"log.file.inode",
			"log.file.fingerprint",
			"log.file.path",
			"log.offset",
			"event.ingested",
		}

		AssertMapsEqual(t, agent, otel, ignoredFields, "expected documents to be equal")
	})

}

// TestAgentMetricsInput is a test that compares documents ingested by
// agent metrics input and otel metrics input and asserts that they are
// equivalent.
func TestAgentMetricsInput(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})

	metricsets := []string{"cpu", "memory", "network", "filesystem"}

	type configOptions struct {
		HomeDir         string
		ESEndpoint      string
		BeatsESApiKey   string
		FBReceiverIndex string
		Namespace       string
	}
	configTemplate := `agent.logging.level: info
agent.logging.to_stderr: true
inputs:
  - type: system/metrics
    id: agent-system-metrics-input
    data_stream.namespace: {{.Namespace}}
    use_output: default
    streams:
      - metricsets:
        - cpu
        data_stream.dataset: system.cpu
      - metricsets:
        - memory
        data_stream.dataset: system.memory
      - metricsets:
        - network
        data_stream.dataset: system.network
      - metricsets:
        - filesystem
        data_stream.dataset: system.filesystem
  - type: system/metrics
    id: otel-system-metrics-input
    data_stream.namespace: otel-{{.Namespace}}
    use_output: default
    _runtime_experimental: otel
    streams:
      - metricsets:
        - cpu
        data_stream.dataset: system.cpu
      - metricsets:
        - memory
        data_stream.dataset: system.memory
      - metricsets:
        - network
        data_stream.dataset: system.network
      - metricsets:
        - filesystem
        data_stream.dataset: system.filesystem
outputs:
  default:
    type: elasticsearch
    hosts: [{{.ESEndpoint}}]
    api_key: {{.BeatsESApiKey}}
`

	esEndpoint, err := getESHost()
	require.NoError(t, err, "error getting elasticsearch endpoint")
	esApiKey, err := createESApiKey(info.ESClient)
	require.NoError(t, err, "error creating API key")
	require.True(t, len(esApiKey.Encoded) > 1, "api key is invalid %q", esApiKey)

	beatsApiKey, err := base64.StdEncoding.DecodeString(esApiKey.Encoded)
	require.NoError(t, err, "error decoding api key")

	// map of metricset -> documents
	agentDocs := make(map[string]estools.Documents)
	otelDocs := make(map[string]estools.Documents)

	tmpDir := t.TempDir()

	var configBuffer bytes.Buffer
	require.NoError(t,
		template.Must(template.New("config").Parse(configTemplate)).Execute(&configBuffer,
			configOptions{
				HomeDir:       tmpDir,
				ESEndpoint:    esEndpoint,
				BeatsESApiKey: string(beatsApiKey),
				Namespace:     info.Namespace,
			}))
	configContents := configBuffer.Bytes()
	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Contents of agent config file:\n")
			println(string(configContents))
		}
	})

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(5*time.Minute))
	defer cancel()

	err = fixture.Prepare(ctx)
	require.NoError(t, err)
	err = fixture.Configure(ctx, configContents)
	require.NoError(t, err)

	cmd, err := fixture.PrepareAgentCommand(ctx, nil)
	require.NoError(t, err)
	cmd.WaitDelay = 1 * time.Second

	var output strings.Builder
	cmd.Stderr = &output
	cmd.Stdout = &output

	err = cmd.Start()
	require.NoError(t, err)

	t.Cleanup(func() {
		if t.Failed() {
			t.Log("Elastic-Agent output:")
			t.Log(output.String())
		}
	})

	require.Eventually(t, func() bool {
		err = fixture.IsHealthy(ctx)
		if err != nil {
			t.Logf("waiting for agent healthy: %s", err.Error())
			return false
		}
		return true
	}, 1*time.Minute, 1*time.Second)

	for _, mset := range metricsets {
		require.EventuallyWithTf(t,
			func(ct *assert.CollectT) {
				findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer findCancel()

				docs, err := estools.GetAllLogsForIndexWithContext(findCtx, info.ESClient, fmt.Sprintf(".ds-metrics-system.%s-%s*", mset, info.Namespace))
				require.NoError(ct, err)
				if docs.Hits.Total.Value != 0 {
					agentDocs[mset] = docs
				}
				require.Greater(ct, docs.Hits.Total.Value, 0, "agent docs count")

				docs, err = estools.GetAllLogsForIndexWithContext(findCtx, info.ESClient, fmt.Sprintf(".ds-metrics-system.%s-otel-%s*", mset, info.Namespace))
				require.NoError(ct, err)
				if docs.Hits.Total.Value != 0 {
					otelDocs[mset] = docs
				}
				require.Greater(ct, docs.Hits.Total.Value, 0, "otel docs count")
			},
			30*time.Second, 1*time.Second,
			"Expected to find at least one document for metricset %s, got 0", mset)
	}

	cancel()
	cmd.Wait()

	require.Greater(t, len(agentDocs), 0, "expected to find documents ingested by normal agent metrics input")
	require.Greater(t, len(otelDocs), 0, "expected to find documents ingested by beats receivers")

	// Fields that are present in both agent and otel documents, but are expected to change
	ignoredFields := []string{
		"@timestamp",
		"agent.id",
		"agent.ephemeral_id",
		"elastic_agent.id",
		"data_stream.namespace",
		"event.ingested",
		"event.duration",
	}

	// Fields that are randomly missing in the agent and otel documents based on the test environment.
	flakyFields := []string{
		// depends on network activity during the test
		"host.network.egress.bytes",
		"host.network.egress.packets",
		"host.network.ingress.bytes",
		"host.network.ingress.packets",
		"system.network.in.bytes",
		"system.network.in.packets",
		"system.network.in.dropped",
		"system.network.in.errors",
		"system.network.out.bytes",
		"system.network.out.dropped",
		"system.network.out.errors",
		"system.network.out.packets",
	}

	stripNondeterminism := func(m mapstr.M, mset string) {
		for _, field := range flakyFields {
			m.Delete(field)
		}

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

	for _, mset := range metricsets {
		t.Run(mset, func(t *testing.T) {
			require.Greater(t, len(agentDocs[mset].Hits.Hits), 0, "expected to find agent documents for metricset %s", mset)
			require.Greater(t, len(otelDocs[mset].Hits.Hits), 0, "expected to find otel documents for metricset %s", mset)

			agentDoc := mapstr.M(agentDocs[mset].Hits.Hits[0].Source).Flatten()
			otelDoc := mapstr.M(otelDocs[mset].Hits.Hits[0].Source).Flatten()

			agentKeys := slices.Collect(maps.Keys(agentDoc))
			otelKeys := slices.Collect(maps.Keys(otelDoc))
			slices.Sort(agentKeys)
			slices.Sort(otelKeys)
			assert.Equal(t, agentKeys, otelKeys, "expected to have the same keys in agent and otel documents for metricset %s", mset)

			stripNondeterminism(agentDoc, mset)
			stripNondeterminism(otelDoc, mset)

			AssertMapsEqual(t, agentDoc, otelDoc, ignoredFields, "expected documents to be equal for metricset "+mset)
		})

	}
}

func assertCollectorComponentsHealthy(t *assert.CollectT, status *atesting.AgentStatusCollectorOutput) {
	assert.Equal(t, int(cproto.CollectorComponentStatus_StatusOK), status.Status, "component status should be ok")
	assert.Equal(t, "", status.Error, "component status should not have an error")
	for _, componentStatus := range status.ComponentStatusMap {
		assertCollectorComponentsHealthy(t, componentStatus)
	}
}
