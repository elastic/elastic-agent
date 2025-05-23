// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package integration

import (
	"bytes"
	"context"
	"testing"
	"text/template"
	"time"

	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/pkg/control/v2/cproto"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestClassicAndReceiverAgentMonitoring is a test to compare documents ingested by
// elastic-agent monitoring classic mode vs otel mode
func TestClassicAndReceiverAgentMonitoring(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
		Sudo:  true,
	})

	agentDocs := make(map[string]estools.Documents)
	otelDocs := make(map[string]estools.Documents)

	// Tests logs and metrics are present
	type test struct {
		dsType          string
		dsDataset       string
		dsNamespace     string
		query           map[string]any
		onlyCompareKeys bool
		ignoreFields    []string
	}

	tests := []test{
		{
			dsType:          "logs",
			dsDataset:       "elastic_agent",
			dsNamespace:     info.Namespace,
			query:           map[string]any{"match_phrase": map[string]any{"message": "Determined allowed capabilities"}},
			onlyCompareKeys: false,
		},

		{
			dsType:          "metrics",
			dsDataset:       "elastic_agent.filebeat",
			dsNamespace:     info.Namespace,
			query:           map[string]any{"exists": map[string]any{"field": "beat.stats.memstats.rss"}},
			onlyCompareKeys: true,
			ignoreFields:    []string{"beat.elasticsearch.cluster.id", "beat.stats.libbeat.config.reloads", "beat.stats.libbeat.config.running", "beat.stats.libbeat.config.starts", "beat.stats.libbeat.config.stops"},
		},
		{
			dsType:          "metrics",
			dsDataset:       "elastic_agent.metricbeat",
			dsNamespace:     info.Namespace,
			query:           map[string]any{"exists": map[string]any{"field": "beat.stats.memstats.rss"}},
			onlyCompareKeys: true,
			ignoreFields:    []string{"beat.elasticsearch.cluster.id", "beat.stats.libbeat.config.reloads", "beat.stats.libbeat.config.running", "beat.stats.libbeat.config.starts", "beat.stats.libbeat.config.stops"},
		},
		{
			dsType:          "metrics",
			dsDataset:       "elastic_agent.elastic_agent",
			dsNamespace:     info.Namespace,
			onlyCompareKeys: true,
			query:           map[string]any{"exists": map[string]any{"field": "system.process.memory.size"}},
		},
		// TODO: fbreceiver must support /inputs/ endpoint for this to work
		// {
		// 	dsType:      "metrics",
		// 	dsDataset:   "elastic_agent.filebeat_input",
		// 	dsNamespace: info.Namespace,
		// 	query:       map[string]any{"exists": map[string]any{"field": "filebeat_input.bytes_processed_total"}},
		// },
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

	t.Run("verify elastic-agent monitoring functionality", func(t *testing.T) {
		ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
		t.Cleanup(cancel)

		type configOptions struct {
			InputPath  string
			ESEndpoint string
			ESApiKey   string
			Namespace  string
		}

		// 1. Start elastic agent monitoring in classic mode
		classicMonitoringTemplate := `
outputs:
  default:
    type: elasticsearch
    hosts: {{.ESEndpoint}}
    api_key: {{.ESApiKey }}
    preset: balanced

agent.monitoring:
  enabled: true
  logs: true
  metrics: true
  use_output: default
  namespace: {{ .Namespace }}
`
		// Get elasticsearch endpoint and api_key
		esEndpoint, err := getESHost()
		apiKeyResponse, err := createESApiKey(info.ESClient)
		require.NoError(t, err, "failed to get api key")
		require.True(t, len(apiKeyResponse.Encoded) > 1, "api key is invalid %q", apiKeyResponse)
		apiKey, err := getDecodedApiKey(apiKeyResponse)
		require.NoError(t, err, "error decoding api key")

		// Parse template
		var classicMonitoring bytes.Buffer
		template.Must(template.New("config").Parse(classicMonitoringTemplate)).Execute(&classicMonitoring,
			configOptions{
				ESEndpoint: esEndpoint,
				ESApiKey:   apiKey,
				Namespace:  info.Namespace,
			})

		classicFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		err = classicFixture.Prepare(ctx)
		require.NoError(t, err, "error preparing fixture")

		err = classicFixture.Configure(ctx, classicMonitoring.Bytes())
		require.NoError(t, err, "error configuring fixture")

		output, err := classicFixture.InstallWithoutEnroll(ctx, &installOpts)
		require.NoErrorf(t, err, "error install withouth enroll: %s\ncombinedoutput:\n%s", err, string(output))
		timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

		require.Eventually(t, func() bool {
			err = classicFixture.IsHealthy(ctx)
			if err != nil {
				t.Logf("waiting for agent healthy: %s", err.Error())
				return false
			}
			return true
		}, 1*time.Minute, 1*time.Second)

		// 2. Assert monitoring logs and metrics are available on ES
		for _, tc := range tests {
			require.Eventuallyf(t,
				func() bool {
					findCtx, findCancel := context.WithTimeout(ctx, 10*time.Second)
					defer findCancel()

					rawQuery := map[string]any{
						"query": map[string]any{
							"bool": map[string]any{
								"must":   tc.query,
								"filter": map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": timestamp}}},
							},
						},
					}

					index := tc.dsType + "-" + tc.dsDataset + "-" + tc.dsNamespace
					docs, err := estools.PerformQueryForRawQuery(findCtx, rawQuery, ".ds-"+index+"*", info.ESClient)
					require.NoError(t, err)
					if docs.Hits.Total.Value != 0 {
						key := tc.dsType + "-" + tc.dsDataset + "-" + tc.dsNamespace
						agentDocs[key] = docs
					}
					return docs.Hits.Total.Value > 0
				},
				2*time.Minute, 5*time.Second,
				"agent monitoring classic no documents found for timestamp: %s, type: %s, dataset: %s, namespace: %s, query: %v", timestamp, tc.dsType, tc.dsDataset, tc.dsNamespace, tc.query)
		}

		// 3. Uninstall
		combinedOutput, err := classicFixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
		require.NoErrorf(t, err, "error uninstalling classic agent monitoring, err: %s, combined output: %s", err, string(combinedOutput))

		// 4. Start elastic agent monitoring in otel mode
		receiverMonitoringTemplate := `
outputs:
  default:
    type: elasticsearch
    hosts: {{.ESEndpoint}}
    api_key: {{.ESApiKey }}
    preset: balanced

agent.monitoring:
  enabled: true
  logs: true
  metrics: true
  use_output: default
  namespace: {{ .Namespace }}
  _runtime_experimental: otel
`

		var receiverBuffer bytes.Buffer
		template.Must(template.New("config").Parse(receiverMonitoringTemplate)).Execute(&receiverBuffer,
			configOptions{
				ESEndpoint: esEndpoint,
				ESApiKey:   apiKey,
				Namespace:  info.Namespace,
			})

		beatReceiverFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)
		err = beatReceiverFixture.Prepare(ctx)
		require.NoError(t, err)
		err = beatReceiverFixture.Configure(ctx, receiverBuffer.Bytes())
		require.NoError(t, err)
		combinedOutput, err = beatReceiverFixture.InstallWithoutEnroll(ctx, &installOpts)
		require.NoErrorf(t, err, "error install without enroll: %s\ncombinedoutput:\n%s", err, string(combinedOutput))
		// store timestamp to filter otel docs with timestamp greater than this value
		timestampBeatReceiver := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

		require.EventuallyWithT(t, func(collect *assert.CollectT) {
			status, statusErr := beatReceiverFixture.ExecStatus(ctx)
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

		// 5. Assert monitoring logs and metrics are available on ES (for otel mode)
		for _, tc := range tests {
			require.Eventuallyf(t,
				func() bool {
					findCtx, findCancel := context.WithTimeout(ctx, 10*time.Second)
					defer findCancel()

					rawQuery := map[string]any{
						"query": map[string]any{
							"bool": map[string]any{
								"must":   tc.query,
								"filter": map[string]any{"range": map[string]any{"@timestamp": map[string]any{"gte": timestampBeatReceiver}}},
							},
						},
						"sort": []map[string]any{
							{"@timestamp": map[string]any{"order": "asc"}},
						},
					}

					index := tc.dsType + "-" + tc.dsDataset + "-" + tc.dsNamespace
					docs, err := estools.PerformQueryForRawQuery(findCtx, rawQuery, ".ds-"+index+"*", info.ESClient)
					require.NoError(t, err)
					if docs.Hits.Total.Value != 0 {
						key := tc.dsType + "-" + tc.dsDataset + "-" + tc.dsNamespace
						otelDocs[key] = docs
					}
					return docs.Hits.Total.Value > 0
				},
				4*time.Minute, 5*time.Second,
				"agent monitoring beats receivers no documents found for timestamp: %s, type: %s, dataset: %s, namespace: %s, query: %v", timestampBeatReceiver, tc.dsType, tc.dsDataset, tc.dsNamespace, tc.query)
		}

		// 6. Uninstall
		combinedOutput, err = beatReceiverFixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
		require.NoErrorf(t, err, "error uninstalling beat receiver agent monitoring, err: %s, combined output: %s", err, string(combinedOutput))

		// 7. Compare both documents are equivalent
		for _, tc := range tests[:3] {
			key := tc.dsType + "-" + tc.dsDataset + "-" + tc.dsNamespace
			agent := agentDocs[key].Hits.Hits[0].Source
			otel := otelDocs[key].Hits.Hits[0].Source
			ignoredFields := []string{
				// Expected to change between agentDocs and OtelDocs
				"@timestamp",
				"agent.ephemeral_id",
				// agent.id is different because it's the id of the underlying beat
				"agent.id",
				// agent.version is different because we force version 9.0.0 in CI
				"agent.version",
				"elastic_agent.id",
				"log.file.inode",
				"log.file.fingerprint",
				"log.file.path",
				"log.offset",
				"event.ingested",
			}
			switch tc.onlyCompareKeys {
			case true:
				AssertMapstrKeysEqual(t, agent, otel, append(ignoredFields, tc.ignoreFields...), "expected document keys to be equal")
			case false:
				AssertMapsEqual(t, agent, otel, ignoredFields, "expected documents to be equal")
			}
		}
	})
}

func assertCollectorComponentsHealthy(t *assert.CollectT, status *atesting.AgentStatusCollectorOutput) {
	assert.Equal(t, int(cproto.CollectorComponentStatus_StatusOK), status.Status, "component status should be ok")
	assert.Equal(t, "", status.Error, "component status should not have an error")
	for _, componentStatus := range status.ComponentStatusMap {
		assertCollectorComponentsHealthy(t, componentStatus)
	}
}
