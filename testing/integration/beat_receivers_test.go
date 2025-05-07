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
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/utils"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
)

// TestClassicAndReceiverAgentMonitoring is a test to elastic-agent
// monitoring with classic beats as separate processes vs beats
// receivers in the same process
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
	// 1. create and install policy with just monitoring
	// 2. download the policy, add the API key
	// 3. install without enrolling in fleet
	// 4. make sure logs and metrics for agent monitoring are being received
	// 5. Uninstall

	// 5. restart with blank policy (stop collecting)
	// 6. configure with beats receiver policy
	// 7. restart with beats receiver policy
	// 8. make sure logs and metrics for agent monitoring are being received
	// 9. compare monitoring logs and metrics

	t.Run("verify elastic-agent monitoring functionality", func(t *testing.T) {
		ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
		defer cancel()

		type configOptions struct {
			InputPath              string
			ESEndpoint             string
			ESApiKey               string
			FilebeatSocketEndpoint string
			MetricbeatBeatEndpoint string
			MetricbeatHttpEndpoint string
			Namespace              string
		}

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

		// 3. Install without enrolling in fleet
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

		// 4. make sure logs and metrics for agent monitoring are being received
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
				5*time.Minute, 5*time.Second,
				"agent monitoring classic no documents found for timestamp: %s, type: %s, dataset: %s, namespace: %s, query: %v", timestamp, tc.dsType, tc.dsDataset, tc.dsNamespace, tc.query)
		}

		// 5. Uninstall
		combinedOutput, err := classicFixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
		require.NoErrorf(t, err, "error uninstalling classic agent monitoring, err: %s, combined output: %s", err, string(combinedOutput))

		// 6. Install without enroll and blank elastic-agent.yml, to get working directory
		beatReceiverFixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)
		err = beatReceiverFixture.Prepare(ctx)
		require.NoError(t, err)
		err = beatReceiverFixture.Configure(ctx, []byte{})
		require.NoError(t, err)
		combinedOutput, err = beatReceiverFixture.InstallWithoutEnroll(ctx, &installOpts)
		require.NoErrorf(t, err, "error install without enroll: %s\ncombinedoutput:\n%s", err, string(combinedOutput))
		require.Eventually(t, func() bool {
			err = beatReceiverFixture.IsHealthy(ctx)
			if err != nil {
				t.Logf("waiting for agent healthy: %s", err.Error())
				return false
			}
			return true
		}, 30*time.Second, 1*time.Second)

		configTemplateOTel := `
receivers:
  filebeatreceiver/filestream-monitoring:
    filebeat:
      inputs:
        - type: filestream
          enabled: true
          id: filestream-monitoring-agent
          paths:
            - '{{.InputPath}}/data/elastic-agent-*/logs/elastic-agent-*.ndjson'
            - '{{.InputPath}}/data/elastic-agent-*/logs/elastic-agent-watcher-*.ndjson'
          close:
            on_state_change:
              inactive: 5m
          parsers:
            - ndjson:
                add_error_key: true
                message_key: message
                overwrite_keys: true
                target: ""
          processors:
            - add_fields:
                fields:
                  dataset: elastic_agent
                  namespace: {{.Namespace}}
                  type: logs
                target: data_stream
            - add_fields:
                fields:
                  dataset: elastic_agent
                target: event
            - add_fields:
                fields:
                  id: 0ddca301-e7c0-4eac-8432-7dd05bc9cb06
                  snapshot: false
                  version: 8.19.0
                target: elastic_agent
            - add_fields:
                fields:
                  id: 0879f47d-df41-464d-8462-bc2b8fef45bf
                target: agent
            - drop_event:
                when:
                  regexp:
                    component.id: .*-monitoring$
            - drop_event:
                when:
                  regexp:
                    message: ^Non-zero metrics in the last
            - copy_fields:
                fields:
                  - from: data_stream.dataset
                    to: data_stream.dataset_original
            - drop_fields:
                fields:
                  - data_stream.dataset
            - copy_fields:
                fail_on_error: false
                fields:
                  - from: component.dataset
                    to: data_stream.dataset
                ignore_missing: true
            - copy_fields:
                fail_on_error: false
                fields:
                  - from: data_stream.dataset_original
                    to: data_stream.dataset
            - drop_fields:
                fields:
                  - data_stream.dataset_original
                  - event.dataset
            - copy_fields:
                fields:
                  - from: data_stream.dataset
                    to: event.dataset
            - drop_fields:
                fields:
                  - ecs.version
                ignore_missing: true
    output:
      otelconsumer:
    queue:
      mem:
        flush:
          timeout: 0s
    logging:
      level: info
      selectors:
        - '*'
    http.enabled: true
    http.host: '{{ .FilebeatSocketEndpoint }}'
  metricbeatreceiver/beat-monitoring:
    metricbeat:
      modules:
        - failure_threshold: 5
          hosts:
            - http+{{ .FilebeatSocketEndpoint }}
          metricsets:
            - stats
          module: beat
          enabled: true
          period: 60s
          processors:
            - add_fields:
                fields:
                  dataset: elastic_agent.filebeat
                  namespace: {{.Namespace}}
                  type: metrics
                target: data_stream
            - add_fields:
                fields:
                  dataset: elastic_agent.filebeat
                target: event
            - add_fields:
                fields:
                  id: f9787136-2d04-4999-a504-848c2e25d90e
                  process: filebeat
                  snapshot: false
                  version: 9.0.0
                target: elastic_agent
            - add_fields:
                fields:
                  id: f9787136-2d04-4999-a504-848c2e25d90e
                target: agent
            - add_fields:
                fields:
                  binary: filebeat
                  id: filestream-monitoring
                target: component
        - failure_threshold: 5
          hosts:
            - http+{{ .MetricbeatBeatEndpoint }}
          id: metrics-monitoring-metricbeat
          metricsets:
            - stats
          module: beat
          enabled: true
          period: 60s
          processors:
            - add_fields:
                fields:
                  dataset: elastic_agent.metricbeat
                  namespace: {{.Namespace}}
                  type: metrics
                target: data_stream
            - add_fields:
                fields:
                  dataset: elastic_agent.metricbeat
                target: event
            - add_fields:
                fields:
                  stream_id: metrics-monitoring-metricbeat
                target: '@metadata'
            - add_fields:
                fields:
                  id: f9787136-2d04-4999-a504-848c2e25d90e
                  process: metricbeat
                  snapshot: false
                  version: 9.0.0
                target: elastic_agent
            - add_fields:
                fields:
                  id: f9787136-2d04-4999-a504-848c2e25d90e
                target: agent
            - add_fields:
                fields:
                  binary: metricbeat
                  id: beat/metrics-monitoring
                target: component
    output:
      otelconsumer:
    queue:
      mem:
        flush:
          timeout: 0s
    logging:
      level: info
      selectors:
        - '*'
    http.enabled: true
    http.host: '{{ .MetricbeatBeatEndpoint }}'
  metricbeatreceiver/http-monitoring:
    metricbeat:
      modules:
        - failure_threshold: 5
          hosts:
            - http://localhost:6791
          id: metrics-monitoring-agent
          index: metrics-elastic_agent.elastic_agent-{{ .Namespace }}
          metricsets:
            - json
          module: http
          enabled: true
          namespace: agent
          path: /stats
          period: 60s
          processors:
            - add_fields:
                fields:
                  input_id: metrics-monitoring-agent
                target: '@metadata'
            - add_fields:
                fields:
                  dataset: elastic_agent.elastic_agent
                  namespace: {{.Namespace}}
                  type: metrics
                target: data_stream
            - add_fields:
                fields:
                  dataset: elastic_agent.elastic_agent
                target: event
            - add_fields:
                fields:
                  stream_id: metrics-monitoring-agent
                target: '@metadata'
            - add_fields:
                fields:
                  id: f9787136-2d04-4999-a504-848c2e25d90e
                  snapshot: false
                  version: 9.0.0
                target: elastic_agent
            - add_fields:
                fields:
                  id: f9787136-2d04-4999-a504-848c2e25d90e
                target: agent
            - copy_fields:
                fail_on_error: false
                fields:
                  - from: http.agent.beat.cpu
                    to: system.process.cpu
                  - from: http.agent.beat.memstats.memory_sys
                    to: system.process.memory.size
                  - from: http.agent.beat.handles
                    to: system.process.fd
                  - from: http.agent.beat.cgroup
                    to: system.process.cgroup
                  - from: http.agent.apm-server
                    to: apm-server
                  - from: http.filebeat_input
                    to: filebeat_input
                ignore_missing: true
            - drop_fields:
                fields:
                  - http
                ignore_missing: true
            - add_fields:
                fields:
                  binary: elastic-agent
                  id: elastic-agent
                target: component
        - failure_threshold: 5
          hosts:
            - http+{{ .FilebeatSocketEndpoint }}
          id: metrics-monitoring-filebeat-1
          index: metrics-elastic_agent.filebeat_input-{{ .Namespace }}
          json:
            is_array: true
          metricsets:
            - json
          module: http
          enabled: true
          namespace: filebeat_input
          path: /inputs/
          period: 60s
          processors:
            - add_fields:
                fields:
                  input_id: metrics-monitoring-agent
                target: '@metadata'
            - add_fields:
                fields:
                  dataset: elastic_agent.filebeat_input
                  namespace: {{.Namespace}}
                  type: metrics
                target: data_stream
            - add_fields:
                fields:
                  dataset: elastic_agent.filebeat_input
                target: event
            - add_fields:
                fields:
                  stream_id: metrics-monitoring-filebeat-1
                target: '@metadata'
            - add_fields:
                fields:
                  id: f9787136-2d04-4999-a504-848c2e25d90e
                  snapshot: false
                  version: 9.0.0
                target: elastic_agent
            - add_fields:
                fields:
                  id: f9787136-2d04-4999-a504-848c2e25d90e
                target: agent
            - add_fields:
                fields:
                  id: f9787136-2d04-4999-a504-848c2e25d90e
                  process: filebeat
                  snapshot: false
                  version: 9.0.0
                target: elastic_agent
            - copy_fields:
                fail_on_error: false
                fields:
                  - from: http.agent.beat.cpu
                    to: system.process.cpu
                  - from: http.agent.beat.memstats.memory_sys
                    to: system.process.memory.size
                  - from: http.agent.beat.handles
                    to: system.process.fd
                  - from: http.agent.beat.cgroup
                    to: system.process.cgroup
                  - from: http.agent.apm-server
                    to: apm-server
                  - from: http.filebeat_input
                    to: filebeat_input
                ignore_missing: true
            - drop_fields:
                fields:
                  - http
                ignore_missing: true
            - add_fields:
                fields:
                  binary: filebeat
                  id: filestream-monitoring
                target: component
    output:
      otelconsumer:
    queue:
      mem:
        flush:
          timeout: 0s
    logging:
      level: debug
      selectors:
        - '*'
    http.enabled: true
    http.host: '{{ .MetricbeatHttpEndpoint }}'
exporters:
  debug:
    use_internal_logger: false
    verbosity: detailed
  elasticsearch/log:
    endpoints:
      - {{.ESEndpoint}}
    compression: none
    api_key: {{.ESApiKey}}
    logs_dynamic_index:
      enabled: true
    batcher:
      enabled: true
      flush_timeout: 0.5s
    mapping:
      mode: bodymap
service:
  telemetry:
    logs:
      level: "DEBUG"
  pipelines:
    logs:
      receivers:
        - filebeatreceiver/filestream-monitoring
        - metricbeatreceiver/beat-monitoring
        - metricbeatreceiver/http-monitoring
      exporters:
        - elasticsearch/log
        - debug
agent:
  monitoring:
    enabled: true
    logs: false
    metrics: false
  logging:
    level: debug
`

		filebeatSocketEndpoint := utils.SocketURLWithFallback(uuid.Must(uuid.NewV4()).String(), paths.TempDir())
		metricbeatBeatEndpoint := utils.SocketURLWithFallback(uuid.Must(uuid.NewV4()).String(), paths.TempDir())
		metricbeatHttpEndpoint := utils.SocketURLWithFallback(uuid.Must(uuid.NewV4()).String(), paths.TempDir())

		var configBuffer bytes.Buffer
		template.Must(template.New("config").Parse(configTemplateOTel)).Execute(&configBuffer,
			configOptions{
				InputPath:              beatReceiverFixture.WorkDir(),
				ESEndpoint:             esEndpoint,
				ESApiKey:               apiKeyResponse.Encoded,
				FilebeatSocketEndpoint: filebeatSocketEndpoint,
				MetricbeatBeatEndpoint: metricbeatBeatEndpoint,
				MetricbeatHttpEndpoint: metricbeatHttpEndpoint,
				Namespace:              info.Namespace,
			})
		configOTelContents := configBuffer.Bytes()
		err = beatReceiverFixture.Configure(ctx, configOTelContents)
		require.NoError(t, err)

		// 8. restart with beats receiver policy
		combinedOutput, err = beatReceiverFixture.Exec(ctx, []string{"restart"})
		require.NoErrorf(t, err, "error restarting agent: %s\ncombinedoutput:\n%s", err, string(combinedOutput))

		// 9. make sure logs and metrics for agent monitoring are being received
		timestampBeatReceiver := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
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
				5*time.Minute, 5*time.Second,
				"agent monitoring beats receivers no documents found for timestamp: %s, type: %s, dataset: %s, namespace: %s, query: %v", timestampBeatReceiver, tc.dsType, tc.dsDataset, tc.dsNamespace, tc.query)
		}

		// 10. Uninstall
		combinedOutput, err = beatReceiverFixture.Uninstall(ctx, &atesting.UninstallOpts{Force: true})
		require.NoErrorf(t, err, "error uninstalling beat receiver agent monitoring, err: %s, combined output: %s", err, string(combinedOutput))

		// 11. Compare classic vs beat receiver events
		for _, tc := range tests[:3] {
			key := tc.dsType + "-" + tc.dsDataset + "-" + tc.dsNamespace
			agent := agentDocs[key].Hits.Hits[0].Source
			otel := otelDocs[key].Hits.Hits[0].Source
			ignoredFields := []string{
				// Expected to change between agentDocs and OtelDocs
				"@timestamp",
				"agent.ephemeral_id",
				"agent.id",
				"agent.version",
				"data_stream.namespace",
				"log.file.inode",
				"log.file.fingerprint",
				"log.file.path",
				"log.offset",

				// needs investigation
				"event.agent_id_status",
				"event.ingested",

				// elastic_agent * fields are hardcoded in processor list for now which is why they differ
				"elastic_agent.id",
				"elastic_agent.snapshot",
				"elastic_agent.version",
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
