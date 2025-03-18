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
	"net/http"
	"runtime"
	"testing"
	"text/template"
	"time"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent-libs/testing/estools"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	atesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/pkg/utils"
	"gopkg.in/yaml.v2"

	"github.com/gofrs/uuid/v5"
	"github.com/stretchr/testify/require"
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
		Develop:        true,
	}

	// Flow
	// 1. Create and install policy with just monitoring
	// 2. Download the policy, add the API key
	// 3. Install without enrolling in fleet
	// 4. Make sure logs and metrics for agent monitoring are being received
	t.Run("verify elastic-agent monitoring functionality", func(t *testing.T) {
		ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
		defer cancel()

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
		policyResponse, err := info.KibanaClient.CreatePolicy(ctx, createPolicyReq)
		require.NoError(t, err, "error creating policy")

		// 2. Download the policy, add the API key
		downloadURL := fmt.Sprintf("/api/fleet/agent_policies/%s/download", policyResponse.ID)
		resp, err := info.KibanaClient.Connection.SendWithContext(ctx, http.MethodGet, downloadURL, nil, nil, nil)
		require.NoError(t, err, "error downloading policy")
		policy, err := io.ReadAll(resp.Body)
		require.NoError(t, err, "error reading policy response")
		defer resp.Body.Close()

		apiKeyResponse, err := createESApiKey(info.ESClient)
		require.NoError(t, err, "failed to get api key")
		require.True(t, len(apiKeyResponse.Encoded) > 1, "api key is invalid %q", apiKeyResponse)
		apiKey, err := base64.StdEncoding.DecodeString(apiKeyResponse.Encoded)
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
			Agent             map[string]any           `yaml:"agent"`
			Inputs            []map[string]any         `yaml:"inputs"`
			Signed            map[string]any           `yaml:"signed"`
			SecretReferences  []map[string]any         `yaml:"secret_references"`
			Namespaces        []map[string]any         `yaml:"namespaces"`
		}

		y := PolicyStruct{}
		err = yaml.Unmarshal(policy, &y)
		require.NoError(t, err, "error unmarshalling policy")
		d, prs := y.Outputs["default"]
		require.True(t, prs, "default must be in outputs")
		d.ApiKey = string(apiKey)
		y.Outputs["default"] = d
		policyBytes, err := yaml.Marshal(y)
		require.NoErrorf(t, err, "error marshalling policy, struct was %v", y)
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("policy was %s", string(policyBytes))
			}
		})

		// 3. Install without enrolling in fleet
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		err = fixture.Prepare(ctx)
		require.NoError(t, err, "error preparing fixture")

		err = fixture.Configure(ctx, policyBytes)
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
					findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
					defer findCancel()
					mustClauses := []map[string]any{
						{"match": map[string]any{"data_stream.type": tc.dsType}},
						{"match": map[string]any{"data_stream.dataset": tc.dsDataset}},
						{"match": map[string]any{"data_stream.namespace": tc.dsNamespace}},
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

		type configOptions struct {
			InputPath      string
			ESEndpoint     string
			ESApiKey       string
			SocketEndpoint string
			Namespace      string
		}
		esEndpoint, err := getESHost()
		require.NoError(t, err, "error getting elasticsearch endpoint")
		esApiKey, err := createESApiKey(info.ESClient)
		require.NoError(t, err, "error creating API key")
		require.NotEmptyf(t, esApiKey.Encoded, "api key is invalid %q", esApiKey)

		// Start monitoring in otel mode
		fixture, err := define.NewFixtureFromLocalBuild(t, define.Version())
		require.NoError(t, err)

		ctx, cancel := testcontext.WithDeadline(t, context.Background(), time.Now().Add(5*time.Minute))
		defer cancel()

		err = fixture.Prepare(ctx)
		require.NoError(t, err)

		// installs elastic-agent with empty elastic-agent.yml to get its working dir first
		err = fixture.Configure(ctx, []byte{})
		require.NoError(t, err)

		output, err := fixture.InstallWithoutEnroll(ctx, &installOpts)
		require.NoErrorf(t, err, "error install withouth enroll: %s\ncombinedoutput:\n%s", err, string(output))

		// Ensure elastic-agent is healthy, otherwise we cannot perform retstart operation
		require.Eventually(t, func() bool {
			err = fixture.IsHealthy(ctx)
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
            -  {{.InputPath}}/data/elastic-agent-*/logs/elastic-agent-*.ndjson 
            -  {{.InputPath}}/data/elastic-agent-*/logs/elastic-agent-watcher-*.ndjson
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
    http.host: {{ .SocketEndpoint }}
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
      flush_timeout: 0s
    mapping:
      mode: bodymap	  
service:
  pipelines:
    logs:
      receivers:
        - filebeatreceiver/filestream-monitoring
      exporters:
        - elasticsearch/log  
`
		socketEndpoint := utils.SocketURLWithFallback(uuid.Must(uuid.NewV4()).String(), paths.TempDir())

		// configure elastic-agent.yml with new config
		var configBuffer bytes.Buffer
		template.Must(template.New("config").Parse(configTemplateOTel)).Execute(&configBuffer,
			configOptions{
				InputPath:      fixture.WorkDir(),
				ESEndpoint:     esEndpoint,
				ESApiKey:       esApiKey.Encoded,
				SocketEndpoint: socketEndpoint,
				Namespace:      info.Namespace,
			})
		configOTelContents := configBuffer.Bytes()
		t.Cleanup(func() {
			if t.Failed() {
				t.Logf("Contents of agent config file:\n%s\n", string(configOTelContents))
			}
		})
		err = fixture.Configure(ctx, configOTelContents)
		require.NoError(t, err)

		// Get the timestamp before restarting. Required to separate logs from agent and otel
		timestamp := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")

		fmt.Println(time.Now())
		// Restart elastic-agent
		output, err = fixture.Exec(ctx, []string{"restart"})
		require.NoErrorf(t, err, "error restarting agent: %s\ncombinedoutput:\n%s", err, string(output))

		require.Eventually(t, func() bool {
			err = fixture.IsHealthy(ctx)
			if err != nil {
				t.Logf("waiting for agent healthy: %s", err.Error())
				return false
			}
			return true
		}, 30*time.Second, 1*time.Second)

		// run this only for logs for now
		tc := tests[0]
		require.Eventuallyf(t,
			func() bool {
				findCtx, findCancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer findCancel()
				mustClauses := []map[string]any{
					{"match": map[string]any{"message": tc.message}},
					{"range": map[string]interface{}{
						"@timestamp": map[string]string{
							"gte": timestamp, // Use captured timestamp
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

		AssertMapsEqual(t, agent, otel, ignoredFields, "expected documents to be equal")
	})

}
