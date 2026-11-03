// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/estools"
	aTesting "github.com/elastic/elastic-agent/pkg/testing"
	"github.com/elastic/elastic-agent/pkg/testing/define"
	"github.com/elastic/elastic-agent/pkg/testing/tools/testcontext"
	"github.com/elastic/elastic-agent/testing/integration"
)

// prometheusRemoteWriteExporterConfig scrapes host metrics and exports them
// with the prometheus_remote_write exporter to the Elasticsearch Prometheus
// remote write endpoint. The dataset and namespace are set through the URL
// path, so the samples land in metrics-generic.prometheus-{{.Namespace}}.
const prometheusRemoteWriteExporterConfig = `
receivers:
  host_metrics:
    collection_interval: 5s
    scrapers:
      cpu:
      memory:

exporters:
  debug:
    verbosity: basic

  prometheus_remote_write:
    endpoint: {{.ESEndpoint}}/_prometheus/metrics/generic/{{.Namespace}}/api/v1/write
    headers:
      Authorization: ApiKey {{.ESApiKey}}
    resource_to_telemetry_conversion:
      enabled: true
    # Do not queue, so that failures show up right away in the logs.
    sending_queue:
      enabled: false

service:
  pipelines:
    metrics:
      receivers: [host_metrics]
      exporters: [prometheus_remote_write, debug]
`

// TestOtelPrometheusRemoteWriteExporter verifies that the bundled
// prometheus_remote_write exporter can write to the Elasticsearch Prometheus
// remote write endpoint.
func TestOtelPrometheusRemoteWriteExporter(t *testing.T) {
	info := define.Require(t, define.Requirements{
		Group: integration.Default,
		Local: true,
		OS: []define.OS{
			{Type: define.Windows},
			{Type: define.Linux},
			{Type: define.Darwin},
		},
		Stack: &define.Stack{},
	})

	// Ensure everything is saved in case of test failure,
	// this folder is also collected on CI.
	tempDir := aTesting.TempDir(t, "..", "..", "..", "build")

	esHost, err := integration.GetESHost()
	require.NoError(t, err, "failed to get ES host")
	require.NotEmpty(t, esHost)

	esClient := info.ESClient
	require.NotNil(t, esClient)
	esApiKey := createESApiKey(t, esClient)

	cfg := prometheusRemoteWriteExporterConfig
	cfg = strings.ReplaceAll(cfg, "{{.ESEndpoint}}", esHost)
	cfg = strings.ReplaceAll(cfg, "{{.ESApiKey}}", esApiKey.Encoded)
	cfg = strings.ReplaceAll(cfg, "{{.Namespace}}", info.Namespace)

	cfgFilePath := filepath.Join(tempDir, "otel.yml")
	require.NoError(t, os.WriteFile(cfgFilePath, []byte(cfg), 0o600))

	fixture, err := define.NewFixtureFromLocalBuild(t, define.Version(), aTesting.WithAdditionalArgs([]string{"--config", cfgFilePath}))
	require.NoError(t, err)

	ctx, cancel := testcontext.WithDeadline(t, t.Context(), time.Now().Add(10*time.Minute))
	defer cancel()
	err = fixture.Prepare(ctx, fakeComponent)
	require.NoError(t, err)

	// remove elastic-agent.yml, otel should be independent
	require.NoError(t, os.Remove(filepath.Join(fixture.WorkDir(), "elastic-agent.yml")))

	// the exporter must be part of the binary and the configuration must be valid
	cmd, err := fixture.PrepareAgentCommand(ctx, []string{"otel", "validate", "--config", cfgFilePath})
	require.NoError(t, err)
	out, err := cmd.CombinedOutput()
	require.NoErrorf(t, err, "otel validate failed: %s", out)

	var fixtureWg sync.WaitGroup
	fixtureWg.Add(1)
	go func() {
		defer fixtureWg.Done()
		err = fixture.RunOtelWithClient(ctx)
	}()

	// The data stream is named after the dataset and namespace set in the endpoint URL.
	dataStream := "metrics-generic.prometheus-" + info.Namespace

	require.EventuallyWithT(
		t,
		func(c *assert.CollectT) {
			findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer findCancel()

			// The remote write endpoint stores every sample as a document with
			// the value under metrics.<name>. The exporter normalizes the
			// OTel metric system.cpu.time to system_cpu_time_seconds_total.
			query := map[string]any{
				"query": map[string]any{
					"exists": map[string]any{"field": "metrics.system_cpu_time_seconds_total"},
				},
			}
			docs, err := estools.PerformQueryForRawQuery(findCtx, query, dataStream, esClient)
			require.NoError(c, err)
			require.Positivef(c, docs.Hits.Total.Value, "expecting samples of system_cpu_time_seconds_total in data stream %s", dataStream)
		},
		3*time.Minute,
		5*time.Second,
		"did not find any samples written through the Prometheus remote write exporter")

	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded), "Retrieved unexpected error: %v", err)
}
