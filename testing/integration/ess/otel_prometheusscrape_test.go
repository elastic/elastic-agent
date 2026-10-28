// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build integration

package ess

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	"github.com/elastic/elastic-transport-go/v8/elastictransport"
)

const prometheusScrapeJobName = "edot_scrape_it"

// prometheusScrapePayload is served by the test as the scrape target. It
// exposes a counter, a gauge, a classic histogram and a summary in the
// Prometheus text format.
const prometheusScrapePayload = `# HELP edot_it_requests_total Total requests.
# TYPE edot_it_requests_total counter
edot_it_requests_total{method="get"} 42
# HELP edot_it_temperature_celsius Current temperature.
# TYPE edot_it_temperature_celsius gauge
edot_it_temperature_celsius{room="lab"} 21.5
# HELP edot_it_latency_seconds Request latency.
# TYPE edot_it_latency_seconds histogram
edot_it_latency_seconds_bucket{le="0.1"} 3
edot_it_latency_seconds_bucket{le="0.5"} 7
edot_it_latency_seconds_bucket{le="+Inf"} 10
edot_it_latency_seconds_sum 2.5
edot_it_latency_seconds_count 10
# HELP edot_it_duration_seconds Operation duration.
# TYPE edot_it_duration_seconds summary
edot_it_duration_seconds{quantile="0.5"} 0.2
edot_it_duration_seconds{quantile="0.99"} 0.9
edot_it_duration_seconds_sum 12.5
edot_it_duration_seconds_count 50
`

// prometheusScrapeReceiverConfig scrapes the test endpoint with the
// prometheusscrape receiver and exports the samples as is to the
// Elasticsearch Prometheus remote write endpoint. The exporter settings are
// the ones required to keep the Prometheus schema intact.
const prometheusScrapeReceiverConfig = `
receivers:
  prometheusscrape:
    config:
      scrape_configs:
        - job_name: {{.Job}}
          scrape_interval: 5s
          static_configs:
            - targets: ["{{.Target}}"]

exporters:
  debug:
    verbosity: basic

  prometheus_remote_write:
    endpoint: {{.ESEndpoint}}/_prometheus/metrics/generic/{{.Namespace}}/api/v1/write
    protobuf_message: prometheus.WriteRequest
    headers:
      Authorization: ApiKey {{.ESApiKey}}
    translation_strategy: UnderscoreEscapingWithoutSuffixes
    disable_scope_info: true
    target_info:
      enabled: false
    send_metadata: false
    # Do not queue, so that failures show up right away in the logs.
    sending_queue:
      enabled: false

service:
  pipelines:
    metrics:
      receivers: [prometheusscrape]
      exporters: [prometheus_remote_write, debug]
`

// TestOtelPrometheusScrapeReceiver verifies that data scraped by the bundled
// prometheusscrape receiver and written with the prometheus_remote_write
// exporter reaches the Elasticsearch Prometheus remote write endpoint with the
// Prometheus schema preserved.
func TestOtelPrometheusScrapeReceiver(t *testing.T) {
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

	// The scrape target served by the test.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		_, _ = fmt.Fprint(w, prometheusScrapePayload)
	}))
	defer target.Close()
	targetAddr := strings.TrimPrefix(target.URL, "http://")

	cfg := prometheusScrapeReceiverConfig
	cfg = strings.ReplaceAll(cfg, "{{.ESEndpoint}}", esHost)
	cfg = strings.ReplaceAll(cfg, "{{.ESApiKey}}", esApiKey.Encoded)
	cfg = strings.ReplaceAll(cfg, "{{.Namespace}}", info.Namespace)
	cfg = strings.ReplaceAll(cfg, "{{.Job}}", prometheusScrapeJobName)
	cfg = strings.ReplaceAll(cfg, "{{.Target}}", targetAddr)

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

	// the receiver must be part of the binary and the configuration must be valid
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

	count := func(c *assert.CollectT, query map[string]any) int64 {
		findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer findCancel()
		docs, err := estools.PerformQueryForRawQuery(findCtx, map[string]any{"query": query}, dataStream, esClient)
		require.NoError(c, err)
		return int64(docs.Hits.Total.Value)
	}
	exists := func(field string) map[string]any {
		return map[string]any{"exists": map[string]any{"field": field}}
	}
	term := func(field, value string) map[string]any {
		return map[string]any{"term": map[string]any{field: value}}
	}
	all := func(clauses ...map[string]any) map[string]any {
		return map[string]any{"bool": map[string]any{"filter": clauses}}
	}

	// Every series is stored under its exact scraped name, with no suffix added
	// or removed by the translation.
	scraped := []string{
		"edot_it_requests_total",
		"edot_it_temperature_celsius",
		"edot_it_latency_seconds_bucket",
		"edot_it_latency_seconds_sum",
		"edot_it_latency_seconds_count",
		"edot_it_duration_seconds",
		"edot_it_duration_seconds_sum",
		"edot_it_duration_seconds_count",
	}
	// Names that would show up if the exporter or the receiver translated the data.
	mangled := []string{
		"edot_it_requests_total_total",
		"edot_it_latency_seconds_bucket_total",
		"edot_it_latency_seconds_sum_total",
		"edot_it_latency_seconds_count_total",
		"edot_it_duration_seconds_sum_total",
		"edot_it_duration_seconds_count_total",
		"target_info",
	}

	require.EventuallyWithT(
		t,
		func(c *assert.CollectT) {
			for _, name := range scraped {
				assert.Positivef(c, count(c, exists("metrics."+name)), "expecting samples of %s in data stream %s", name, dataStream)
			}

			// job and instance are datapoint labels, as in Prometheus.
			assert.Positive(c, count(c, all(exists("metrics.edot_it_requests_total"), term("labels.job", prometheusScrapeJobName), term("labels.instance", targetAddr))),
				"expecting job and instance labels on edot_it_requests_total")
			// le and quantile are kept as labels.
			assert.Positive(c, count(c, all(exists("metrics.edot_it_latency_seconds_bucket"), term("labels.le", "0.5"))),
				"expecting the le label on histogram buckets")
			assert.Positive(c, count(c, all(exists("metrics.edot_it_duration_seconds"), term("labels.quantile", "0.99"))),
				"expecting the quantile label on summary series")
		},
		3*time.Minute,
		5*time.Second,
		"did not find the scraped samples written through the Prometheus remote write exporter")

	// Negative checks, run once the expected data is there so that an empty
	// data stream cannot make them pass.
	for _, name := range mangled {
		assert.Zerof(t, countOnce(t, esClient, dataStream, exists("metrics."+name)), "unexpected series %s", name)
	}
	assert.Zero(t, countOnce(t, esClient, dataStream, exists("labels.otel_scope_name")), "unexpected otel_scope_name label")

	cancel()
	fixtureWg.Wait()
	require.True(t, err == nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded), "Retrieved unexpected error: %v", err)
}

// countOnce returns the number of documents of the data stream matching the query.
func countOnce(t *testing.T, esClient elastictransport.Interface, dataStream string, query map[string]any) int64 {
	t.Helper()
	findCtx, findCancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer findCancel()
	docs, err := estools.PerformQueryForRawQuery(findCtx, map[string]any{"query": query}, dataStream, esClient)
	require.NoError(t, err)
	return int64(docs.Hits.Total.Value)
}
