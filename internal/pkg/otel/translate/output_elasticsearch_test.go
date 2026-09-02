// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"bytes"
	_ "embed"
	"fmt"
	"strings"
	"testing"
	"text/template"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/confmap"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
)

func TestGetRetryConfig(t *testing.T) {
	escfg := defaultOptions
	expectedRequestStatuses := defaultRetryOnStatus()
	expectedDocumentStatuses := defaultRetryOnDocumentStatus

	retryConfig := getRetryConfig(escfg)

	assert.Equal(t,
		expectedRequestStatuses,
		retryConfig["retry_on_status"],
		"the defaults for 'retry_on_status' must be preserved",
	)
	assert.Equal(
		t,
		expectedDocumentStatuses,
		retryConfig["retry_on_document_status"],
		"the defaults for 'retry_on_document_status' must be preserved",
	)
}

func TestToOtelConfig(t *testing.T) {
	logger := logptest.NewTestingLogger(t, "")

	t.Run("basic config translation", func(t *testing.T) {
		beatCfg := `
hosts:
  - localhost:9200
  - localhost:9300
protocol: http
path: /foo/bar
username: elastic
password: changeme
index: "some-index"
backoff:
  init: 42s
  max: 420s
workers: 30
headers:
  X-Header-1: foo
  X-Bar-Header: bar`

		OTelCfg := `
endpoints:
  - http://localhost:9200/foo/bar
  - http://localhost:9300/foo/bar
logs_index: some-index
logs_dynamic_pipeline:
  enabled: true
max_conns_per_host: 60
password: changeme
retry:
  enabled: true
  initial_interval: 42s
  max_interval: 7m0s
  max_retries: 3
  retry_on_status:
__REQUEST_RETRY_STATUSES__
  retry_on_document_status:
  - 429
  - 500
  - 501
  - 502
  - 503
  - 504
  - 505
  - 506
  - 507
  - 508
  - 510
  - 511
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 120
  queue_size: 3200
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
user: elastic
headers:
  X-Header-1: foo
  X-Bar-Header: bar
bulk_response_filter_path: errors,items.*.error,items.*.status,items.*.failure_store
compression: gzip
compression_params:
  level: 1
include_source_on_error: true
logs_dynamic_id:
  enabled: true
logs_dynamic_pipeline:
  enabled: true
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, _, err := ESToOTelConfig(cfg, "", logger)
		require.NoError(t, err, "error translating elasticsearch output to ES exporter config")
		expOutput := newFromYamlString(t, OTelCfg)
		compareAndAssert(t, expOutput, confmap.NewFromStringMap(got))
	})

	t.Run("test api key is encoded before mapping to es-exporter", func(t *testing.T) {
		beatCfg := `
hosts:
  - localhost:9200
index: "some-index"
api_key: "TiNAGG4BaaMdaH1tRfuU:KnR6yE41RrSowb0kQ0HWoA"
`

		OTelCfg := `
endpoints:
  - http://localhost:9200
logs_index: some-index
logs_dynamic_pipeline:
  enabled: true
retry:
  enabled: true
  initial_interval: 1s
  max_interval: 1m0s
  max_retries: 3
  retry_on_status:
__REQUEST_RETRY_STATUSES__
  retry_on_document_status:
  - 429
  - 500
  - 501
  - 502
  - 503
  - 504
  - 505
  - 506
  - 507
  - 508
  - 510
  - 511
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 2
  queue_size: 3200
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
max_conns_per_host: 1
api_key: VGlOQUdHNEJhYU1kYUgxdFJmdVU6S25SNnlFNDFSclNvd2Iwa1EwSFdvQQ==
bulk_response_filter_path: errors,items.*.error,items.*.status,items.*.failure_store
compression: gzip
compression_params:
  level: 1
include_source_on_error: true
logs_dynamic_id:
  enabled: true
logs_dynamic_pipeline:
  enabled: true
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, _, err := ESToOTelConfig(cfg, "", logger)
		require.NoError(t, err, "error translating elasticsearch output to ES exporter config ")
		expOutput := newFromYamlString(t, OTelCfg)
		compareAndAssert(t, expOutput, confmap.NewFromStringMap(got))
	})

	t.Run("test hosts can be a string and parameters is respected", func(t *testing.T) {
		beatCfg := `
hosts: "localhost:9200"
index: "some-index"
api_key: "TiNAGG4BaaMdaH1tRfuU:KnR6yE41RrSowb0kQ0HWoA"
parameters:
  somekey : somevalue
`

		OTelCfg := `
endpoints:
  - http://localhost:9200?somekey=somevalue
logs_index: some-index
logs_dynamic_pipeline:
  enabled: true
retry:
  enabled: true
  initial_interval: 1s
  max_interval: 1m0s
  max_retries: 3
  retry_on_status:
__REQUEST_RETRY_STATUSES__
  retry_on_document_status:
  - 429
  - 500
  - 501
  - 502
  - 503
  - 504
  - 505
  - 506
  - 507
  - 508
  - 510
  - 511
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 2
  queue_size: 3200
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
max_conns_per_host: 1
api_key: VGlOQUdHNEJhYU1kYUgxdFJmdVU6S25SNnlFNDFSclNvd2Iwa1EwSFdvQQ==
bulk_response_filter_path: errors,items.*.error,items.*.status,items.*.failure_store
compression: gzip
compression_params:
  level: 1
include_source_on_error: true
logs_dynamic_id:
  enabled: true
logs_dynamic_pipeline:
  enabled: true
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, _, err := ESToOTelConfig(cfg, "", logger)
		require.NoError(t, err, "error translating elasticsearch output to ES exporter config ")
		expOutput := newFromYamlString(t, OTelCfg)
		compareAndAssert(t, expOutput, confmap.NewFromStringMap(got))
	})

	t.Run("ssl setting of type []string can be a string", func(t *testing.T) {
		beatCfg := `
hosts: "localhost:9200"
index: "some-index"
api_key: "TiNAGG4BaaMdaH1tRfuU:KnR6yE41RrSowb0kQ0HWoA"
ssl.certificate_authorities: "/not/a/real/path/ca.pem"
ssl.supported_protocols: "TLSv1.3"
ssl.cipher_suites: "ECDHE-ECDSA-AES-256-CBC-SHA"
ssl.curve_types: "P-256"
`

		OTelCfg := `
endpoints:
  - http://localhost:9200
logs_index: some-index
logs_dynamic_pipeline:
  enabled: true
retry:
  enabled: true
  initial_interval: 1s
  max_interval: 1m0s
  max_retries: 3
  retry_on_status:
__REQUEST_RETRY_STATUSES__
  retry_on_document_status:
  - 429
  - 500
  - 501
  - 502
  - 503
  - 504
  - 505
  - 506
  - 507
  - 508
  - 510
  - 511
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 2
  queue_size: 3200
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
max_conns_per_host: 1
api_key: VGlOQUdHNEJhYU1kYUgxdFJmdVU6S25SNnlFNDFSclNvd2Iwa1EwSFdvQQ==
bulk_response_filter_path: errors,items.*.error,items.*.status,items.*.failure_store
compression: gzip
compression_params:
  level: 1
include_source_on_error: true
logs_dynamic_id:
  enabled: true
logs_dynamic_pipeline:
  enabled: true
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, _, err := ESToOTelConfig(cfg, "", logger)
		require.NoError(t, err, "error translating elasticsearch output to ES exporter config ")
		expOutput := newFromYamlString(t, OTelCfg)
		compareAndAssert(t, expOutput, confmap.NewFromStringMap(got))
	})

	// when preset is configured, we only test worker, bulk_max_size
	// idle_connection_timeout should be correctly configured on beatsauthextension
	// es-exporter sets compression level to 1 by default
	t.Run("check preset config translation", func(t *testing.T) {
		commonBeatCfg := `
hosts:
  - localhost:9200
index: "some-index"
username: elastic
password: changeme
preset: %s
`

		commonOTelCfg := `
logs_dynamic_pipeline:
  enabled: true
endpoints:
  - http://localhost:9200
retry:
  enabled: true
  initial_interval: 1s
  max_interval: 1m0s
  max_retries: 3
  retry_on_status:
__REQUEST_RETRY_STATUSES__
  retry_on_document_status:
  - 429
  - 500
  - 501
  - 502
  - 503
  - 504
  - 505
  - 506
  - 507
  - 508
  - 510
  - 511
logs_index: some-index
password: changeme
user: elastic
bulk_response_filter_path: errors,items.*.error,items.*.status,items.*.failure_store
compression: gzip
compression_params:
  level: 1
include_source_on_error: true
logs_dynamic_id:
  enabled: true
logs_dynamic_pipeline:
  enabled: true
`

		tests := []struct {
			presetName string
			output     string
		}{
			{
				presetName: "balanced",
				output: commonOTelCfg + `
max_conns_per_host: 1
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 2
  queue_size: 6400
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
 `,
			},
			{
				presetName: "throughput",
				output: commonOTelCfg + `
max_conns_per_host: 4
sending_queue:
  batch:
    flush_timeout: 5s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 8
  queue_size: 25600
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
 `,
			},
			{
				presetName: "scale",
				output: `
logs_dynamic_pipeline:
  enabled: true
endpoints:
  - http://localhost:9200
retry:
  enabled: true
  initial_interval: 5s
  max_interval: 5m0s
  max_retries: 3
  retry_on_status:
__REQUEST_RETRY_STATUSES__
  retry_on_document_status:
  - 429
  - 500
  - 501
  - 502
  - 503
  - 504
  - 505
  - 506
  - 507
  - 508
  - 510
  - 511
logs_index: some-index
password: changeme
user: elastic
max_conns_per_host: 1
sending_queue:
  batch:
    flush_timeout: 20s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 2
  queue_size: 6400
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
bulk_response_filter_path: errors,items.*.error,items.*.status,items.*.failure_store
compression: gzip
compression_params:
  level: 1
include_source_on_error: true
logs_dynamic_id:
  enabled: true
logs_dynamic_pipeline:
  enabled: true
 `,
			},
			{
				presetName: "latency",
				output: commonOTelCfg + `
max_conns_per_host: 1
sending_queue:
  batch:
    flush_timeout: 1s
    max_size: 50
    min_size: 50
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 2
  queue_size: 4100
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
 `,
			},
			{
				presetName: "custom",
				output: commonOTelCfg + `
max_conns_per_host: 1
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 2
  queue_size: 3200
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
 `,
			},
		}

		for _, test := range tests {
			t.Run("config translation w/"+test.presetName, func(t *testing.T) {
				cfg := config.MustNewConfigFrom(fmt.Sprintf(commonBeatCfg, test.presetName))
				got, _, err := ESToOTelConfig(cfg, "", logger)
				require.NoError(t, err, "error translating elasticsearch output to OTel ES exporter type")
				expOutput := newFromYamlString(t, test.output)
				compareAndAssert(t, expOutput, confmap.NewFromStringMap(got))
			})
		}
	})

	t.Run("test max_retries positive", func(t *testing.T) {
		beatCfg := `
hosts:
  - localhost:9200
  - localhost:9300
protocol: http
max_retries: 5
path: /foo/bar
username: elastic
password: changeme
index: "some-index"
backoff:
  init: 42s
  max: 420s
workers: 30
headers:
  X-Header-1: foo
  X-Bar-Header: bar`

		OTelCfg := `
endpoints:
  - http://localhost:9200/foo/bar
  - http://localhost:9300/foo/bar
logs_index: some-index
logs_dynamic_pipeline:
  enabled: true
max_conns_per_host: 60
password: changeme
retry:
  enabled: true
  initial_interval: 42s
  max_interval: 7m0s
  max_retries: 5
  retry_on_status:
__REQUEST_RETRY_STATUSES__
  retry_on_document_status:
  - 429
  - 500
  - 501
  - 502
  - 503
  - 504
  - 505
  - 506
  - 507
  - 508
  - 510
  - 511
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 120
  queue_size: 3200
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
user: elastic
headers:
  X-Header-1: foo
  X-Bar-Header: bar
bulk_response_filter_path: errors,items.*.error,items.*.status,items.*.failure_store
compression: gzip
compression_params:
  level: 1
include_source_on_error: true
logs_dynamic_id:
  enabled: true
logs_dynamic_pipeline:
  enabled: true
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, _, err := ESToOTelConfig(cfg, "", logger)
		require.NoError(t, err, "error translating elasticsearch output to ES exporter config")
		expOutput := newFromYamlString(t, OTelCfg)
		compareAndAssert(t, expOutput, confmap.NewFromStringMap(got))
	})

	t.Run("test max_retries zero", func(t *testing.T) {
		beatCfg := `
hosts:
  - localhost:9200
  - localhost:9300
protocol: http
max_retries: 0
path: /foo/bar
username: elastic
password: changeme
index: "some-index"
backoff:
  init: 42s
  max: 420s
workers: 30
headers:
  X-Header-1: foo
  X-Bar-Header: bar`

		OTelCfg := `
endpoints:
  - http://localhost:9200/foo/bar
  - http://localhost:9300/foo/bar
logs_index: some-index
logs_dynamic_pipeline:
  enabled: true
max_conns_per_host: 60
password: changeme
retry:
  enabled: false
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 120
  queue_size: 3200
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
user: elastic
headers:
  X-Header-1: foo
  X-Bar-Header: bar
bulk_response_filter_path: errors,items.*.error,items.*.status,items.*.failure_store
compression: gzip
compression_params:
  level: 1
include_source_on_error: true
logs_dynamic_id:
  enabled: true
logs_dynamic_pipeline:
  enabled: true
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, _, err := ESToOTelConfig(cfg, "", logger)
		require.NoError(t, err, "error translating elasticsearch output to ES exporter config")
		expOutput := newFromYamlString(t, OTelCfg)
		compareAndAssert(t, expOutput, confmap.NewFromStringMap(got))
	})
}

func TestCompressionConfig(t *testing.T) {
	compressionConfig := `
hosts:
  - localhost:9200
  - localhost:9300
protocol: http
path: /foo/bar
username: elastic
password: changeme
index: "some-index"
compression_level: %d`

	otelConfig := `
logs_dynamic_pipeline:
  enabled: true
endpoints:
  - http://localhost:9200/foo/bar
  - http://localhost:9300/foo/bar
logs_index: some-index
password: changeme
retry:
  enabled: true
  initial_interval: 1s
  max_interval: 1m0s
  max_retries: 3
  retry_on_status:
__REQUEST_RETRY_STATUSES__
  retry_on_document_status:
  - 429
  - 500
  - 501
  - 502
  - 503
  - 504
  - 505
  - 506
  - 507
  - 508
  - 510
  - 511
max_conns_per_host: 2
user: elastic
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 1600
    min_size: 1600
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 4
  queue_size: 3200
  wait_for_result: true
suppress_conflict_errors: true
timeout: 1m30s
bulk_response_filter_path: errors,items.*.error,items.*.status,items.*.failure_store
{{ if gt . 0 }}
compression: gzip
compression_params:
  level: {{ . }}
{{ else }}
compression: none
{{ end }}
include_source_on_error: true
logs_dynamic_id:
  enabled: true
logs_dynamic_pipeline:
  enabled: true
`

	for level := range 9 {
		t.Run(fmt.Sprintf("compression-level-%d", level), func(t *testing.T) {
			cfg := config.MustNewConfigFrom(fmt.Sprintf(compressionConfig, level))
			got, _, err := ESToOTelConfig(cfg, "", logp.NewNopLogger())
			require.NoError(t, err, "error translating elasticsearch output to ES exporter config")
			var otelBuffer bytes.Buffer
			require.NoError(t, template.Must(template.New("config").Parse(otelConfig)).Execute(&otelBuffer, level))
			expOutput := newFromYamlString(t, otelBuffer.String())
			compareAndAssert(t, expOutput, confmap.NewFromStringMap(got))
		})
	}
}

func TestToOTelConfig_CheckUnsupported(t *testing.T) {
	logger := logptest.NewTestingLogger(t, "")

	cases := []struct {
		name            string
		cfg             map[string]any
		wantErrContains string
	}{
		{"indices", map[string]any{"indices": []any{"i"}}, "indices is currently not supported"},
		{"allow_older_versions_false", map[string]any{"allow_older_versions": false}, "allow_older_versions:false is currently not supported"},
		{"loadbalance_false", map[string]any{"loadbalance": false}, "loadbalance:false is currently not supported"},
		{"non_indexable_policy", map[string]any{"non_indexable_policy": "x"}, "non_indexable_policy is currently not supported"},
		{"max_retries_negative", map[string]any{"max_retries": -5}, "max_retries should be non-negative"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(c.cfg)
			require.NoError(t, err, "error translating elasticsearch output to ES exporter config")

			_, _, err = ESToOTelConfig(cfg, "", logger)
			require.ErrorContains(t, err, c.wantErrContains)
		})
	}
}

func TestCalcNamedPresetSizing(t *testing.T) {
	cases := []struct {
		name          string
		maxConns      int
		batchSize     int
		floor         int
		wantQueueSize int
		wantConsumers int
	}{
		{
			name:          "balanced single host",
			maxConns:      1,
			batchSize:     1600,
			floor:         3200,
			wantQueueSize: 6400, // 2*1600*2=6400 > floor 3200
			wantConsumers: 2,
		},
		{
			name:          "throughput single host",
			maxConns:      4,
			batchSize:     1600,
			floor:         12800,
			wantQueueSize: 25600, // 2*1600*8=25600 > floor 12800
			wantConsumers: 8,
		},
		{
			name:      "latency preset floor kicks in without cap",
			maxConns:  1,
			batchSize: 50,
			floor:     4100,
			// formula gives 2*50*2=200, below floor 4100 but no cap applied;
			// queueSize takes the floor, numConsumers stays at connection-model value
			wantQueueSize: 4100,
			wantConsumers: 2,
		},
		{
			name:          "large host list capped at maxQueueEvents",
			maxConns:      30,
			batchSize:     1600,
			floor:         3200,
			wantQueueSize: maxQueueEvents,                  // 2*1600*60=192000 > 64000
			wantConsumers: max(1, maxQueueEvents/(2*1600)), // 20
		},
		{
			name:      "cap applies then floor above ceiling recalculates consumers",
			maxConns:  30,
			batchSize: 1600,
			floor:     maxQueueEvents + 10000, // hypothetical: preset floor above memory ceiling
			// formula 192000 > 64000: cap to 64000, numConsumers=20;
			// then floor 74000 > 64000: apply floor and recalculate
			wantQueueSize: maxQueueEvents + 10000,
			wantConsumers: max(1, (maxQueueEvents+10000)/(2*1600)),
		},
		{
			name:          "zero batchSize guarded",
			maxConns:      1,
			batchSize:     0,
			floor:         0,
			wantQueueSize: 4, // batchSize clamped to 1: 2*1*2=4
			wantConsumers: 2,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gotQueueSize, gotConsumers := calcNamedPresetSizing(c.maxConns, c.batchSize, c.floor)
			assert.Equal(t, c.wantQueueSize, gotQueueSize, "queueSize")
			assert.Equal(t, c.wantConsumers, gotConsumers, "numConsumers")
		})
	}
}

func newFromYamlString(t *testing.T, input string) *confmap.Conf {
	t.Helper()
	input = strings.ReplaceAll(input, "__REQUEST_RETRY_STATUSES__", requestRetryStatusesYAML())
	var rawConf map[string]any
	err := yaml.Unmarshal([]byte(input), &rawConf)
	require.NoError(t, err)

	return confmap.NewFromStringMap(rawConf)
}

func requestRetryStatusesYAML() string {
	statuses := defaultRetryOnStatus()
	lines := make([]string, len(statuses))
	for i, status := range statuses {
		lines[i] = fmt.Sprintf("  - %d", status)
	}

	return strings.Join(lines, "\n")
}

func compareAndAssert(t *testing.T, expectedOutput *confmap.Conf, gotOutput *confmap.Conf) {
	t.Helper()
	// convert it to a common type
	want, err := yaml.Marshal(expectedOutput.ToStringMap())
	require.NoError(t, err)
	got, err := yaml.Marshal(gotOutput.ToStringMap())
	require.NoError(t, err)

	assert.Equal(t, string(want), string(got))
}
