// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"bytes"
	_ "embed"
	"fmt"
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
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 60
  queue_size: 3200
  wait_for_result: true
user: elastic
headers:
  X-Header-1: foo
  X-Bar-Header: bar
compression: gzip
compression_params:
  level: 1
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, err := ToOTelConfig(cfg, logger)
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
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 1
  queue_size: 3200
  wait_for_result: true
max_conns_per_host: 1
api_key: VGlOQUdHNEJhYU1kYUgxdFJmdVU6S25SNnlFNDFSclNvd2Iwa1EwSFdvQQ==
compression: gzip
compression_params:
  level: 1
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, err := ToOTelConfig(cfg, logger)
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
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 1
  queue_size: 3200
  wait_for_result: true
max_conns_per_host: 1
api_key: VGlOQUdHNEJhYU1kYUgxdFJmdVU6S25SNnlFNDFSclNvd2Iwa1EwSFdvQQ==
compression: gzip
compression_params:
  level: 1
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, err := ToOTelConfig(cfg, logger)
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
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 1
  queue_size: 3200
  wait_for_result: true
max_conns_per_host: 1
api_key: VGlOQUdHNEJhYU1kYUgxdFJmdVU6S25SNnlFNDFSclNvd2Iwa1EwSFdvQQ==
compression: gzip
compression_params:
  level: 1
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, err := ToOTelConfig(cfg, logger)
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
compression: gzip
compression_params:
  level: 1
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
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 1
  queue_size: 3200
  wait_for_result: true
 `,
			},
			{
				presetName: "throughput",
				output: commonOTelCfg + `
max_conns_per_host: 4
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 1600
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 4
  queue_size: 12800
  wait_for_result: true
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
    flush_timeout: 10s
    max_size: 1600
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 1
  queue_size: 3200
  wait_for_result: true
compression: gzip
compression_params:
  level: 1
 `,
			},
			{
				presetName: "latency",
				output: commonOTelCfg + `
max_conns_per_host: 1
sending_queue:
  batch:
    flush_timeout: 10s
    max_size: 50
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 1
  queue_size: 4100
  wait_for_result: true
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
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 1
  queue_size: 3200
  wait_for_result: true
 `,
			},
		}

		for _, test := range tests {
			t.Run("config translation w/"+test.presetName, func(t *testing.T) {
				cfg := config.MustNewConfigFrom(fmt.Sprintf(commonBeatCfg, test.presetName))
				got, err := ToOTelConfig(cfg, logger)
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
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 60
  queue_size: 3200
  wait_for_result: true
user: elastic
headers:
  X-Header-1: foo
  X-Bar-Header: bar
compression: gzip
compression_params:
  level: 1
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, err := ToOTelConfig(cfg, logger)
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
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 60
  queue_size: 3200
  wait_for_result: true
user: elastic
headers:
  X-Header-1: foo
  X-Bar-Header: bar
compression: gzip
compression_params:
  level: 1
 `
		cfg := config.MustNewConfigFrom(beatCfg)
		got, err := ToOTelConfig(cfg, logger)
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
    min_size: 0
    sizer: items
  block_on_overflow: true
  enabled: true
  num_consumers: 2
  queue_size: 3200
  wait_for_result: true
{{ if gt . 0 }}
compression: gzip
compression_params:
  level: {{ . }}
{{ else }}
compression: none
{{ end }}`

	for level := range 9 {
		t.Run(fmt.Sprintf("compression-level-%d", level), func(t *testing.T) {
			cfg := config.MustNewConfigFrom(fmt.Sprintf(compressionConfig, level))
			got, err := ToOTelConfig(cfg, logp.NewNopLogger())
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
		{"loadbalance_false", map[string]any{"loadbalance": false}, "ladbalance:false is currently not supported"},
		{"non_indexable_policy", map[string]any{"non_indexable_policy": "x"}, "non_indexable_policy is currently not supported"},
		{"max_retries_negative", map[string]any{"max_retries": -5}, "max_retries should be non-negative"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(c.cfg)
			require.NoError(t, err, "error translating elasticsearch output to ES exporter config")

			_, err = ToOTelConfig(cfg, logger)
			require.ErrorContains(t, err, c.wantErrContains)
		})
	}
}

func newFromYamlString(t *testing.T, input string) *confmap.Conf {
	t.Helper()
	var rawConf map[string]any
	err := yaml.Unmarshal([]byte(input), &rawConf)
	require.NoError(t, err)

	return confmap.NewFromStringMap(rawConf)
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
