// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package translate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

func TestKafkaOAuth2Translation(t *testing.T) {
	input := `
hosts: ["kafka1:9092"]
topic: static-topic
username: elastic
password: changeme
sasl.mechanism: OAUTHBEARER
oauth:
  oauth2client:
    client_id: my-client
    client_secret: my-secret
    token_url: https://example.com/oauth2/token
`
	expectedMap := map[string]any{
		"brokers":   []string{"kafka1:9092"},
		"client_id": "beats",
		"logs": map[string]any{
			"topic":    "static-topic",
			"encoding": "raw",
		},
		"metadata": map[string]any{
			"refresh_interval": 10 * time.Minute,
		},
		"producer": map[string]any{
			"compression": "gzip",
			"compression_params": map[string]any{
				"level": 4,
			},
			"max_message_bytes": 1000000,
			"required_acks":     1,
		},
		"protocol_version": "2.1.0",
		"retry_on_failure": map[string]any{
			"initial_interval": 1 * time.Second,
			"max_interval":     60 * time.Second,
		},
		"sending_queue": map[string]any{
			"batch": map[string]any{
				"flush_timeout": "10s",
				"max_size":      2048,
				"sizer":         "items",
				"min_size":      1600,
			},
			"queue_size": 3200,
		},
		"timeout": 10 * time.Second,
		"auth": map[string]any{
			"sasl": map[string]any{ //nolint:gosec // G101: test fixture, not a real credential
				"mechanism":                "OAUTHBEARER",
				"oauthbearer_token_source": "oauth2client/_agent-component/default",
			},
		},
		"record_partitioner": map[string]any{
			"extension": "kafkapartitioner/_agent-component/default",
		},
	}

	cfg, err := config.NewConfigFrom(input)
	require.NoError(t, err, "error creating kafka config")
	gotMap, processorCfg, extensionCfg, err := KafkaToOTelConfig(cfg, "default", logp.NewNopLogger())
	require.NoError(t, err, "error translating kafka to kafka exporter")
	require.Equal(t, expectedMap, gotMap)
	require.Nil(t, processorCfg)
	require.Contains(t, extensionCfg, "oauth2client/_agent-component/default")
}

func TestKafkaOAuthRequiresOauthConfig(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name: "missing oauth",
			input: `
hosts: ["kafka1:9092"]
topic: static-topic
sasl.mechanism: OAUTHBEARER
`,
			wantErr: "oauth config is required when sasl.mechanism is OAUTHBEARER",
		},
		{
			name: "empty oauth",
			input: `
hosts: ["kafka1:9092"]
topic: static-topic
sasl.mechanism: OAUTHBEARER
oauth: {}
`,
			wantErr: "oauth config is required when sasl.mechanism is OAUTHBEARER",
		},
		{
			name: "unsupported oauth type",
			input: `
hosts: ["kafka1:9092"]
topic: static-topic
sasl.mechanism: OAUTHBEARER
oauth:
  unknown:
    client_id: my-client
`,
			wantErr: "unsupported oauth config",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(tc.input)
			require.NoError(t, err, "error creating kafka config")
			gotMap, processorCfg, extensionCfg, err := KafkaToOTelConfig(cfg, "default", logp.NewNopLogger())
			require.Error(t, err)
			require.ErrorContains(t, err, tc.wantErr)
			require.Nil(t, gotMap)
			require.Nil(t, processorCfg)
			require.Nil(t, extensionCfg)
		})
	}
}

func TestKafkaKerberosTranslation(t *testing.T) {
	testCases := []struct {
		name             string
		input            string
		expectedKerberos map[string]any
		expectKerberos   bool
	}{
		{
			name: "kerberos with password auth",
			input: `
hosts: ["kafka1:9092"]
topic: static-topic
kerberos:
  enabled: true
  auth_type: password
  username: elastic
  password: changeme
  config_path: /etc/krb5.conf
  service_name: kafka
  realm: ELASTIC
  enable_krb5_fast: true
`,
			expectKerberos: true,
			expectedKerberos: map[string]any{
				"service_name":             "kafka",
				"realm":                    "ELASTIC",
				"username":                 "elastic",
				"password":                 "changeme",
				"config_file":              "/etc/krb5.conf",
				"disable_fast_negotiation": false,
				"keytab_file":              "",
				"use_keytab":               false,
			},
		},
		{
			name: "kerberos with keytab auth",
			input: `
hosts: ["kafka1:9092"]
topic: static-topic
kerberos:
  enabled: true
  auth_type: keytab
  username: elastic
  keytab: /etc/security/kafka.keytab
  config_path: /etc/krb5.conf
  service_name: kafka
  realm: ELASTIC
`,
			expectKerberos: true,
			expectedKerberos: map[string]any{
				"service_name":             "kafka",
				"realm":                    "ELASTIC",
				"username":                 "elastic",
				"password":                 "",
				"config_file":              "/etc/krb5.conf",
				"disable_fast_negotiation": true,
				"keytab_file":              "/etc/security/kafka.keytab",
				"use_keytab":               true,
			},
		},
		{
			name: "kerberos disabled is omitted",
			input: `
hosts: ["kafka1:9092"]
topic: static-topic
kerberos:
  enabled: false
  auth_type: password
  username: elastic
  password: changeme
  config_path: /etc/krb5.conf
  service_name: kafka
  realm: ELASTIC
`,
			expectKerberos: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(tc.input)
			require.NoError(t, err, "error creating kafka config")

			gotMap, _, _, err := KafkaToOTelConfig(cfg, "", logp.NewNopLogger())
			require.NoError(t, err, "error translating kafka to kafka exporter")

			gotKerberos, ok := gotMap["auth"]
			if !tc.expectKerberos {
				require.False(t, ok, "kerberos should be omitted from exporter config")
				return
			}

			require.True(t, ok, "kerberos should be present in exporter config")
			require.Equal(t, tc.expectedKerberos, gotKerberos.(map[string]any)["kerberos"])
		})
	}
}
