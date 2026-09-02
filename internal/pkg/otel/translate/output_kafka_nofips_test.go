// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package translate

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
)

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

			gotMap, _, err := KafkaToOTelConfig(cfg, "", logp.NewNopLogger())
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
