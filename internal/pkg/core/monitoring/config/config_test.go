// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
	"gotest.tools/assert"

	"github.com/elastic/beats/v7/x-pack/elastic-agent/pkg/config"
)

func TestAPMConfig(t *testing.T) {
	tcs := map[string]struct {
		in  map[string]interface{}
		out APMConfig
	}{
		"default": {
			in:  map[string]interface{}{},
			out: defaultAPMConfig(),
		},
		"custom": {
			in: map[string]interface{}{
				"traces": true,
				"apm": map[string]interface{}{
					"api_key":     "abc123",
					"environment": "production",
					"hosts":       []string{"https://abc.123.com"},
					"tls": map[string]interface{}{
						"skip_verify":        true,
						"server_certificate": "server_cert",
						"server_ca":          "server_ca",
					},
				},
			},
			out: APMConfig{
				APIKey:      "abc123",
				Environment: "production",
				Hosts:       []string{"https://abc.123.com"},
				TLS: APMTLS{
					SkipVerify:        true,
					ServerCertificate: "server_cert",
					ServerCA:          "server_ca",
				},
			},
		},
	}

	for name, tc := range tcs {
		t.Run(name, func(t *testing.T) {
			in, err := config.NewConfigFrom(tc.in)
			require.NoError(t, err)

			cfg := DefaultConfig()
			require.NoError(t, in.Unpack(cfg))
			require.NotNil(t, cfg)

			assert.DeepEqual(t, tc.out, cfg.APM)
		})
	}
}
