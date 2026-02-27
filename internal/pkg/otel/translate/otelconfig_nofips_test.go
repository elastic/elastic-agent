// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package translate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/config"
)

func TestBeatsAuthExtensionKerberos(t *testing.T) {
	tests := []struct {
		name          string
		outputCfg     map[string]any
		expected      map[string]any
		expectedError string
	}{
		{
			name: "with kerberos enabled",
			outputCfg: map[string]any{
				"kerberos": map[string]any{
					"enabled":     true,
					"auth_type":   "password",
					"config_path": "temp/krb5.conf",
					"username":    "beats",
					"password":    "testing",
					"realm":       "elastic",
				},
			},
			expected: map[string]any{
				"continue_on_error":       true,
				"idle_connection_timeout": "3s",
				"timeout":                 "1m30s",
				"kerberos": map[string]any{
					"enabled":          true,
					"auth_type":        "password",
					"config_path":      "temp/krb5.conf",
					"username":         "beats",
					"password":         "testing",
					"realm":            "elastic",
					"enable_krb5_fast": false,
					"service_name":     "",
					"keytab":           "",
				},
				"proxy_disable": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(tt.outputCfg)
			require.NoError(t, err)

			actual, err := getBeatsAuthExtensionConfig(cfg)
			if tt.expectedError != "" {
				require.Error(t, err)
				assert.Equal(t, tt.expectedError, err.Error())
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, actual)
			}
		})
	}
}
