// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package translate

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetBeatsAuthExtensionConfig(t *testing.T) {
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
			expectedError: "kerberos is not supported in fips mode accessing 'kerberos'",
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
