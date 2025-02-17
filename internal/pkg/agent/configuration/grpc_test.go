// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package configuration

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOverrideDefaultGRPCPort(t *testing.T) {
	testcases := []struct {
		name     string
		env      string
		expected uint16
	}{{
		name:     "no env var",
		env:      "",
		expected: DefaultGPRCPortInContainer,
	}, {
		name:     "valid env var",
		env:      "1234",
		expected: 1234,
	}, {
		name:     "invalid env var",
		env:      "not a number",
		expected: DefaultGPRCPortInContainer,
	}}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := GRPCConfig{}
			if tc.env != "" {
				os.Setenv(grpcPortContainerEnvVar, tc.env)
				defer os.Unsetenv(grpcPortContainerEnvVar)
			}
			OverrideDefaultContainerGRPCPort(&cfg)
			assert.Equal(t, tc.expected, cfg.Port)
		})
	}
}
