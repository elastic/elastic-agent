// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
)

func TestGetFlushTimeout(t *testing.T) {
	logger := logptest.NewTestingLogger(t, "")

	testCases := []struct {
		name     string
		input    map[string]any
		expected string
	}{
		{
			name:     "unitless integer is interpreted as seconds",
			input:    map[string]any{"queue.mem.flush.timeout": 5},
			expected: "5s",
		},
		{
			name:     "unitless zero is interpreted as seconds",
			input:    map[string]any{"queue.mem.flush.timeout": 0},
			expected: "0s",
		},
		{
			name:     "unitless fractional value preserves original text",
			input:    map[string]any{"queue.mem.flush.timeout": 0.1},
			expected: "0.1s",
		},
		{
			name:     "unitless value with leading dot preserves original text",
			input:    map[string]any{"queue.mem.flush.timeout": ".9"},
			expected: ".9s",
		},
		{
			name:     "unitless value with trailing dot preserves original text",
			input:    map[string]any{"queue.mem.flush.timeout": "2."},
			expected: "2.s",
		},
		{
			name:     "value with seconds unit is passed through",
			input:    map[string]any{"queue.mem.flush.timeout": "5s"},
			expected: "5s",
		},
		{
			name:     "value with minutes unit is passed through",
			input:    map[string]any{"queue.mem.flush.timeout": "2m"},
			expected: "2m",
		},
		{
			name:     "value with milliseconds unit is passed through",
			input:    map[string]any{"queue.mem.flush.timeout": "100ms"},
			expected: "100ms",
		},
		{
			name:     "missing value falls back to default",
			input:    map[string]any{},
			expected: "10s",
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(test.input)
			require.NoError(t, err)

			got := getFlushTimeout(logger, cfg)
			require.Equal(t, test.expected, got)

			// The OTel exporterhelper flush_timeout is a time.Duration, so the
			// returned value must always parse with a unit.
			_, err = time.ParseDuration(got)
			require.NoError(t, err, "flush_timeout %q must be a valid duration", got)
		})
	}
}

func TestTLSCommonToOTel(t *testing.T) {

	logger := logptest.NewTestingLogger(t, "")

	ptrBool := func(v bool) *bool { return &v }

	testCases := []struct {
		name           string
		input          *tlscommon.Config
		expectedOutput map[string]any
	}{
		{
			name:           "when *tlscommon.Config is nil",
			input:          nil,
			expectedOutput: nil,
		},
		{
			name: "when ssl.enabled = false",
			input: &tlscommon.Config{
				Enabled: ptrBool(false),
			},
			expectedOutput: map[string]any{
				"insecure": true,
			},
		},
		{
			name: "when ssl.enabled = true",
			input: &tlscommon.Config{
				Enabled: ptrBool(true),
			},
			expectedOutput: map[string]any{
				"min_version": "1.2",
				"max_version": "1.3",
			},
		},
		{
			name: "when ssl.verification_mode:none",
			input: &tlscommon.Config{
				VerificationMode: tlscommon.VerifyNone,
			},
			expectedOutput: map[string]any{
				"insecure_skip_verify": true,
				"min_version":          "1.2",
				"max_version":          "1.3"},
		},
	}

	for _, test := range testCases {
		t.Run(test.name, func(t *testing.T) {
			gotMap, err := TLSToOTel(test.input, logger)
			require.NoError(t, err)
			require.Equal(t, test.expectedOutput, gotMap)
		})
	}

}
