// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package translate

import (
	"testing"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp/logptest"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/stretchr/testify/require"
)

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

func TestCurvePreference(t *testing.T) {
	input := `
ssl:
  curve_types: 
  - P-256
  - P-384
  - P-521
  - X25519
`

	inputCfg := config.MustNewConfigFrom(input)
	sslCfg, err := inputCfg.Child("ssl", -1)
	require.NoError(t, err)
	tlsCfg := &tlscommon.Config{}
	err = sslCfg.Unpack(tlsCfg)
	require.NoError(t, err)

	got, err := TLSToOTel(tlsCfg, logptest.NewTestingLogger(t, ""))
	require.NoError(t, err)
	expectedMap := map[string]any{
		"curve_preferences": []string{"P256", "P384", "P521", "X25519"},
		"min_version":       "1.2",
		"max_version":       "1.3",
	}
	require.Equal(t, expectedMap, got)

}
