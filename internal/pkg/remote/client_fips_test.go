// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package remote

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestClientWithUnsupportedTLSVersions(t *testing.T) {
	testLogger, _ := loggertest.New("TestClientWithUnsupportedTLSVersions")
	const unsupportedErrorMsg = "invalid configuration: unsupported tls version: %s"

	cases := map[string]struct {
		versions       []tlscommon.TLSVersion
		expectedErrMsg string
	}{
		"1.0": {
			versions:       []tlscommon.TLSVersion{tlscommon.TLSVersion10},
			expectedErrMsg: fmt.Sprintf(unsupportedErrorMsg, tlscommon.TLSVersion10),
		},
		"1.1": {
			versions:       []tlscommon.TLSVersion{tlscommon.TLSVersion11},
			expectedErrMsg: fmt.Sprintf(unsupportedErrorMsg, tlscommon.TLSVersion11),
		},
		"1.2": {
			versions:       []tlscommon.TLSVersion{tlscommon.TLSVersion12},
			expectedErrMsg: "",
		},
		"1.3": {
			versions:       []tlscommon.TLSVersion{tlscommon.TLSVersion13},
			expectedErrMsg: "",
		},
		"1.1,1.2": {
			versions:       []tlscommon.TLSVersion{tlscommon.TLSVersion11, tlscommon.TLSVersion12},
			expectedErrMsg: fmt.Sprintf(unsupportedErrorMsg, tlscommon.TLSVersion11),
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			tlsEnabled := true
			config := Config{
				Transport: httpcommon.HTTPTransportSettings{
					TLS: &tlscommon.Config{
						Enabled:  &tlsEnabled,
						Versions: test.versions,
					},
				},
			}

			client, err := NewWithConfig(testLogger, config, nil)
			if test.expectedErrMsg == "" {
				require.NotNil(t, client)
				require.NoError(t, err)
			} else {
				require.Nil(t, client)
				require.Equal(t, test.expectedErrMsg, err.Error())
			}
		})
	}
}
