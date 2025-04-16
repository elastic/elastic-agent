// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package remote

import (
	"fmt"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestClientWithUnsupportedTLSVersions(t *testing.T) {
	testLogger, _ := loggertest.New("TestClientWithUnsupportedTLSVersions")
	const unsupportedErrorMsg = "invalid configuration: unsupported tls version: %s"

	cases := map[tlscommon.TLSVersion]string{
		tlscommon.TLSVersion10: unsupportedErrorMsg,
		tlscommon.TLSVersion11: unsupportedErrorMsg,
		tlscommon.TLSVersion12: "",
		tlscommon.TLSVersion13: "",
	}

	for ver, expectedErrMsg := range cases {
		t.Run(ver.String(), func(t *testing.T) {
			tlsEnabled := true
			config := Config{
				Transport: httpcommon.HTTPTransportSettings{
					TLS: &tlscommon.Config{
						Enabled:  &tlsEnabled,
						Versions: []tlscommon.TLSVersion{ver},
					},
				},
			}

			client, err := NewWithConfig(testLogger, config, nil)
			if expectedErrMsg == "" {
				require.NotNil(t, client)
				require.NoError(t, err)
			} else {
				expectedErrMsg = fmt.Sprintf(expectedErrMsg, ver)
				require.Nil(t, client)
				require.Equal(t, expectedErrMsg, err.Error())
			}
		})
	}
}

// TODO: add test for non-compliant keypair (RSA with key length < 2048)
