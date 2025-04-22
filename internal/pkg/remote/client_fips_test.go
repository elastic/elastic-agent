// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package remote

import (
	_ "embed"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

//go:embed testdata/rsa_1024.cert.pem
var rsa1024CertPEM string

//go:embed testdata/rsa_1024.key.pem
var rsa1024KeyPem string

func TestClientWithUnsupportedTLSVersions(t *testing.T) {
	testLogger, _ := loggertest.New("TestClientWithUnsupportedTLSVersions")
	const unsupportedErrorMsg = "invalid configuration: unsupported tls version: %s"

	cases := map[string]struct {
		tlsConfig      tlscommon.Config
		versions       []tlscommon.TLSVersion
		expectedErrMsg string
	}{
		"TLSv1.0": {
			tlsConfig:      tlscommon.Config{Versions: []tlscommon.TLSVersion{tlscommon.TLSVersion10}},
			versions:       []tlscommon.TLSVersion{tlscommon.TLSVersion10},
			expectedErrMsg: fmt.Sprintf(unsupportedErrorMsg, tlscommon.TLSVersion10),
		},
		"TLSv1.1": {
			tlsConfig:      tlscommon.Config{Versions: []tlscommon.TLSVersion{tlscommon.TLSVersion11}},
			versions:       []tlscommon.TLSVersion{tlscommon.TLSVersion11},
			expectedErrMsg: fmt.Sprintf(unsupportedErrorMsg, tlscommon.TLSVersion11),
		},
		"TLSv1.2": {
			tlsConfig:      tlscommon.Config{Versions: []tlscommon.TLSVersion{tlscommon.TLSVersion12}},
			versions:       []tlscommon.TLSVersion{tlscommon.TLSVersion12},
			expectedErrMsg: "",
		},
		"TLSv1.3": {
			tlsConfig:      tlscommon.Config{Versions: []tlscommon.TLSVersion{tlscommon.TLSVersion13}},
			versions:       []tlscommon.TLSVersion{tlscommon.TLSVersion13},
			expectedErrMsg: "",
		},
		"TLSv1.1,TLSv1.2": {
			tlsConfig:      tlscommon.Config{Versions: []tlscommon.TLSVersion{tlscommon.TLSVersion11, tlscommon.TLSVersion12}},
			versions:       []tlscommon.TLSVersion{tlscommon.TLSVersion11, tlscommon.TLSVersion12},
			expectedErrMsg: fmt.Sprintf(unsupportedErrorMsg, tlscommon.TLSVersion11),
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			tlsEnabled := true
			test.tlsConfig.Enabled = &tlsEnabled
			config := Config{
				Transport: httpcommon.HTTPTransportSettings{
					TLS: &test.tlsConfig,
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
