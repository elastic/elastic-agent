// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package remote

import (
	"context"
	"fmt"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	"github.com/stretchr/testify/require"
	"net/http"
	"testing"
)

func TestClientWithUnsupportedTLSVersions(t *testing.T) {
	const unsupportedForFIPSErrorMsg = "tls: no supported versions satisfy MinVersion and MaxVersion"
	const supportedForFIPSErrorMsg = "x509: certificate signed by unknown authority"

	cases := map[tlscommon.TLSVersion]string{
		tlscommon.TLSVersion10: unsupportedForFIPSErrorMsg,
		tlscommon.TLSVersion11: unsupportedForFIPSErrorMsg,
		tlscommon.TLSVersion12: supportedForFIPSErrorMsg,
		tlscommon.TLSVersion13: supportedForFIPSErrorMsg,
	}

	for ver, expectedErrMsg := range cases {
		t.Run(ver.String(), withTLSServer(func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/nested/echo-hello", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"message":"hello"}`)
			})
			return addCatchAll(mux, t)
		}, func(t *testing.T, host string) {
			testLogger, _ := loggertest.New("TestClientWithRSAKeySmallKeyLength")

			url := "https://" + host + "/"

			config, err := NewConfigFromURL(url)
			require.NoError(t, err)

			tlsEnabled := true
			config.Transport = httpcommon.HTTPTransportSettings{
				TLS: &tlscommon.Config{
					Enabled:  &tlsEnabled,
					Versions: []tlscommon.TLSVersion{ver},
				},
			}

			client, err := NewWithConfig(testLogger, config, nil)
			require.NotNil(t, client)
			require.NoError(t, err)

			ctx := context.Background()
			response, err := client.Send(ctx, http.MethodGet, "/nested/echo-hello", nil, nil, nil)
			require.Nil(t, response)
			fmt.Println(err)
			require.Contains(t, err.Error(), expectedErrMsg)
		}))
	}
}

// TODO: add test for non-compliant keypair (RSA with key length < 2048)
