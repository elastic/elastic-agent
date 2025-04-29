// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package remote

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/testutils/fipsutils"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

//go:embed testdata/ca.crt
var caCertPEM []byte

//go:embed testdata/server.crt
var serverCertPEM []byte

//go:embed testdata/server.key
var serverKeyPEM []byte // RSA key with length = 2048 bits

//go:embed testdata/fips_invalid.key
var fipsInvalidKeyPEM []byte // RSA key with length = 1024 bits

//go:embed testdata/fips_invalid.crt
var fipsInvalidCertPEM []byte

//go:embed testdata/fips_valid.key
var fipsValidKeyPEM []byte // RSA key with length = 2048 bits

//go:embed testdata/fips_valid.crt
var fipsValidCertPEM []byte

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

type serverLog struct {
	log strings.Builder
	mu  sync.Mutex
}

func (s *serverLog) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.log.Write(data)
}

func (s *serverLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.log.String()
}

func TestClientWithCertificate(t *testing.T) {
	cases := map[string]struct {
		clientCertificate    []byte
		clientKey            []byte
		expectedHandshakeErr string
		expectedServerLog    string
	}{
		"fips_invalid_key_fips140only": {
			clientCertificate:    fipsInvalidCertPEM,
			clientKey:            fipsInvalidKeyPEM,
			expectedHandshakeErr: "use of keys smaller than 2048 bits is not allowed in FIPS 140-only mode",
			expectedServerLog:    "no FIPS compatible certificate chains found",
		},
		"fips_valid_key_fips140only": {
			clientCertificate:    fipsValidCertPEM,
			clientKey:            fipsValidKeyPEM,
			expectedHandshakeErr: "",
			expectedServerLog:    "",
		},
	}

	for name, test := range cases {
		t.Run(name, func(t *testing.T) {
			goDebugFIPS140 := fipsutils.GoDebugFIPS140()
			if goDebugFIPS140 != fipsutils.GoDebugFIPS140Only {
				t.Skipf(
					`test expects to be run with GODEBUG=fips140=only but actual value is "%s", so skipping`,
					goDebugFIPS140,
				)
			}

			server, serverLog := startTLSServer(t)

			// Create client and have it present a certificate during the
			// TLS handshake with the server
			testLogger, _ := loggertest.New("TestClientWithCertificate")
			config := Config{
				Host: server.URL,
				Transport: httpcommon.HTTPTransportSettings{
					TLS: &tlscommon.Config{
						CAs: []string{string(caCertPEM)},
						Certificate: tlscommon.CertificateConfig{
							Certificate: string(test.clientCertificate),
							Key:         string(test.clientKey),
						},
					},
				},
			}
			client, err := NewWithConfig(testLogger, config, nil)

			// Use client to call fake API on HTTPS server
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			resp, err := client.Send(ctx, http.MethodGet, "/echo-hello", nil, nil, nil)

			if test.expectedHandshakeErr == "" {
				require.NotNil(t, resp)
				require.NoError(t, err)
			} else {
				require.Nil(t, resp)
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedHandshakeErr)
			}

			require.Eventually(
				t,
				func() bool {
					return assert.Contains(t, serverLog.String(), test.expectedServerLog)
				},
				100*time.Millisecond, 10*time.Millisecond,
			)
		})
	}
}

func startTLSServer(t *testing.T) (*httptest.Server, *serverLog) {
	// Configure server and start it
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCertPEM)

	// Create HTTPS server
	const successResp = `{"message":"hello"}`
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, successResp)
	}))

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	server.TLS = &tls.Config{
		RootCAs:      caCertPool,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	logger := new(serverLog)
	server.Config.ErrorLog = log.New(logger, "", 0)

	server.StartTLS()

	return server, logger
}
