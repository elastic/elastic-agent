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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

//go:embed testdata/root.crt
var rootCertPEM []byte

//go:embed testdata/root.key
var rootKeyPEM []byte // RSA key with length = 2048 bits

//go:embed testdata/server.crt
var serverCertPEM []byte

//go:embed testdata/server.key
var serverKeyPEM []byte // RSA key with length = 2048 bits

//go:embed testdata/agent_insecure.crt
var agentCertPEM []byte

//go:embed testdata/agent_insecure.key
var agentKeyPEM []byte // RSA key with length = 1024 bits

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

func TestClientWithInsecureCertificate(t *testing.T) {
	rootCertPool := x509.NewCertPool()
	rootCertPool.AppendCertsFromPEM(rootCertPEM)

	// Create HTTPS server
	const successResp = `{"message":"hello"}`
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, successResp)
	}))

	serverCert, err := tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	require.NoError(t, err)

	server.TLS = &tls.Config{
		RootCAs:      rootCertPool,
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    rootCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	var serverLog strings.Builder
	server.Config.ErrorLog = log.New(&serverLog, "", 0)

	server.StartTLS()
	defer server.Close()

	// Create client with a certificate that uses a RSA keypair with
	// < 2048 bits of key length.
	testLogger, _ := loggertest.New("downloader")
	config := Config{
		Host: server.URL,
		Transport: httpcommon.HTTPTransportSettings{
			TLS: &tlscommon.Config{
				CAs: []string{string(rootCertPEM)},
				Certificate: tlscommon.CertificateConfig{
					Certificate: string(agentCertPEM),
					Key:         string(agentKeyPEM),
				},
			},
		},
	}
	client, err := NewWithConfig(testLogger, config, nil)

	// Use client to call fake API on HTTPS server, expecting the call to fail
	// with a TLS validation error due to FIPS requirements.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	resp, err := client.Send(ctx, http.MethodGet, "/echo-hello", nil, nil, nil)

	require.Nil(t, resp)
	require.Error(t, err)
	require.Contains(t, serverLog.String(), "no FIPS compatible certificate chains found")
	require.Contains(t, err.Error(), "invalid key length")
}
