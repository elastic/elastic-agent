// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build requirefips

package remote

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

func TestClientWithUnsupportedTLSConfig(t *testing.T) {
	testLogger, _ := loggertest.New("TestClientWithUnsupportedTLSVersions")
	const unsupportedErrorMsg = "invalid configuration: unsupported tls version: %s"

	privateKeyPEM, certificatePEM := makeRSA1024KeyCertPair(t)

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
		"rsa_1024": {
			tlsConfig: tlscommon.Config{Certificate: tlscommon.CertificateConfig{
				Certificate: certificatePEM,
				Key:         privateKeyPEM,
			}},
		},
	}

	/* TODO: move block to elastic-agent-libs/transport/tlscommon */
	cert, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	require.NoError(t, err)
	privateKey := cert.PrivateKey.(*rsa.PrivateKey)
	t.Log(privateKey.N.BitLen())
	/* end block */

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

// makeRSA1024KeyCertPair returns a private key and certificate encoded
// in PEM format, generated from an RSA 1024-bit keypair.
func makeRSA1024KeyCertPair(t *testing.T) (string, string) {
	// Generate RSA keypair
	keyBytes, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)

	err = keyBytes.Validate()
	require.NoError(t, err)

	// Generate certificate from keypair
	tpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{"US"},
			Organization: []string{"Elastic"},
			Province:     []string{"CA"},
			CommonName:   "CN",
		},
	}

	cert, err := x509.CreateCertificate(rand.Reader, &tpl, &tpl, &keyBytes.PublicKey, keyBytes)
	require.NoError(t, err)

	// Convert private key to PEM format
	b, err := x509.MarshalPKCS8PrivateKey(keyBytes)
	require.NoError(t, err)

	keyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	})

	// Convert certificate to PEM format
	certPem := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert,
	})

	return string(keyPem), string(certPem)
}
