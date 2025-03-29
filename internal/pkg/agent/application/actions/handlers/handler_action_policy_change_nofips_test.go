// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !requirefips

package handlers

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	mockhandlers "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/agent/application/actions/handlers"
)

func Test_Handler_SSL_Passphrase(t *testing.T) {
	log, _ := logger.New("", false)

	agentInfo := &info.AgentInfo{}
	nullStore := &storage.NullStore{}

	agentChildEncPassphrase := `reallySecurePassword`
	passphrasePath := filepath.Join(t.TempDir(), "passphrase")
	err = os.WriteFile(
		passphrasePath,
		[]byte(agentChildEncPassphrase),
		0400)
	require.NoError(t, err,
		"could not write agent child certificate key passphrase to temp directory")

	fleetRootPair, fleetChildPair, err := certutil.NewRootAndChildCerts()
	require.NoError(t, err, "failed creating fleet root and child certs")

	agentRootPair, agentChildPair, err := certutil.NewRootAndChildCerts()
	require.NoError(t, err, "failed creating root and child certs")

	agentChildDERKey, _ := pem.Decode(agentChildPair.Key)
	require.NoError(t, err, "could not create tls.Certificates from child certificate")

	encPem, err := x509.EncryptPEMBlock( //nolint:staticcheck // we need to drop support for this, but while we don't, it needs to be tested.
		rand.Reader,
		"EC PRIVATE KEY",
		agentChildDERKey.Bytes,
		[]byte(agentChildEncPassphrase),
		x509.PEMCipherAES128)
	require.NoError(t, err, "failed encrypting agent child certificate key block")
	agentChildEncPair := certutil.Pair{
		Cert: agentChildPair.Cert,
		Key:  pem.EncodeToMemory(encPem),
	}

	wrongRootPair, wrongChildPair, err := certutil.NewRootAndChildCerts()
	require.NoError(t, err, "failed creating root and child certs")

	statusHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" {
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write(nil)
			require.NoError(t, err)
		}
		_, err := w.Write(nil)
		require.NoError(t, err)
	}
	fleetmTLSServer := httptest.NewUnstartedServer(
		http.HandlerFunc(statusHandler))

	fleetNomTLSServer := httptest.NewUnstartedServer(
		http.HandlerFunc(statusHandler))

	fleetRootCertPool := x509.NewCertPool()
	fleetRootCertPool.AppendCertsFromPEM(fleetRootPair.Cert)
	cert, err := tls.X509KeyPair(fleetChildPair.Cert, fleetChildPair.Key)
	require.NoError(t, err, "could not create tls.Certificates from child certificate")

	agentRootCertPool := x509.NewCertPool()
	agentRootCertPool.AppendCertsFromPEM(agentRootPair.Cert)

	fleetmTLSServer.TLS = &tls.Config{ //nolint:gosec // it's just a test
		RootCAs:      fleetRootCertPool,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    agentRootCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	fleetNomTLSServer.TLS = &tls.Config{ //nolint:gosec // it's just a test
		RootCAs:      fleetRootCertPool,
		Certificates: []tls.Certificate{cert},
	}

	fleetmTLSServer.StartTLS()
	defer fleetmTLSServer.Close()
	fleetNomTLSServer.StartTLS()
	defer fleetNomTLSServer.Close()

	trueVar := true
	tcs := []struct {
		name                     string
		originalCfg              *configuration.Configuration
		newCfg                   map[string]interface{}
		setterCalledCount        int
		wantCAs                  []string
		wantCertificateConfig    tlscommon.CertificateConfig
		assertErr                func(t *testing.T, err error)
		customLogLevelSetterMock func(t *testing.T) *mockhandlers.LogLevelSetter
	}{{
		name: "certificate and key with passphrase is applied when present",
		originalCfg: &configuration.Configuration{
			Fleet: &configuration.FleetAgentConfig{
				Client: remote.Config{
					Host: fleetmTLSServer.URL,
					Transport: httpcommon.HTTPTransportSettings{
						TLS: &tlscommon.Config{
							CAs: []string{string(fleetRootPair.Cert)},
						},
					},
				},
				AccessAPIKey: "ignore",
			},
			Settings: configuration.DefaultSettingsConfig(),
		},
		newCfg: map[string]interface{}{
			"fleet.ssl.enabled":        true,
			"fleet.ssl.certificate":    string(agentChildEncPair.Cert),
			"fleet.ssl.key":            string(agentChildEncPair.Key),
			"fleet.ssl.key_passphrase": agentChildEncPassphrase,
		},
		setterCalledCount: 1,
		wantCAs:           []string{string(fleetRootPair.Cert)},
		wantCertificateConfig: tlscommon.CertificateConfig{
			Certificate: string(agentChildEncPair.Cert),
			Key:         string(agentChildEncPair.Key),
			Passphrase:  agentChildEncPassphrase,
		},
		assertErr: func(t *testing.T, err error) {
			assert.NoError(t, err,
				"unexpected error when applying fleet.ssl.certificate and key")
		},
	}, {
		name: "certificate and key with passphrase_path is applied when present",
		originalCfg: &configuration.Configuration{
			Fleet: &configuration.FleetAgentConfig{
				Client: remote.Config{
					Host: fleetmTLSServer.URL,
					Transport: httpcommon.HTTPTransportSettings{
						TLS: &tlscommon.Config{
							CAs: []string{string(fleetRootPair.Cert)},
						},
					},
				},
				AccessAPIKey: "ignore",
			},
			Settings: configuration.DefaultSettingsConfig(),
		},
		newCfg: map[string]interface{}{
			"fleet.ssl.enabled":             true,
			"fleet.ssl.certificate":         string(agentChildEncPair.Cert),
			"fleet.ssl.key":                 string(agentChildEncPair.Key),
			"fleet.ssl.key_passphrase_path": passphrasePath,
		},
		setterCalledCount: 1,
		wantCAs:           []string{string(fleetRootPair.Cert)},
		wantCertificateConfig: tlscommon.CertificateConfig{
			Certificate:    string(agentChildEncPair.Cert),
			Key:            string(agentChildEncPair.Key),
			PassphrasePath: passphrasePath,
		},
		assertErr: func(t *testing.T, err error) {
			assert.NoError(t, err,
				"unexpected error when applying fleet.ssl.certificate and key")
		},
	},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			log, logs := loggertest.New(tc.name)
			defer func() {
				if t.Failed() {
					t.Log("test failed, see handler logs below:")
					for _, l := range logs.TakeAll() {
						t.Log(l)
					}
				}
			}()

			var setterCalledCount int
			setter := testSetter{SetClientFn: func(c client.Sender) {
				setterCalledCount++
			}}

			var logLevelSetterMock *mockhandlers.LogLevelSetter
			if tc.customLogLevelSetterMock != nil {
				logLevelSetterMock = tc.customLogLevelSetterMock(t)
			} else {
				logLevelSetterMock = nilLogLevelSet(t)
			}
			h := PolicyChangeHandler{
				agentInfo:            &info.AgentInfo{},
				config:               tc.originalCfg,
				store:                &storage.NullStore{},
				setters:              []actions.ClientSetter{&setter},
				log:                  log,
				policyLogLevelSetter: logLevelSetterMock,
			}

			cfg := config.MustNewConfigFrom(tc.newCfg)

			err := h.handlePolicyChange(context.Background(), cfg)
			tc.assertErr(t, err)

			assert.Equal(t, tc.setterCalledCount, setterCalledCount,
				"setter was not called")
			if assert.NotNil(t, h.config.Fleet.Client.Transport.TLS, "TLS settings in fleet client config should not be null") {
				assert.Equal(t,
					tc.wantCAs, h.config.Fleet.Client.Transport.TLS.CAs,
					"unexpected CAs")
				assert.Equal(t,
					tc.wantCertificateConfig, h.config.Fleet.Client.Transport.TLS.Certificate,
					"unexpected certificate/key pair")
			}
		})
	}
}
