// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package handlers

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	noopacker "github.com/elastic/elastic-agent/internal/pkg/fleetapi/acker/noop"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
	mockhandlers "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/agent/application/actions/handlers"
)

func TestPolicyChange(t *testing.T) {
	log, _ := logger.New("", false)
	ack := noopacker.New()

	agentInfo := &info.AgentInfo{}
	nullStore := &storage.NullStore{}

	t.Run("Receive a config change and successfully emits a raw configuration", func(t *testing.T) {
		ch := make(chan coordinator.ConfigChange, 1)

		conf := map[string]interface{}{"hello": "world"}
		action := &fleetapi.ActionPolicyChange{
			ActionID:   "abc123",
			ActionType: "POLICY_CHANGE",
			Data: fleetapi.ActionPolicyChangeData{
				Policy: conf,
			},
		}

		cfg := configuration.DefaultConfiguration()
		handler := NewPolicyChangeHandler(log, agentInfo, cfg, nullStore, ch, nilLogLevelSet(t), &coordinator.Coordinator{})

		err := handler.Handle(context.Background(), action, ack)
		require.NoError(t, err)

		change := <-ch
		require.Equal(t, config.MustNewConfigFrom(conf), change.Config())
	})
	t.Run("Received config with $$ in inputs", func(t *testing.T) {
		ch := make(chan coordinator.ConfigChange, 1)

		conf := map[string]interface{}{
			"inputs": []interface{}{map[string]interface{}{
				"type": "key",
				"key":  "$$$$",
			}}}
		action := &fleetapi.ActionPolicyChange{
			ActionID:   "abc123",
			ActionType: "POLICY_CHANGE",
			Data: fleetapi.ActionPolicyChangeData{
				Policy: conf,
			},
		}

		cfg := configuration.DefaultConfiguration()
		handler := NewPolicyChangeHandler(log, agentInfo, cfg, nullStore, ch, nilLogLevelSet(t), &coordinator.Coordinator{})

		err := handler.Handle(context.Background(), action, ack)
		require.NoError(t, err)

		change := <-ch
		m, err := change.Config().ToMapStr()
		require.NoError(t, err)

		require.Equal(t, conf, m)
	})
}

func TestPolicyAcked(t *testing.T) {
	log, _ := logger.New("", false)

	agentInfo := &info.AgentInfo{}
	nullStore := &storage.NullStore{}

	t.Run("Config change should ACK", func(t *testing.T) {
		ch := make(chan coordinator.ConfigChange, 1)
		tacker := &testAcker{}

		config := map[string]interface{}{"hello": "world"}
		actionID := "abc123"
		action := &fleetapi.ActionPolicyChange{
			ActionID:   actionID,
			ActionType: "POLICY_CHANGE",
			Data: fleetapi.ActionPolicyChangeData{
				Policy: config,
			},
		}

		cfg := configuration.DefaultConfiguration()
		handler := NewPolicyChangeHandler(log, agentInfo, cfg, nullStore, ch, nilLogLevelSet(t), &coordinator.Coordinator{})

		err := handler.Handle(context.Background(), action, tacker)
		require.NoError(t, err)

		change := <-ch
		require.NoError(t, change.Ack())

		actions := tacker.Items()
		assert.EqualValues(t, 1, len(actions))
		assert.Equal(t, actionID, actions[0])
	})
}

func TestPolicyChangeHandler_handlePolicyChange_FleetClientSettings(t *testing.T) {
	mockProxy := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write(nil)
			require.NoError(t, err)
		}))

	fleetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/status" {
			w.WriteHeader(http.StatusNotFound)
			_, err := w.Write(nil)
			require.NoError(t, err)
		}
		_, err := w.Write(nil)
		require.NoError(t, err)
	}))

	defer mockProxy.Close()
	defer fleetServer.Close()

	fleetServerURL, err := url.Parse(fleetServer.URL)
	require.NoError(t, err)

	fleetServerHost := fleetServerURL.Host
	fleetServerPort, err := strconv.Atoi(fleetServerURL.Port())
	require.NoError(t, err)

	t.Run("policy with proxy config", func(t *testing.T) {
		t.Run("rollback client changes when cannot create client",
			func(t *testing.T) {
				log, _ := loggertest.New("TestPolicyChangeHandler")
				var setterCalledCount int
				setter := testSetter{SetClientFn: func(c client.Sender) {
					setterCalledCount++
				}}

				originalCfg := &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Server: &configuration.FleetServerConfig{
							Host: fleetServerHost,
							Port: uint16(fleetServerPort),
						},
						Client: remote.Config{
							Host:  "http://example.co",
							Hosts: []string{"http://hosts1.com", "http://hosts2.com"},
							Transport: httpcommon.HTTPTransportSettings{
								Proxy: httpcommon.HTTPClientProxySettings{
									URL: &httpcommon.ProxyURI{
										Host: "original.proxy",
									},
								}}},
					},
					Settings: configuration.DefaultSettingsConfig()}

				h := PolicyChangeHandler{
					agentInfo:            &info.AgentInfo{},
					config:               originalCfg,
					store:                &storage.NullStore{},
					setters:              []actions.ClientSetter{&setter},
					log:                  log,
					policyLogLevelSetter: mockhandlers.NewLogLevelSetter(t),
				}

				cfg := config.MustNewConfigFrom(
					map[string]interface{}{
						"fleet.host":      "http://some.url",
						"fleet.proxy_url": "http://some.proxy",
					})

				err := h.handlePolicyChange(context.Background(), cfg)
				require.Error(t, err) // it needs to fail to rollback

				assert.Equal(t, 0, setterCalledCount)
				assert.Equal(t,
					originalCfg.Fleet.Client.Host,
					h.config.Fleet.Client.Host)
				assert.Equal(t,
					originalCfg.Fleet.Client.Hosts,
					h.config.Fleet.Client.Hosts)
				assert.Equal(t,
					originalCfg.Fleet.Client.Transport.Proxy.URL,
					h.config.Fleet.Client.Transport.Proxy.URL)
			})

		t.Run("rollback client changes when cannot reach fleet-server",
			func(t *testing.T) {
				log, _ := loggertest.New("TestPolicyChangeHandler")
				var setterCalledCount int
				setter := testSetter{SetClientFn: func(c client.Sender) {
					setterCalledCount++
				}}

				originalCfg := &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Server: &configuration.FleetServerConfig{
							Host: fleetServerHost,
							Port: uint16(fleetServerPort),
						},
						AccessAPIKey: "ignore",
						Client: remote.Config{
							Host:  "http://example.co",
							Hosts: []string{"http://hosts1.com", "http://hosts2.com"},
							Transport: httpcommon.HTTPTransportSettings{
								Proxy: httpcommon.HTTPClientProxySettings{
									URL: &httpcommon.ProxyURI{
										Host: "original.proxy",
									},
								}}},
					},
					Settings: configuration.DefaultSettingsConfig()}

				h := PolicyChangeHandler{
					agentInfo:            &info.AgentInfo{},
					config:               originalCfg,
					store:                &storage.NullStore{},
					setters:              []actions.ClientSetter{&setter},
					log:                  log,
					policyLogLevelSetter: mockhandlers.NewLogLevelSetter(t),
				}

				cfg := config.MustNewConfigFrom(
					map[string]interface{}{
						"fleet.host":      "http://some.url",
						"fleet.proxy_url": "http://some.proxy",
					})

				err := h.handlePolicyChange(context.Background(), cfg)
				require.Error(t, err) // it needs to fail to rollback

				assert.Equal(t, 0, setterCalledCount)
				assert.Equal(t,
					originalCfg.Fleet.Client.Host,
					h.config.Fleet.Client.Host)
				assert.Equal(t,
					originalCfg.Fleet.Client.Hosts,
					h.config.Fleet.Client.Hosts)
				assert.Equal(t,
					originalCfg.Fleet.Client.Transport.Proxy.URL,
					h.config.Fleet.Client.Transport.Proxy.URL)
			})

		t.Run("a new Hosts and no proxy changes the remote config", func(t *testing.T) {
			log, _ := loggertest.New("TestPolicyChangeHandler")
			var setterCalledCount int
			setter := testSetter{SetClientFn: func(c client.Sender) {
				setterCalledCount++
			}}

			originalCfg := &configuration.Configuration{
				Fleet: &configuration.FleetAgentConfig{
					Server: &configuration.FleetServerConfig{
						Host: fleetServerHost,
						Port: uint16(fleetServerPort),
					},
					AccessAPIKey: "ignore",
					Client: remote.Config{
						Host: "http://example.co",
					},
				},
				Settings: configuration.DefaultSettingsConfig()}

			h := PolicyChangeHandler{
				agentInfo:            &info.AgentInfo{},
				config:               originalCfg,
				store:                &storage.NullStore{},
				setters:              []actions.ClientSetter{&setter},
				log:                  log,
				policyLogLevelSetter: nilLogLevelSet(t),
			}

			cfg := config.MustNewConfigFrom(
				map[string]interface{}{
					"fleet.hosts": fleetServer.URL})

			err := h.handlePolicyChange(context.Background(), cfg)
			require.NoError(t, err)

			assert.Equal(t, 1, setterCalledCount)
			assert.Empty(t, h.config.Fleet.Client.Host)
			assert.Empty(t, h.config.Fleet.Client.Protocol)
			assert.Empty(t, h.config.Fleet.Client.Path)
			assert.Equal(t, []string{fleetServer.URL}, h.config.Fleet.Client.Hosts)
			assert.Empty(t, h.config.Fleet.Client.Transport.Proxy.URL)
		})

		t.Run("a proxy changes the fleet client", func(t *testing.T) {
			log, _ := loggertest.New("TestPolicyChangeHandler")
			var setterCalledCount int
			setter := testSetter{SetClientFn: func(c client.Sender) {
				setterCalledCount++
			}}

			originalCfg := &configuration.Configuration{
				Fleet: &configuration.FleetAgentConfig{
					Server: &configuration.FleetServerConfig{
						Host: fleetServerHost,
						Port: uint16(fleetServerPort),
					},
					AccessAPIKey: "ignore",
					Client: remote.Config{
						Transport: httpcommon.HTTPTransportSettings{
							Proxy: httpcommon.HTTPClientProxySettings{
								URL: &httpcommon.ProxyURI{
									Host: "original.proxy",
								},
							}}},
				},
				Settings: configuration.DefaultSettingsConfig()}

			h := PolicyChangeHandler{
				agentInfo:            &info.AgentInfo{},
				config:               originalCfg,
				store:                &storage.NullStore{},
				setters:              []actions.ClientSetter{&setter},
				log:                  log,
				policyLogLevelSetter: nilLogLevelSet(t),
			}

			cfg := config.MustNewConfigFrom(
				map[string]interface{}{
					"fleet.proxy_url": mockProxy.URL,
					"fleet.host":      fleetServer.URL})

			err := h.handlePolicyChange(context.Background(), cfg)
			require.NoError(t, err)

			assert.Equal(t, 1, setterCalledCount)
			assert.Equal(t,
				mockProxy.URL,
				h.config.Fleet.Client.Transport.Proxy.URL.String())
		})

		t.Run("empty proxy don't change the fleet client",
			func(t *testing.T) {
				wantProxy := mockProxy.URL

				log, _ := loggertest.New("TestPolicyChangeHandler")
				var setterCalledCount int
				setter := testSetter{SetClientFn: func(c client.Sender) {
					setterCalledCount++
				}}

				mockProxyURL, err := url.Parse(mockProxy.URL)
				require.NoError(t, err)

				tmpMockProxyURI := httpcommon.ProxyURI(*mockProxyURL)
				mockProxyURI := &tmpMockProxyURI
				originalCfg := &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Server: &configuration.FleetServerConfig{
							Host: fleetServerHost,
							Port: uint16(fleetServerPort),
						},
						AccessAPIKey: "ignore",
						Client: remote.Config{
							Host: fleetServerHost,
							Transport: httpcommon.HTTPTransportSettings{
								Proxy: httpcommon.HTTPClientProxySettings{
									URL: mockProxyURI,
								}}},
					},
					Settings: configuration.DefaultSettingsConfig()}

				h := PolicyChangeHandler{
					agentInfo:            &info.AgentInfo{},
					config:               originalCfg,
					store:                &storage.NullStore{},
					setters:              []actions.ClientSetter{&setter},
					log:                  log,
					policyLogLevelSetter: nilLogLevelSet(t),
				}

				cfg := config.MustNewConfigFrom(
					map[string]interface{}{
						"fleet.proxy_url": "",
						"fleet.host":      fleetServer.URL})

				err = h.handlePolicyChange(context.Background(), cfg)
				require.NoError(t, err)

				assert.Equal(t, 1, setterCalledCount)
				assert.Equal(t,
					wantProxy,
					h.config.Fleet.Client.Transport.Proxy.URL.String())
			})
	})

	t.Run("Bad http status from new fleet host does not change remote config", func(t *testing.T) {
		badStatusCodes := []int{http.StatusInternalServerError, http.StatusNotFound}
		for _, httpStatusCode := range badStatusCodes {
			t.Run(fmt.Sprintf("HTTP %d", httpStatusCode), func(t *testing.T) {
				alwaysErroringServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(httpStatusCode)
					_, err := w.Write(nil)
					require.NoError(t, err)
				}))
				defer alwaysErroringServer.Close()

				log, _ := loggertest.New("TestPolicyChangeHandler")
				var setterCalledCount int
				setter := testSetter{SetClientFn: func(c client.Sender) {
					setterCalledCount++
				}}

				originalCfg := &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Server: &configuration.FleetServerConfig{
							Host: fleetServerHost,
							Port: uint16(fleetServerPort),
						},
						AccessAPIKey: "ignore",
						Client: remote.Config{
							Transport: httpcommon.HTTPTransportSettings{
								Proxy: httpcommon.HTTPClientProxySettings{
									URL: nil,
								}}},
					},
					Settings: configuration.DefaultSettingsConfig()}

				h := PolicyChangeHandler{
					agentInfo:            &info.AgentInfo{},
					config:               originalCfg,
					store:                &storage.NullStore{},
					setters:              []actions.ClientSetter{&setter},
					log:                  log,
					policyLogLevelSetter: mockhandlers.NewLogLevelSetter(t),
				}

				cfg := config.MustNewConfigFrom(
					map[string]interface{}{
						"fleet.proxy_url": "",
						"fleet.hosts":     []string{alwaysErroringServer.URL},
					})

				err = h.handlePolicyChange(context.Background(), cfg)
				if assert.Error(t, err, "action policy change handler should return an error if new fleet server sends back a bad status code") {
					// check that we have the correct error contents
					assert.ErrorContains(t, err, fmt.Sprintf("fleet server ping returned a bad status code: %d", httpStatusCode))
				}

				assert.Equal(t, 0, setterCalledCount, "client setter should nopt have been called as the new policy was invalid")
				assert.Equal(t, fleetServerHost, h.config.Fleet.Server.Host, "fleet server host should be unchanged since new policy has been rejected")
			})
		}
	})

	t.Run("policy with SSL config", func(t *testing.T) {
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
		}{
			{
				name: "certificate_authorities is applied when present",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							Host: fleetNomTLSServer.URL,
						},
						AccessAPIKey: "ignore",
					},
					Settings: configuration.DefaultSettingsConfig(),
				},
				newCfg: map[string]interface{}{
					"fleet.ssl.enabled":                 true,
					"fleet.ssl.certificate_authorities": []string{string(fleetRootPair.Cert)},
				},
				setterCalledCount: 1,
				wantCAs:           []string{string(fleetRootPair.Cert)},
				assertErr: func(t *testing.T, err error) {
					assert.NoError(t, err,
						"unexpected error when applying fleet.ssl.certificate_authorities")
				},
			},
			{
				name: "certificate_authorities is ignored if empty",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							// To the reviewers: this testcase was using the mTLS fleet server in the original PR
							// https://github.com/elastic/elastic-agent/pull/4398/files#diff-09ced2f2269134a71e037d9fb1bd4a2f4a157c472f45c601b74b71ce5179d04fR491
							// but there is no way for it to work without a certificate, switched it to TLS fleet server ¯\_(ツ)_/¯
							Host: fleetNomTLSServer.URL,
							Transport: httpcommon.HTTPTransportSettings{
								TLS: &tlscommon.Config{CAs: []string{string(fleetRootPair.Cert)}},
							},
						},
						AccessAPIKey: "ignore",
					},
					Settings: configuration.DefaultSettingsConfig(),
				},
				newCfg: map[string]interface{}{
					// changing the URL for a server without TLS, so it'll
					// work without the CA.
					"fleet.host":                        fleetServer.URL,
					"fleet.ssl.enabled":                 true,
					"fleet.ssl.certificate_authorities": []string{},
				},
				setterCalledCount: 1,
				wantCAs:           []string{string(fleetRootPair.Cert)},
				assertErr: func(t *testing.T, err error) {
					assert.NoError(t, err,
						"unexpected error when applying fleet.ssl.certificate_authorities")
				},
			},
			{
				name: "certificate_authorities is ignored if absent",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							Host: fleetNomTLSServer.URL,
							Transport: httpcommon.HTTPTransportSettings{
								TLS: &tlscommon.Config{CAs: []string{string(fleetRootPair.Cert)}},
							},
						},
						AccessAPIKey: "ignore",
					},
					Settings: configuration.DefaultSettingsConfig(),
				},
				newCfg: map[string]interface{}{
					"fleet.ssl.enabled": true,
				},
				setterCalledCount: 1, // it should not exit early
				wantCAs:           []string{string(fleetRootPair.Cert)},
				assertErr: func(t *testing.T, err error) {
					assert.NoError(t, err,
						"unexpected error when applying fleet.ssl.certificate_authorities")
				},
			},
			{
				name: "certificate_authorities isn't applied if wrong",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							Host: fleetNomTLSServer.URL,
							Transport: httpcommon.HTTPTransportSettings{
								TLS: &tlscommon.Config{
									Enabled: &trueVar,
									CAs:     []string{string(fleetRootPair.Cert)}},
							},
						},
						AccessAPIKey: "ignore",
					},
					Settings: configuration.DefaultSettingsConfig(),
				},
				newCfg: map[string]interface{}{
					"fleet.ssl.enabled":                 true,
					"fleet.ssl.certificate_authorities": []string{string(wrongRootPair.Cert)},
				},
				setterCalledCount: 0,
				wantCAs:           []string{string(fleetRootPair.Cert)},
				assertErr: func(t *testing.T, err error) {
					assert.Error(t, err,
						"bad fleet.ssl.certificate_authorities provided, it should have returned an error")
				},
				customLogLevelSetterMock: func(t *testing.T) *mockhandlers.LogLevelSetter {
					// We don't expect any log level to be set if config is wrong
					return mockhandlers.NewLogLevelSetter(t)
				},
			},
			{
				name: "certificate and key is applied when present",
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
					"fleet.ssl.enabled":     true,
					"fleet.ssl.certificate": string(agentChildPair.Cert),
					"fleet.ssl.key":         string(agentChildPair.Key),
				},
				setterCalledCount: 1,
				wantCAs:           []string{string(fleetRootPair.Cert)},
				wantCertificateConfig: tlscommon.CertificateConfig{
					Certificate: string(agentChildPair.Cert),
					Key:         string(agentChildPair.Key),
				},
				assertErr: func(t *testing.T, err error) {
					assert.NoError(t, err,
						"unexpected error when applying fleet.ssl.certificate and key")
				},
			},
			{
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
			},
			{
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
			{
				name: "certificate and key is ignored if empty",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							Host: fleetmTLSServer.URL,
							Transport: httpcommon.HTTPTransportSettings{
								TLS: &tlscommon.Config{
									CAs: []string{string(fleetRootPair.Cert)},
									Certificate: tlscommon.CertificateConfig{
										Certificate: string(agentChildPair.Cert),
										Key:         string(agentChildPair.Key),
									},
								},
							},
						},
						AccessAPIKey: "ignore",
					},
					Settings: configuration.DefaultSettingsConfig(),
				},
				newCfg: map[string]interface{}{
					"fleet.ssl.enabled":     true,
					"fleet.ssl.certificate": "",
					"fleet.ssl.key":         "",
				},
				setterCalledCount: 1,
				wantCAs:           []string{string(fleetRootPair.Cert)},
				wantCertificateConfig: tlscommon.CertificateConfig{
					Certificate: string(agentChildPair.Cert),
					Key:         string(agentChildPair.Key),
				},
				assertErr: func(t *testing.T, err error) {
					assert.NoError(t, err,
						"unexpected error when applying fleet.ssl.certificate and key")
				},
			},
			{
				name: "certificate and key is ignored if absent",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							Host: fleetmTLSServer.URL,
							Transport: httpcommon.HTTPTransportSettings{
								TLS: &tlscommon.Config{
									CAs: []string{string(fleetRootPair.Cert)},
									Certificate: tlscommon.CertificateConfig{
										Certificate: string(agentChildPair.Cert),
										Key:         string(agentChildPair.Key),
									},
								},
							},
						},
						AccessAPIKey: "ignore",
					},
					Settings: configuration.DefaultSettingsConfig(),
				},
				newCfg:            map[string]interface{}{},
				setterCalledCount: 0,
				wantCAs:           []string{string(fleetRootPair.Cert)},
				wantCertificateConfig: tlscommon.CertificateConfig{
					Certificate: string(agentChildPair.Cert),
					Key:         string(agentChildPair.Key),
				},
				assertErr: func(t *testing.T, err error) {
					assert.NoError(t, err,
						"unexpected error when applying fleet.ssl.certificate and key")
				},
			},
			{
				name: "certificate and key isn't applied if wrong",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							Host: fleetmTLSServer.URL,
							Transport: httpcommon.HTTPTransportSettings{
								TLS: &tlscommon.Config{
									CAs: []string{string(fleetRootPair.Cert)},
									Certificate: tlscommon.CertificateConfig{
										Certificate: string(agentChildPair.Cert),
										Key:         string(agentChildPair.Key),
									},
								},
							},
						},
						AccessAPIKey: "ignore",
					},
					Settings: configuration.DefaultSettingsConfig(),
				},
				newCfg: map[string]interface{}{
					"fleet.ssl.enabled":     true,
					"fleet.ssl.certificate": string(wrongChildPair.Cert),
					"fleet.ssl.key":         string(wrongChildPair.Key),
				},
				setterCalledCount: 0,
				wantCAs:           []string{string(fleetRootPair.Cert)},
				wantCertificateConfig: tlscommon.CertificateConfig{
					Certificate: string(agentChildPair.Cert),
					Key:         string(agentChildPair.Key),
				},
				assertErr: func(t *testing.T, err error) {
					assert.Error(t, err,
						"wrong fleet.ssl.certificate and key should cause an error")
				},
				customLogLevelSetterMock: func(t *testing.T) *mockhandlers.LogLevelSetter {
					// We don't expect any log level to be set if config is wrong
					return mockhandlers.NewLogLevelSetter(t)
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
	})
}

type testAcker struct {
	acked     []string
	ackedLock sync.Mutex
}

func (t *testAcker) Ack(_ context.Context, action fleetapi.Action) error {
	t.ackedLock.Lock()
	defer t.ackedLock.Unlock()

	if t.acked == nil {
		t.acked = make([]string, 0)
	}

	t.acked = append(t.acked, action.ID())
	return nil
}

func (t *testAcker) Commit(_ context.Context) error {
	return nil
}

func (t *testAcker) Clear() {
	t.ackedLock.Lock()
	defer t.ackedLock.Unlock()

	t.acked = make([]string, 0)
}

func (t *testAcker) Items() []string {
	t.ackedLock.Lock()
	defer t.ackedLock.Unlock()
	return t.acked
}

type testSetter struct {
	SetClientFn func(c client.Sender)
}

func (s *testSetter) SetClient(c client.Sender) {
	s.SetClientFn(c)
}

func TestPolicyChangeHandler_handlePolicyChange_LogLevelSet(t *testing.T) {

	matchLogLevel := func(expectedLevel logger.Level) func(*logger.Level) bool {
		return func(level *logger.Level) bool {
			if level == nil {
				return false
			}
			return expectedLevel == *level
		}
	}

	type args struct {
		c map[string]any
	}
	tests := []struct {
		name              string
		args              args
		setupExpectations func(setter *mockhandlers.LogLevelSetter)
		wantErr           assert.ErrorAssertionFunc
	}{
		{
			name: "set debug log level from policy",
			args: args{
				c: map[string]interface{}{
					"agent.logging.level": "debug",
				},
			},
			setupExpectations: func(setter *mockhandlers.LogLevelSetter) {
				setter.EXPECT().SetLogLevel(mock.Anything, mock.MatchedBy(matchLogLevel(logp.DebugLevel))).Return(nil).Once()
			},
			wantErr: assert.NoError,
		},
		{
			name: "set info log level from policy",
			args: args{
				c: map[string]interface{}{
					"agent.logging.level": "info",
				},
			},
			setupExpectations: func(setter *mockhandlers.LogLevelSetter) {
				setter.EXPECT().
					SetLogLevel(mock.Anything, mock.MatchedBy(matchLogLevel(logp.InfoLevel))).
					Return(nil).Once()
			},
			wantErr: assert.NoError,
		},
		{
			name: "set warning log level from policy",
			args: args{
				c: map[string]interface{}{
					"agent.logging.level": "warning",
				},
			},
			setupExpectations: func(setter *mockhandlers.LogLevelSetter) {
				setter.EXPECT().
					SetLogLevel(mock.Anything, mock.MatchedBy(matchLogLevel(logp.WarnLevel))).
					Return(nil).Once()
			},
			wantErr: assert.NoError,
		},
		{
			name: "set error log level from policy",
			args: args{
				c: map[string]interface{}{
					"agent.logging.level": "error",
				},
			},
			setupExpectations: func(setter *mockhandlers.LogLevelSetter) {
				setter.EXPECT().
					SetLogLevel(mock.Anything, mock.MatchedBy(matchLogLevel(logp.ErrorLevel))).
					Return(nil).Once()
			},
			wantErr: assert.NoError,
		},
		{
			name: "set critical log level from policy",
			args: args{
				c: map[string]interface{}{
					"agent.logging.level": "critical",
				},
			},
			setupExpectations: func(setter *mockhandlers.LogLevelSetter) {
				setter.EXPECT().
					SetLogLevel(mock.Anything, mock.MatchedBy(matchLogLevel(logp.CriticalLevel))).
					Return(nil).Once()
			},
			wantErr: assert.NoError,
		},
		{
			name: "Error: Wrong log level error in policy",
			args: args{
				c: map[string]interface{}{
					"agent.logging.level": "asdasd",
				},
			},
			// don't set any expectations on the LogLevelSetter mock because we don't expect any calls
			setupExpectations: nil,
			wantErr:           assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			log, _ := loggertest.New(tt.name)
			mockLogLevelSetter := mockhandlers.NewLogLevelSetter(t)

			if tt.setupExpectations != nil {
				tt.setupExpectations(mockLogLevelSetter)
			}

			h := &PolicyChangeHandler{
				log:                  log,
				agentInfo:            &info.AgentInfo{},
				config:               configuration.DefaultConfiguration(),
				store:                &storage.NullStore{},
				policyLogLevelSetter: mockLogLevelSetter,
			}

			tt.wantErr(t, h.handlePolicyChange(context.Background(), config.MustNewConfigFrom(tt.args.c)), fmt.Sprintf("handlePolicyChange(ctx, %v)", tt.args.c))
		})
	}
}

func nilLogLevelSet(t *testing.T) *mockhandlers.LogLevelSetter {
	// nilLogLevel is a variable used to match nil policy log level being set
	var nilLogLevel *logger.Level = nil

	logLevelSetter := mockhandlers.NewLogLevelSetter(t)
	logLevelSetter.EXPECT().SetLogLevel(mock.Anything, nilLogLevel).Return(nil).Once()
	return logLevelSetter
}
