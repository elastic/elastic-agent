// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
			Policy:     conf,
		}

		cfg := configuration.DefaultConfiguration()
		handler := NewPolicyChangeHandler(log, agentInfo, cfg, nullStore, ch)

		err := handler.Handle(context.Background(), action, ack)
		require.NoError(t, err)

		change := <-ch
		require.Equal(t, config.MustNewConfigFrom(conf), change.Config())
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
			Policy:     config,
		}

		cfg := configuration.DefaultConfiguration()
		handler := NewPolicyChangeHandler(log, agentInfo, cfg, nullStore, ch)

		err := handler.Handle(context.Background(), action, tacker)
		require.NoError(t, err)

		change := <-ch
		require.NoError(t, change.Ack())

		actions := tacker.Items()
		assert.EqualValues(t, 1, len(actions))
		assert.Equal(t, actionID, actions[0])
	})
}

func TestPolicyChangeHandler_handleFleetServerHosts(t *testing.T) {
	mockProxy := httptest.NewServer(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, err := w.Write(nil)
			require.NoError(t, err)
		}))

	fleetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "api/status" {
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

	t.Run("Rollback client changes when cannot create client",
		func(t *testing.T) {
			log, _ := logger.NewTesting("TestPolicyChangeHandler")
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
				agentInfo: &info.AgentInfo{},
				config:    originalCfg,
				store:     &storage.NullStore{},
				setters:   []actions.ClientSetter{&setter},
				log:       log,
			}

			cfg := config.MustNewConfigFrom(
				map[string]interface{}{
					"fleet.host":      "http://some.url",
					"fleet.proxy_url": "http://some.proxy",
				})

			err := h.handleFleetServerConfig(context.Background(), cfg)
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

	t.Run("Rollback client changes when cannot reach fleet-server",
		func(t *testing.T) {
			log, _ := logger.NewTesting("TestPolicyChangeHandler")
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
				agentInfo: &info.AgentInfo{},
				config:    originalCfg,
				store:     &storage.NullStore{},
				setters:   []actions.ClientSetter{&setter},
				log:       log,
			}

			cfg := config.MustNewConfigFrom(
				map[string]interface{}{
					"fleet.host":      "http://some.url",
					"fleet.proxy_url": "http://some.proxy",
				})

			err := h.handleFleetServerConfig(context.Background(), cfg)
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

	t.Run("A policy with a new Host and no proxy changes the Host", func(t *testing.T) {
		log, _ := logger.NewTesting("TestPolicyChangeHandler")
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
					Host: "http://example.co"},
			},
			Settings: configuration.DefaultSettingsConfig()}

		h := PolicyChangeHandler{
			agentInfo: &info.AgentInfo{},
			config:    originalCfg,
			store:     &storage.NullStore{},
			setters:   []actions.ClientSetter{&setter},
			log:       log,
		}

		cfg := config.MustNewConfigFrom(
			map[string]interface{}{
				"fleet.host": fleetServer.URL})

		err := h.handleFleetServerConfig(context.Background(), cfg)
		require.NoError(t, err)

		assert.Equal(t, 1, setterCalledCount)
		assert.Equal(t, fleetServer.URL, h.config.Fleet.Client.Host)
		assert.Empty(t,
			h.config.Fleet.Client.Transport.Proxy.URL)
	})

	t.Run("A policy with proxy changes the fleet client", func(t *testing.T) {
		log, _ := logger.NewTesting("TestPolicyChangeHandler")
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
			agentInfo: &info.AgentInfo{},
			config:    originalCfg,
			store:     &storage.NullStore{},
			setters:   []actions.ClientSetter{&setter},
			log:       log,
		}

		cfg := config.MustNewConfigFrom(
			map[string]interface{}{
				"fleet.proxy_url": mockProxy.URL,
				"fleet.host":      fleetServer.URL})

		err := h.handleFleetServerConfig(context.Background(), cfg)
		require.NoError(t, err)

		assert.Equal(t, 1, setterCalledCount)
		assert.Equal(t,
			mockProxy.URL,
			h.config.Fleet.Client.Transport.Proxy.URL.String())
	})

	t.Run("A policy with empty proxy don't change the fleet client",
		func(t *testing.T) {
			wantProxy := mockProxy.URL

			log, _ := logger.NewTesting("TestPolicyChangeHandler")
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
				agentInfo: &info.AgentInfo{},
				config:    originalCfg,
				store:     &storage.NullStore{},
				setters:   []actions.ClientSetter{&setter},
				log:       log,
			}

			cfg := config.MustNewConfigFrom(
				map[string]interface{}{
					"fleet.proxy_url": "",
					"fleet.host":      fleetServer.URL})

			err = h.handleFleetServerConfig(context.Background(), cfg)
			require.NoError(t, err)

			assert.Equal(t, 1, setterCalledCount)
			assert.Equal(t,
				wantProxy,
				h.config.Fleet.Client.Transport.Proxy.URL.String())
		})

	t.Run("policy with SSL config", func(t *testing.T) {
		// TODO: make sure the ssl config is applied when it needs:
		//  - if there is SSL config and an empty one comes?
		//  - any invalid config isn't applied

		fleetRootPair, fleetChildPair, err := certutil.NewRootAndChildCerts()
		require.NoError(t, err, "failed creating fleet root and child certs")

		wrongRootPair, _, err := certutil.NewRootAndChildCerts()
		require.NoError(t, err, "failed creating root and child certs")

		// agentRootPair, agentChildPair, err := certutil.NewRootAndChildCerts()
		// require.NoError(t, err, "failed creating agent root and child certs")

		fleetTLSServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "api/status" {
				w.WriteHeader(http.StatusNotFound)
				_, err := w.Write(nil)
				require.NoError(t, err)
			}
			_, err := w.Write(nil)
			require.NoError(t, err)
		}))

		rootCertPool := x509.NewCertPool()
		rootCertPool.AppendCertsFromPEM(fleetRootPair.Cert)
		cert, err := tls.X509KeyPair(fleetChildPair.Cert, fleetChildPair.Key)
		require.NoError(t, err, "could not create tls.Certificates from child certificate")

		fleetTLSServer.TLS = &tls.Config{
			RootCAs:      rootCertPool,
			Certificates: []tls.Certificate{cert},
		}

		fleetTLSServer.StartTLS()
		defer mockProxy.Close()
		defer fleetTLSServer.Close()
		trueVar := true
		tcs := []struct {
			name              string
			originalCfg       *configuration.Configuration
			newCfg            map[string]interface{}
			setterCalledCount int
			wantCAs           []string
			assertErr         func(t *testing.T, err error)
		}{
			{
				name: "fleet.ssl.certificate_authorities is applied",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							Host: fleetTLSServer.URL,
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
				name: "empty fleet.ssl.certificate_authorities is applied",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							Host: fleetServer.URL,
							Transport: httpcommon.HTTPTransportSettings{
								TLS: &tlscommon.Config{CAs: []string{string(fleetRootPair.Cert)}},
							},
						},
						AccessAPIKey: "ignore",
					},
					Settings: configuration.DefaultSettingsConfig(),
				},
				newCfg: map[string]interface{}{
					"fleet.ssl.enabled":                 true,
					"fleet.ssl.certificate_authorities": []string{},
				},
				setterCalledCount: 1,
				wantCAs:           []string{},
				assertErr: func(t *testing.T, err error) {
					assert.NoError(t, err,
						"unexpected error when applying fleet.ssl.certificate_authorities")
				},
			},
			{
				name: "an absent fleet.ssl.certificate_authorities is ignored",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							Host: fleetTLSServer.URL,
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
				name: "a wrong fleet.ssl.certificate_authorities is ignored",
				originalCfg: &configuration.Configuration{
					Fleet: &configuration.FleetAgentConfig{
						Client: remote.Config{
							Host: fleetTLSServer.URL,
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
			},
		}

		for _, tc := range tcs {
			t.Run(tc.name, func(t *testing.T) {
				log, logs := logger.NewTesting("")
				defer func() {
					if t.Failed() {
						t.Log(logs.All())
					}
				}()

				var setterCalledCount int
				setter := testSetter{SetClientFn: func(c client.Sender) {
					setterCalledCount++
				}}
				h := PolicyChangeHandler{
					agentInfo: &info.AgentInfo{},
					config:    tc.originalCfg,
					store:     &storage.NullStore{},
					setters:   []actions.ClientSetter{&setter},
					log:       log,
				}

				cfg := config.MustNewConfigFrom(tc.newCfg)

				err := h.handleFleetServerConfig(context.Background(), cfg)
				tc.assertErr(t, err)

				assert.Equal(t, tc.setterCalledCount, setterCalledCount,
					"setter was not called")
				assert.Equal(t,
					tc.wantCAs, h.config.Fleet.Client.Transport.TLS.CAs,
					"unexpected CAs")
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
