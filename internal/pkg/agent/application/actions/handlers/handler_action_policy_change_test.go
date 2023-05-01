// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/actions"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/protection"
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
	agentInfo, _ := info.NewAgentInfo(true)
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

	t.Run("Receive a signed policy configuration", func(t *testing.T) {
		ch := make(chan coordinator.ConfigChange, 1)
		const goodData = "eyJpZCI6ImY2ODMzNDQwLWU1ZDItMTFlZC04MDdkLTU5NTZmZDg3YjhjMSIsImFnZW50Ijp7InByb3RlY3Rpb24iOnsiZW5hYmxlZCI6ZmFsc2UsInVuaW5zdGFsbF90b2tlbl9oYXNoIjoiIiwic2lnbmluZ19rZXkiOiJNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV1YWFra2drT1FsVmg3OFVPWnVUOGZPY29jSU1YQXAwMWF6WDVaSzRMa0xpTWU4QmpFTlRGL3RUOHJmM25sdTVtcUJ2bGVQYy9JSk1YTVlpTjVZSm80QT09In19fQ=="
		conf := map[string]interface{}{
			"id": "f6833440-e5d2-11ed-807d-5956fd87b8c1",
			"agent": map[string]interface{}{
				"protection": map[string]interface{}{
					"enabled":              false,
					"uninstall_token_hash": "EuaakkgkOQlVh78UOZuT8fOco",
					"signing_key":          "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuaakkgkOQlVh78UOZuT8fOcocIMXAp01azX5ZK4LkLiMe8BjENTF/tT8rf3nlu5mqBvlePc/IJMXMYiN5YJo4A==",
				},
			},
			"signed": map[string]interface{}{
				"data":      goodData,
				"signature": "MEUCIAHcG2RmW3Ppal9LaY6BEPyUBEUFKpK+Zpzy6+0FK6bCAiEA9KCHBUeI94SHyIvBL5Y3hLJcOgTinZm34T6LO0Ud7d0=",
			},
		}
		action := &fleetapi.ActionPolicyChange{
			ActionID:   "abc123",
			ActionType: "POLICY_CHANGE",
			Policy:     conf,
		}

		cfg := configuration.DefaultConfiguration()
		handler := NewPolicyChangeHandler(log, agentInfo, cfg, nullStore, ch)

		handleAction := func(action *fleetapi.ActionPolicyChange) (map[string]interface{}, error) {
			err := handler.Handle(context.Background(), action, ack)
			if err != nil {
				return nil, err
			}

			change := <-ch
			return change.Config().ToMapStr()
		}

		// First ever config change is trusted, can't be validated
		m, err := handleAction(action)
		require.NoError(t, err)
		require.Equal(t, conf, m)

		// Second config change should be validated successfully
		m, err = handleAction(action)
		require.NoError(t, err)
		require.Equal(t, conf, m)

		// Non matching policy id should fail
		action.Policy["id"] = "a6833440-e5d2-11ed-807d-5956fd87b8c2"
		_, err = handleAction(action)
		require.ErrorIs(t, err, protection.ErrMismatchedPolicyID)

		// Missing policy id should fail
		delete(action.Policy, "id")
		_, err = handleAction(action)
		require.ErrorIs(t, err, protection.ErrMissingPolicyID)

		// Corrupted signed data should fail
		signed := conf["signed"].(map[string]interface{})
		signed["data"] = "eyJpZCI6ImY2ODMzNDQwLWU1ZDIt"
		_, err = handleAction(action)
		require.ErrorIs(t, err, protection.ErrInvalidSignature)
	})
}

func TestPolicyAcked(t *testing.T) {
	log, _ := logger.New("", false)
	agentInfo, _ := info.NewAgentInfo(true)
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

			err := h.handleFleetServerHosts(context.Background(), cfg)
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

			err := h.handleFleetServerHosts(context.Background(), cfg)
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

		err := h.handleFleetServerHosts(context.Background(), cfg)
		require.NoError(t, err)

		assert.Equal(t, 1, setterCalledCount)
		assert.Equal(t, fleetServer.URL, h.config.Fleet.Client.Host)
		assert.Empty(t,
			h.config.Fleet.Client.Transport.Proxy.URL)
	})

	t.Run("A policy with new Hosts and no proxy changes the Hosts", func(t *testing.T) {
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

		wantHosts := []string{fleetServer.URL, fleetServer.URL}
		cfg := config.MustNewConfigFrom(
			map[string]interface{}{
				"fleet.hosts": wantHosts})

		err := h.handleFleetServerHosts(context.Background(), cfg)
		require.NoError(t, err)

		assert.Equal(t, 1, setterCalledCount)
		assert.Equal(t, wantHosts, h.config.Fleet.Client.Hosts)
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

		err := h.handleFleetServerHosts(context.Background(), cfg)
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

			err = h.handleFleetServerHosts(context.Background(), cfg)
			require.NoError(t, err)

			assert.Equal(t, 1, setterCalledCount)
			assert.Equal(t,
				wantProxy,
				h.config.Fleet.Client.Transport.Proxy.URL.String())
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
