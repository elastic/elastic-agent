// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
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
			Policy:     conf,
		}

		cfg := configuration.DefaultConfiguration()

		handler := NewPolicyChangeHandler(log, agentInfo, cfg, nullStore, ch, noLogLevelSet(t))

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
		handler := NewPolicyChangeHandler(log, agentInfo, cfg, nullStore, ch, noLogLevelSet(t))

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
				Settings: configuration.DefaultSettingsConfig(),
			}

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
			agentInfo:            &info.AgentInfo{},
			config:               originalCfg,
			store:                &storage.NullStore{},
			setters:              []actions.ClientSetter{&setter},
			log:                  log,
			policyLogLevelSetter: noLogLevelSet(t),
		}

		cfg := config.MustNewConfigFrom(
			map[string]interface{}{
				"fleet.host": fleetServer.URL})

		err := h.handlePolicyChange(context.Background(), cfg)
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
			agentInfo:            &info.AgentInfo{},
			config:               originalCfg,
			store:                &storage.NullStore{},
			setters:              []actions.ClientSetter{&setter},
			log:                  log,
			policyLogLevelSetter: noLogLevelSet(t),
		}

		wantHosts := []string{fleetServer.URL, fleetServer.URL}
		cfg := config.MustNewConfigFrom(
			map[string]interface{}{
				"fleet.hosts": wantHosts})

		err := h.handlePolicyChange(context.Background(), cfg)
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
			agentInfo:            &info.AgentInfo{},
			config:               originalCfg,
			store:                &storage.NullStore{},
			setters:              []actions.ClientSetter{&setter},
			log:                  log,
			policyLogLevelSetter: noLogLevelSet(t),
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
				agentInfo:            &info.AgentInfo{},
				config:               originalCfg,
				store:                &storage.NullStore{},
				setters:              []actions.ClientSetter{&setter},
				log:                  log,
				policyLogLevelSetter: noLogLevelSet(t),
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

			log, _ := logger.NewTesting(tt.name)
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

func noLogLevelSet(t *testing.T) *mockhandlers.LogLevelSetter {
	// nilLogLevel is a variable used to match nil policy log level being set
	var nilLogLevel *logger.Level = nil

	logLevelSetter := mockhandlers.NewLogLevelSetter(t)
	logLevelSetter.EXPECT().SetLogLevel(mock.Anything, nilLogLevel).Return(nil).Once()
	return logLevelSetter
}
