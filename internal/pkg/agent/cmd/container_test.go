// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/kibana"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/crypto"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func TestEnvWithDefault(t *testing.T) {
	def := "default"
	key1 := "ENV_WITH_DEFAULT_1"
	key2 := "ENV_WITH_DEFAULT_2"

	res := envWithDefault(def, key1, key2)

	require.Equal(t, def, res)

	t.Setenv(key1, "key1")

	t.Setenv(key2, "key2")

	res2 := envWithDefault(def, key1, key2)
	require.Equal(t, "key1", res2)
}

func TestEnvBool(t *testing.T) {
	key := "TEST_ENV_BOOL"

	t.Setenv(key, "true")

	res := envBool(key)
	require.True(t, res)
}

func TestEnvTimeout(t *testing.T) {
	key := "TEST_ENV_TIMEOUT"

	t.Setenv(key, "10s")

	res := envTimeout(key)
	require.Equal(t, time.Second*10, res)
}

func TestContainerTestPaths(t *testing.T) {
	cases := map[string]struct {
		config   string
		expected containerPaths
	}{
		"only_state_path": {
			config: `state_path: /foo/bar/state`,
			expected: containerPaths{
				StatePath:  "/foo/bar/state",
				ConfigPath: "",
				LogsPath:   "",
			},
		},
		"only_config_path": {
			config: `config_path: /foo/bar/config`,
			expected: containerPaths{
				StatePath:  "",
				ConfigPath: "/foo/bar/config",
				LogsPath:   "",
			},
		},
		"only_logs_path": {
			config: `logs_path: /foo/bar/logs`,
			expected: containerPaths{
				StatePath:  "",
				ConfigPath: "",
				LogsPath:   "/foo/bar/logs",
			},
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg, err := config.NewConfigFrom(c.config)
			require.NoError(t, err)

			var paths containerPaths
			err = cfg.UnpackTo(&paths)
			require.NoError(t, err)

			require.Equal(t, c.expected, paths)
		})
	}
}

func TestBuildEnrollArgs(t *testing.T) {
	cases := map[string]struct {
		cfg    setupConfig
		expect []string
		err    error
	}{
		"service token passes": {
			cfg: setupConfig{
				FleetServer: fleetServerConfig{
					Enable: true,
					Elasticsearch: elasticsearchConfig{
						Host:         "http://localhost:9200",
						ServiceToken: "token-val",
					},
				},
			},
			expect: []string{"--fleet-server-service-token", "token-val"},
			err:    nil,
		},
		"service token path passes": {
			cfg: setupConfig{
				FleetServer: fleetServerConfig{
					Enable: true,
					Elasticsearch: elasticsearchConfig{
						Host:             "http://localhost:9200",
						ServiceTokenPath: "/path/to/token",
					},
				},
			},
			expect: []string{"--fleet-server-service-token-path", "/path/to/token"},
			err:    nil,
		},
		"service token path preferred": {
			cfg: setupConfig{
				FleetServer: fleetServerConfig{
					Enable: true,
					Elasticsearch: elasticsearchConfig{
						Host:             "http://localhost:9200",
						ServiceTokenPath: "/path/to/token",
						ServiceToken:     "token-val",
					},
				},
			},
			expect: []string{"--fleet-server-service-token-path", "/path/to/token"},
			err:    nil,
		},
		"mTLS flags": {
			cfg: setupConfig{
				Fleet: fleetConfig{
					Cert:    "/path/to/agent.crt",
					CertKey: "/path/to/agent.key",
				},
				FleetServer: fleetServerConfig{
					Enable:     true,
					ClientAuth: "optional",
					Elasticsearch: elasticsearchConfig{
						Cert:    "/path/to/es.crt",
						CertKey: "/path/to/es.key",
					},
				},
			},
			expect: []string{"--fleet-server-es-cert", "/path/to/es.crt", "--fleet-server-es-cert-key", "/path/to/es.key", "--fleet-server-client-auth", "optional", "--elastic-agent-cert", "/path/to/agent.crt", "--elastic-agent-cert-key", "/path/to/agent.key"},
			err:    nil,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			args, err := buildEnrollArgs(tc.cfg, "", "")
			if tc.err != nil {
				require.EqualError(t, err, tc.err.Error())
			} else {
				require.NoError(t, err)
			}
			for _, arg := range tc.expect {
				require.Contains(t, args, arg)
			}
		})
	}
}

func TestShouldEnroll(t *testing.T) {
	// enroll token
	enrollmentToken := "test-enroll-token"
	enrollmentTokenHash, err := crypto.GeneratePBKDF2FromPassword([]byte(enrollmentToken))
	require.NoError(t, err)
	enrollmentTokenHashBase64 := base64.StdEncoding.EncodeToString(enrollmentTokenHash)
	enrollmentTokenOther := "test-enroll-token-other"

	// replace token
	replaceToken := "test-replace-token"
	replaceTokenHash, err := crypto.GeneratePBKDF2FromPassword([]byte(replaceToken))
	require.NoError(t, err)
	replaceTokenHashBase64 := base64.StdEncoding.EncodeToString(replaceTokenHash)
	replaceTokenOther := "test-replace-token-other"

	fleetNetworkErr := errors.New("fleet network error")
	for name, tc := range map[string]struct {
		cfg                  setupConfig
		statFn               func(path string) (os.FileInfo, error)
		encryptedDiskStoreFn func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage
		fleetClientFn        func(t *testing.T) client.Sender
		expectedSavedConfig  func(t *testing.T, savedConfig *configuration.Configuration)
		expectedShouldEnroll bool
		expectedErr          error
	}{
		"should not enroll if fleet enroll is disabled": {
			cfg:                  setupConfig{Fleet: fleetConfig{Enroll: false}},
			expectedShouldEnroll: false,
		},
		"should enroll if fleet force is true": {
			cfg:                  setupConfig{Fleet: fleetConfig{Enroll: true, Force: true}},
			expectedShouldEnroll: true,
		},
		"should enroll if config file does not exist": {
			statFn:               func(path string) (os.FileInfo, error) { return nil, os.ErrNotExist },
			cfg:                  setupConfig{Fleet: fleetConfig{Enroll: true, Force: true}},
			expectedShouldEnroll: true,
		},
		"should enroll on agent id but no existing id": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", ID: "diff-agent-id"}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  enrollment_token_hash: "test-hash"
  hosts:
    - host1
  agent:
  protocol: "https"`)), nil).Once()
				return m
			},
			expectedShouldEnroll: true,
		},
		"should enroll on agent id but diff agent id": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", ID: "diff-agent-id"}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  enrollment_token_hash: "test-hash"
  hosts:
    - host1
  agent:
    id: "agent-id"
  protocol: "https"`)), nil).Once()
				return m
			},
			expectedShouldEnroll: true,
		},
		"should enroll on fleet url change": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1"}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  enrollment_token_hash: "test-hash"
  hosts:
    - host2
    - host3
  agent:
  protocol: "https"`)), nil).Once()
				return m
			},
			expectedShouldEnroll: true,
		},
		"should enroll on fleet token change": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", EnrollmentToken: enrollmentTokenOther}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  enrollment_token_hash: "`+enrollmentTokenHashBase64+`"
  hosts:
    - host1
    - host2
    - host3
  agent:
  protocol: "https"`)), nil).Once()
				return m
			},
			expectedShouldEnroll: true,
		},
		"should enroll on replace token change": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", EnrollmentToken: enrollmentToken, ReplaceToken: replaceTokenOther}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  enrollment_token_hash: "`+enrollmentTokenHashBase64+`"
  replace_token_hash: "`+replaceTokenHashBase64+`"
  hosts:
    - host1
    - host2
    - host3
  agent:
  protocol: "https"`)), nil).Once()
				return m
			},
			expectedShouldEnroll: true,
		},
		"should enroll on unauthorized api": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", EnrollmentToken: enrollmentToken}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  enrollment_token_hash: "`+enrollmentTokenHashBase64+`"
  hosts:
    - host1
    - host2
    - host3
  agent:
  protocol: "https"`)), nil).Once()
				return m
			},
			fleetClientFn: func(t *testing.T) client.Sender {
				tries := 0
				m := client.NewMockSender(t)
				call := m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
				call.Run(func(args mock.Arguments) {
					if tries <= 1 {
						call.Return(nil, fleetNetworkErr)
					} else {
						call.Return(nil, client.ErrInvalidAPIKey)
					}
					tries++
				}).Times(3)
				return m
			},
			expectedShouldEnroll: true,
		},
		"should not enroll on no changes": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", EnrollmentToken: enrollmentToken}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  enrollment_token_hash: "`+enrollmentTokenHashBase64+`"
  hosts:
    - host1
    - host2
    - host3
  agent:
  protocol: "https"`)), nil).Once()
				return m
			},
			fleetClientFn: func(t *testing.T) client.Sender {
				tries := 0
				m := client.NewMockSender(t)
				call := m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
				call.Run(func(args mock.Arguments) {
					if tries <= 1 {
						call.Return(nil, fleetNetworkErr)
					} else {
						call.Return(&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{"action": "acks", "items":[]}`)),
						}, nil)
					}
					tries++
				}).Times(3)
				return m
			},
			expectedShouldEnroll: false,
		},
		"should not enroll on no changes with agent ID and replace token": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", ID: "custom-id", EnrollmentToken: enrollmentToken, ReplaceToken: replaceToken}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  enrollment_token_hash: "`+enrollmentTokenHashBase64+`"
  replace_token_hash: "`+replaceTokenHashBase64+`"
  hosts:
    - host1
    - host2
    - host3
  agent:
    id: "custom-id"
  protocol: "https"`)), nil).Once()
				return m
			},
			fleetClientFn: func(t *testing.T) client.Sender {
				tries := 0
				m := client.NewMockSender(t)
				call := m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything)
				call.Run(func(args mock.Arguments) {
					if tries <= 1 {
						call.Return(nil, fleetNetworkErr)
					} else {
						call.Return(&http.Response{
							StatusCode: http.StatusOK,
							Body:       io.NopCloser(strings.NewReader(`{"action": "acks", "items":[]}`)),
						}, nil)
					}
					tries++
				}).Times(3)
				return m
			},
			expectedShouldEnroll: false,
		},
		"should fail on fleet network errors": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", EnrollmentToken: enrollmentToken}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  enrollment_token_hash: "`+enrollmentTokenHashBase64+`"
  hosts:
    - host1
    - host2
    - host3
  agent:
  protocol: "https"`)), nil).Once()
				return m
			},
			fleetClientFn: func(t *testing.T) client.Sender {
				m := client.NewMockSender(t)
				m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(nil, fleetNetworkErr).Times(3)
				return m
			},
			expectedErr: fleetNetworkErr,
		},
		"should not update the enrollment token hash if it does not exist in setup configuration": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", EnrollmentToken: ""}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  hosts:
    - host1
    - host2
    - host3
  agent:
  protocol: "https"`)), nil).Once()
				return m
			},
			fleetClientFn: func(t *testing.T) client.Sender {
				m := client.NewMockSender(t)
				m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"action": "acks", "items":[]}`)),
					}, nil).Once()
				return m
			},
			expectedShouldEnroll: false,
		},
		"should not update the replace token hash if it does not exist in setup configuration": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", EnrollmentToken: "", ReplaceToken: ""}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  hosts:
    - host1
    - host2
    - host3
  agent:
  protocol: "https"`)), nil).Once()
				return m
			},
			fleetClientFn: func(t *testing.T) client.Sender {
				m := client.NewMockSender(t)
				m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"action": "acks", "items":[]}`)),
					}, nil).Once()
				return m
			},
			expectedShouldEnroll: false,
		},
		"should not enroll on no changes and update the stored enrollment token hash": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", EnrollmentToken: enrollmentToken}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  hosts:
    - host1
    - host2
    - host3
  agent:
  protocol: "https"`)), nil).Once()
				m.On("Save", mock.Anything).Run(func(args mock.Arguments) {
					reader := args.Get(0).(io.Reader)
					data, _ := io.ReadAll(reader)
					_ = yaml.Unmarshal(data, savedConfig)
				}).Return(nil).Times(0)
				return m
			},
			fleetClientFn: func(t *testing.T) client.Sender {
				m := client.NewMockSender(t)
				m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"action": "acks", "items":[]}`)),
					}, nil).Once()
				return m
			},
			expectedSavedConfig: func(t *testing.T, savedConfig *configuration.Configuration) {
				require.NotNil(t, savedConfig)
				require.NotNil(t, savedConfig.Fleet)
				enrollmentTokeHash, err := base64.StdEncoding.DecodeString(savedConfig.Fleet.EnrollmentTokenHash)
				require.NoError(t, err)
				require.NoError(t, crypto.ComparePBKDF2HashAndPassword(enrollmentTokeHash, []byte(enrollmentToken)))
			},
			expectedShouldEnroll: false,
		},
		"should not enroll on no changes and update the stored enrollment and replace token hash": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", EnrollmentToken: enrollmentToken, ReplaceToken: replaceToken}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := storage.NewMockStorage(t)
				m.On("Load").Return(io.NopCloser(strings.NewReader(`fleet:
  enabled: true
  access_api_key: "test-key"
  hosts:
    - host1
    - host2
    - host3
  agent:
  protocol: "https"`)), nil).Once()
				m.On("Save", mock.Anything).Run(func(args mock.Arguments) {
					reader := args.Get(0).(io.Reader)
					data, _ := io.ReadAll(reader)
					_ = yaml.Unmarshal(data, savedConfig)
				}).Return(nil).Times(0)
				return m
			},
			fleetClientFn: func(t *testing.T) client.Sender {
				m := client.NewMockSender(t)
				m.On("Send", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).
					Return(&http.Response{
						StatusCode: http.StatusOK,
						Body:       io.NopCloser(strings.NewReader(`{"action": "acks", "items":[]}`)),
					}, nil).Once()
				return m
			},
			expectedSavedConfig: func(t *testing.T, savedConfig *configuration.Configuration) {
				require.NotNil(t, savedConfig)
				require.NotNil(t, savedConfig.Fleet)
				enrollmentTokenHash, err := base64.StdEncoding.DecodeString(savedConfig.Fleet.EnrollmentTokenHash)
				require.NoError(t, err)
				require.NoError(t, crypto.ComparePBKDF2HashAndPassword(enrollmentTokenHash, []byte(enrollmentToken)))
				replaceTokenHash, err := base64.StdEncoding.DecodeString(savedConfig.Fleet.ReplaceTokenHash)
				require.NoError(t, err)
				require.NoError(t, crypto.ComparePBKDF2HashAndPassword(replaceTokenHash, []byte(replaceToken)))
			},
			expectedShouldEnroll: false,
		},
	} {
		t.Run(name, func(t *testing.T) {
			savedConfig := &configuration.Configuration{}
			if tc.statFn != nil {
				oldStatFn := statAgentConfigFile
				statAgentConfigFile = tc.statFn
				t.Cleanup(func() {
					statAgentConfigFile = oldStatFn
				})
			}
			if tc.encryptedDiskStoreFn != nil {
				oldEncryptedDiskStore := newEncryptedDiskStore
				newEncryptedDiskStore = func(ctx context.Context, target string, opts ...storage.EncryptedOptionFunc) (storage.Storage, error) {
					return tc.encryptedDiskStoreFn(t, savedConfig), nil
				}
				t.Cleanup(func() {
					newEncryptedDiskStore = oldEncryptedDiskStore
				})
			}
			if tc.fleetClientFn != nil {
				oldFleetClient := newFleetClient
				newFleetClient = func(log *logger.Logger, apiKey string, cfg remote.Config) (client.Sender, error) {
					return tc.fleetClientFn(t), nil
				}
				t.Cleanup(func() {
					newFleetClient = oldFleetClient
				})
			}
			actualShouldEnroll, err := shouldFleetEnroll(tc.cfg)
			if tc.expectedErr != nil {
				require.ErrorIs(t, err, tc.expectedErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.expectedShouldEnroll, actualShouldEnroll)
			if tc.expectedSavedConfig != nil {
				tc.expectedSavedConfig(t, savedConfig)
			}
		})
	}
}

func TestKibanaFetchPolicy(t *testing.T) {
	tests := []struct {
		name   string
		cfg    setupConfig
		server func(t *testing.T) *httptest.Server
		policy *kibanaPolicy
	}{{
		name: "found by name lookup",
		cfg: setupConfig{
			Fleet: fleetConfig{
				TokenPolicyName: "test-policy",
			},
			Kibana: kibanaConfig{
				RetryMaxCount:      1,
				RetrySleepDuration: 10 * time.Millisecond,
			},
		},
		server: func(t *testing.T) *httptest.Server {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !r.URL.Query().Has("kuery") {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if kuery := r.URL.Query().Get("kuery"); kuery != `name: "test-policy"` {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"items":[{
				    "id": "test-id",
				    "name": "test-policy",
				    "status": "active",
				    "is_default": false,
				    "is_default_fleet_server": false
				    }]}`))
				require.NoError(t, err)
			}))
			return server
		},
		policy: &kibanaPolicy{
			Name:                 "test-policy",
			IsDefault:            false,
			IsDefaultFleetServer: false,
		},
	}, {
		name: "found  by is_default flag",
		cfg: setupConfig{
			Fleet: fleetConfig{
				TokenPolicyName: "test-policy",
			},
			Kibana: kibanaConfig{
				RetryMaxCount:      1,
				RetrySleepDuration: 10 * time.Millisecond,
			},
		},
		server: func(t *testing.T) *httptest.Server {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if !r.URL.Query().Has("kuery") {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch r.URL.Query().Get("kuery") {
				case `name: "test-policy"`:
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte(`{"items": []}`))
					require.NoError(t, err)
				case "is_default: true":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte(`{"items":[{
				    "id": "test-id",
				    "name": "other name",
				    "status": "active",
				    "is_default": true,
				    "is_default_fleet_server": false
				    }]}`))
					require.NoError(t, err)
				default:
					w.WriteHeader(http.StatusBadRequest)
				}
			}))
			return server
		},
		policy: &kibanaPolicy{
			Name:                 "other name",
			IsDefault:            true,
			IsDefaultFleetServer: false,
		},
	}, {
		name: "not found",
		cfg: setupConfig{
			Fleet: fleetConfig{
				TokenPolicyName: "test-policy",
			},
			Kibana: kibanaConfig{
				RetryMaxCount:      1,
				RetrySleepDuration: 10 * time.Millisecond,
			},
		},
		server: func(t *testing.T) *httptest.Server {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"items": []}`))
				require.NoError(t, err)
			}))
			return server
		},
		policy: nil,
	}, {
		name: "found fleet-server policy by id",
		cfg: setupConfig{
			FleetServer: fleetServerConfig{
				Enable:   true,
				PolicyID: "test-server-policy-id",
			},
			Fleet: fleetConfig{
				TokenPolicyName: "test-policy",
			},
			Kibana: kibanaConfig{
				RetryMaxCount:      1,
				RetrySleepDuration: 10 * time.Millisecond,
			},
		},
		server: func(t *testing.T) *httptest.Server {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/fleet/agent_policies/test-server-policy-id" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"item":{
				    "id": "test-server-policy-id",
				    "name": "test-server-policy",
				    "status": "active",
				    "is_default": false,
				    "is_default_fleet_server": false
				    }}`))
				require.NoError(t, err)
			}))
			return server
		},
		policy: &kibanaPolicy{
			Name:                 "test-server-policy",
			IsDefault:            false,
			IsDefaultFleetServer: false,
		},
	}, {
		name: "found fleet-server policy by name",
		cfg: setupConfig{
			FleetServer: fleetServerConfig{
				Enable:   true,
				PolicyID: "test-server-policy-id",
			},
			Fleet: fleetConfig{
				TokenPolicyName: "test-server-policy",
			},
			Kibana: kibanaConfig{
				RetryMaxCount:      1,
				RetrySleepDuration: 10 * time.Millisecond,
			},
		},
		server: func(t *testing.T) *httptest.Server {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/fleet/agent_policies/test-server-policy-id" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					_, err := w.Write([]byte(`{"statusCode": 404, "error": "NotFound", "message": "not found"}`))
					require.NoError(t, err)
					return
				}
				if !r.URL.Query().Has("kuery") {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch r.URL.Query().Get("kuery") {
				case `name: "test-server-policy"`:
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte(`{"items":[{
				    "id": "test-server-policy-id",
				    "name": "test-server-policy",
				    "status": "active",
				    "is_default": false,
				    "is_default_fleet_server": false
				    }]}`))
					require.NoError(t, err)
				default:
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			}))
			return server
		},
		policy: &kibanaPolicy{
			Name:                 "test-server-policy",
			IsDefault:            false,
			IsDefaultFleetServer: false,
		},
	}, {
		name: "found fleet-server policy by is_default_fleet_server flag",
		cfg: setupConfig{
			FleetServer: fleetServerConfig{
				Enable:   true,
				PolicyID: "test-server-policy-id",
			},
			Fleet: fleetConfig{
				TokenPolicyName: "test-policy",
			},
			Kibana: kibanaConfig{
				RetryMaxCount:      1,
				RetrySleepDuration: 10 * time.Millisecond,
			},
		},
		server: func(t *testing.T) *httptest.Server {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/fleet/agent_policies/test-server-policy-id" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					_, err := w.Write([]byte(`{"statusCode": 404, "error": "NotFound", "message": "not found"}`))
					require.NoError(t, err)
					return
				}
				if !r.URL.Query().Has("kuery") {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				switch r.URL.Query().Get("kuery") {
				case `name: "test-policy"`:
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte(`{"items":[]}`))
					require.NoError(t, err)
				case "is_default_fleet_server: true":
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					_, err := w.Write([]byte(`{"items":[{
				    "id": "test-server-policy-id",
				    "name": "test-server-policy",
				    "status": "active",
				    "is_default": false,
				    "is_default_fleet_server": true
				    }]}`))
					require.NoError(t, err)
				default:
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			}))
			return server
		},
		policy: &kibanaPolicy{
			Name:                 "test-server-policy",
			IsDefault:            false,
			IsDefaultFleetServer: true,
		},
	}, {
		name: "fleet-server policy not found",
		cfg: setupConfig{
			FleetServer: fleetServerConfig{
				Enable:   true,
				PolicyID: "test-server-policy-id",
			},
			Fleet: fleetConfig{
				TokenPolicyName: "test-policy",
			},
			Kibana: kibanaConfig{
				RetryMaxCount:      1,
				RetrySleepDuration: 10 * time.Millisecond,
			},
		},
		server: func(t *testing.T) *httptest.Server {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/fleet/agent_policies/test-server-policy-id" {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusNotFound)
					_, err := w.Write([]byte(`{"statusCode": 404, "error": "NotFound", "message": "not found"}`))
					require.NoError(t, err)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"items":[]}`))
				require.NoError(t, err)
			}))
			return server
		},
		policy: nil,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.server(t)
			defer server.Close()

			client := &kibana.Client{
				Connection: kibana.Connection{
					URL:  server.URL,
					HTTP: server.Client(),
				},
			}

			streams, _, _, _ := cli.NewTestingIOStreams()
			policy, err := kibanaFetchPolicy(tc.cfg, client, streams)
			if tc.policy != nil {
				require.NoError(t, err)
				require.NotNil(t, policy)
				require.Equal(t, tc.policy.Name, policy.Name)
				require.Equal(t, tc.policy.IsDefault, policy.IsDefault)
				require.Equal(t, tc.policy.IsDefaultFleetServer, policy.IsDefaultFleetServer)
			} else {
				require.Nil(t, policy)
				require.Error(t, err)
			}
		})
	}
}

func TestKibanaFetchToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/fleet/enrollment_api_keys/test-key" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte(`{"item":{
			    "id": "test-key",
			    "name": "Default (73b9d7da-a8d4-4554-9fc3-7be9bd13e85b)",
			    "active": true,
			    "policy_id": "test-policy-id",
			    "api_key": "key-value"
			}}`))
			require.NoError(t, err)
			require.NoError(t, err)
			return
		}
		if !r.URL.Query().Has("kuery") {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.URL.Query().Get("kuery") != `active: true and policy_id: "test-policy-id"` {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"items":[{
		    "id": "test-key",
		    "name": "Default (73b9d7da-a8d4-4554-9fc3-7be9bd13e85b)",
		    "active": true,
		    "policy_id": "test-policy-id"
		}, {
		    "id": "test-key",
		    "name": "other test key",
		    "active": true,
		    "policy_id": "test-policy-id"
		}],
		"perPage": 10000,
		"page": 1,
		"total": 2}`))
		require.NoError(t, err)
	}))
	defer server.Close()

	cfg := setupConfig{
		Kibana: kibanaConfig{
			RetryMaxCount:      1,
			RetrySleepDuration: 10 * time.Millisecond,
		},
	}

	client := &kibana.Client{
		Connection: kibana.Connection{
			URL:  server.URL,
			HTTP: server.Client(),
		},
	}
	streams, _, _, _ := cli.NewTestingIOStreams()

	t.Run("succeeds", func(t *testing.T) {
		policy := &kibanaPolicy{
			ID:   "test-policy-id",
			Name: "test policy",
		}
		tokenName := "Default"

		token, err := kibanaFetchToken(cfg, client, policy, streams, tokenName)
		require.NoError(t, err)
		require.Equal(t, "key-value", token)
	})
	t.Run("fetch api keys return no matches", func(t *testing.T) {
		policy := &kibanaPolicy{
			ID:   "bad-policy-id",
			Name: "bad policy",
		}
		tokenName := "Default"

		token, err := kibanaFetchToken(cfg, client, policy, streams, tokenName)
		require.Error(t, err)
		require.Empty(t, token)
	})
}
