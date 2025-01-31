// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
	mockStorage "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/agent/storage"
	mockFleetClient "github.com/elastic/elastic-agent/testing/mocks/internal_/pkg/fleetapi/client"
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

func TestKibanaFetchToken(t *testing.T) {
	t.Run("should fetch details from items in the api response", func(t *testing.T) {
		mux := http.NewServeMux()
		mux.HandleFunc("/api/fleet/enrollment_api_keys/", func(w http.ResponseWriter, r *http.Request) {
			basePath := "/api/fleet/enrollment_api_keys/"

			apiKey := kibanaAPIKey{
				ID:       "id",
				PolicyID: "policyID",
				Name:     "tokenName",
				APIKey:   "apiKey",
			}

			trimmed := strings.TrimPrefix(r.URL.String(), basePath)
			if trimmed == "" {
				apiKeys := kibanaAPIKeys{
					Items: []kibanaAPIKey{
						apiKey,
					},
				}
				b, err := json.Marshal(apiKeys)
				require.NoError(t, err)

				_, err = w.Write(b)
				require.NoError(t, err)

				return
			}

			keyDetail := kibanaAPIKeyDetail{
				Item: apiKey,
			}
			b, err := json.Marshal(keyDetail)
			require.NoError(t, err)

			_, err = w.Write(b)
			require.NoError(t, err)
		})

		policy := kibanaPolicy{
			ID: "policyID",
		}

		server := httptest.NewServer(mux)
		defer server.Close()

		client := &kibana.Client{
			Connection: kibana.Connection{
				URL:          server.URL,
				Username:     "",
				Password:     "",
				APIKey:       "",
				ServiceToken: "",
				HTTP:         &http.Client{},
			},
		}
		ak, err := kibanaFetchToken(setupConfig{Kibana: kibanaConfig{RetryMaxCount: 1}}, client, &policy, cli.NewIOStreams(), "tokenName")
		require.NoError(t, err)
		require.Equal(t, "apiKey", ak)
	})
}

func TestShouldEnroll(t *testing.T) {
	enrollmentToken := "test-token"
	enrollmentTokenHash, err := crypto.GeneratePBKDF2FromPassword([]byte(enrollmentToken))
	require.NoError(t, err)
	enrollmentTokenHashBase64 := base64.StdEncoding.EncodeToString(enrollmentTokenHash)

	enrollmentTokenOther := "test-token-other"

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
		"should enroll on fleet url change": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1"}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := mockStorage.NewStorage(t)
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
				m := mockStorage.NewStorage(t)
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
		"should enroll on unauthorized api": {
			statFn: func(path string) (os.FileInfo, error) { return nil, nil },
			cfg:    setupConfig{Fleet: fleetConfig{Enroll: true, URL: "host1", EnrollmentToken: enrollmentToken}},
			encryptedDiskStoreFn: func(t *testing.T, savedConfig *configuration.Configuration) storage.Storage {
				m := mockStorage.NewStorage(t)
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
				m := mockFleetClient.NewSender(t)
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
				m := mockStorage.NewStorage(t)
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
				m := mockFleetClient.NewSender(t)
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
				m := mockStorage.NewStorage(t)
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
				m := mockFleetClient.NewSender(t)
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
				m := mockStorage.NewStorage(t)
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
				m := mockFleetClient.NewSender(t)
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
				m := mockStorage.NewStorage(t)
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
				m := mockFleetClient.NewSender(t)
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
