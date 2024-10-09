// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/testing/certutil"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/core/authority"
	"github.com/elastic/elastic-agent/internal/pkg/testutils"
	"github.com/elastic/elastic-agent/pkg/core/logger"
	"github.com/elastic/elastic-agent/pkg/core/logger/loggertest"
)

type mockStore struct {
	Err     error
	Called  bool
	Content []byte
}

func (m *mockStore) Save(in io.Reader) error {
	m.Called = true
	if m.Err != nil {
		return m.Err
	}

	buf := new(bytes.Buffer)
	io.Copy(buf, in) //nolint:errcheck //not required
	m.Content = buf.Bytes()
	return nil
}

func TestEnroll(t *testing.T) {
	testutils.InitStorage(t)
	skipCreateSecret := false
	if runtime.GOOS == "darwin" {
		skipCreateSecret = true
	}

	log, _ := logger.New("tst", false)

	t.Run("fail to save is propagated", withTLSServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/fleet/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`
{
    "action": "created",
    "item": {
       "id": "a9328860-ec54-11e9-93c4-d72ab8a69391",
        "active": true,
        "policy_id": "69f3f5a0-ec52-11e9-93c4-d72ab8a69391",
        "type": "PERMANENT",
        "enrolled_at": "2019-10-11T18:26:37.158Z",
        "user_provided_metadata": {
						"custom": "customize"
				},
        "local_metadata": {
            "platform": "linux",
            "version": "8.0.0"
        },
        "actions": [],
        "access_api_key": "my-access-token"
    }
}`))
			})
			return mux
		}, func(t *testing.T, caBytes []byte, host string) {
			caFile, err := bytesToTMPFile(caBytes)
			require.NoError(t, err)
			defer os.Remove(caFile)

			url := "https://" + host
			store := &mockStore{Err: errors.New("fail to save")}
			cmd, err := newEnrollCmd(
				log,
				&enrollCmdOption{
					URL:                  url,
					CAs:                  []string{caFile},
					EnrollAPIKey:         "my-enrollment-token",
					UserProvidedMetadata: map[string]interface{}{"custom": "customize"},
					SkipCreateSecret:     skipCreateSecret,
				},
				"",
				store,
			)
			require.NoError(t, err)

			streams, _, _, _ := cli.NewTestingIOStreams()
			err = cmd.Execute(context.Background(), streams)
			require.Error(t, err)
		},
	))

	t.Run("successfully enroll with mTLS and save fleet config in the store", func(t *testing.T) {
		agentCertPassphrase := "a really secure passphrase"
		passphrasePath := filepath.Join(t.TempDir(), "passphrase")
		err := os.WriteFile(
			passphrasePath,
			[]byte(agentCertPassphrase),
			0666)
		require.NoError(t, err,
			"could not write agent child certificate key passphrase to temp directory")

		tlsCfg, _, agentCertPathPair, fleetRootPathPair, _ :=
			mTLSServer(t, agentCertPassphrase)

		mockHandlerCalled := false
		mockHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mockHandlerCalled = true
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`
{
    "action": "created",
    "item": {
       "id": "a9328860-ec54-11e9-93c4-d72ab8a69391",
        "active": true,
        "policy_id": "69f3f5a0-ec52-11e9-93c4-d72ab8a69391",
        "type": "PERMANENT",
        "enrolled_at": "2019-10-11T18:26:37.158Z",
        "user_provided_metadata": {
						"custom": "customize"
				},
        "local_metadata": {
            "platform": "linux",
            "version": "8.0.0"
        },
        "actions": [],
        "access_api_key": "my-access-api-key"
    }
}`))
		})

		s := httptest.NewUnstartedServer(mockHandler)
		s.TLS = tlsCfg
		s.StartTLS()
		defer s.Close()

		store := &mockStore{}
		enrollOptions := enrollCmdOption{
			CAs:               []string{string(fleetRootPathPair.Cert)},
			Certificate:       string(agentCertPathPair.Cert),
			Key:               string(agentCertPathPair.Key),
			KeyPassphrasePath: passphrasePath,

			URL:                  s.URL,
			EnrollAPIKey:         "my-enrollment-api-key",
			UserProvidedMetadata: map[string]interface{}{"custom": "customize"},
			SkipCreateSecret:     skipCreateSecret,
			SkipDaemonRestart:    true,
		}
		cmd, err := newEnrollCmd(
			log,
			&enrollOptions,
			"",
			store,
		)
		require.NoError(t, err, "could not create enroll command")

		streams, _, _, _ := cli.NewTestingIOStreams()
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
		defer cancel()

		err = cmd.Execute(ctx, streams)
		require.NoError(t, err, "enroll command returned and unexpected error")

		fleetCfg, err := readConfig(store.Content)
		require.NoError(t, err, "could not read fleet config from store")

		assert.True(t, mockHandlerCalled, "mock handler should have been called")
		fleetTLS := fleetCfg.Client.Transport.TLS

		require.NotNil(t, fleetTLS, `fleet client TLS config should have been set`)
		assert.Equal(t, s.URL, fmt.Sprintf("%s://%s",
			fleetCfg.Client.Protocol, fleetCfg.Client.Host))
		assert.Equal(t, enrollOptions.CAs, fleetTLS.CAs)
		assert.Equal(t,
			enrollOptions.Certificate, fleetTLS.Certificate.Certificate)
		assert.Equal(t, enrollOptions.Key, fleetTLS.Certificate.Key)
		assert.Equal(t,
			enrollOptions.KeyPassphrasePath, fleetTLS.Certificate.PassphrasePath)
	})

	t.Run("successfully enroll with TLS and save access api key in the store", withTLSServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/fleet/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`
{
    "action": "created",
    "item": {
       "id": "a9328860-ec54-11e9-93c4-d72ab8a69391",
        "active": true,
        "policy_id": "69f3f5a0-ec52-11e9-93c4-d72ab8a69391",
        "type": "PERMANENT",
        "enrolled_at": "2019-10-11T18:26:37.158Z",
        "user_provided_metadata": {
						"custom": "customize"
				},
        "local_metadata": {
            "platform": "linux",
            "version": "8.0.0"
        },
        "actions": [],
        "access_api_key": "my-access-api-key"
    }
}`))
			})
			return mux
		}, func(t *testing.T, caBytes []byte, host string) {
			caFile, err := bytesToTMPFile(caBytes)
			require.NoError(t, err)
			defer os.Remove(caFile)

			url := "https://" + host
			store := &mockStore{}
			cmd, err := newEnrollCmd(
				log,
				&enrollCmdOption{
					URL:                  url,
					CAs:                  []string{caFile},
					EnrollAPIKey:         "my-enrollment-api-key",
					UserProvidedMetadata: map[string]interface{}{"custom": "customize"},
					SkipCreateSecret:     skipCreateSecret,
					SkipDaemonRestart:    true,
				},
				"",
				store,
			)
			require.NoError(t, err)

			streams, _, _, _ := cli.NewTestingIOStreams()
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			if err := cmd.Execute(ctx, streams); err != nil {
				t.Fatalf("enroll command returned and unexpected error: %v", err)
			}

			config, err := readConfig(store.Content)
			require.NoError(t, err)

			assert.Equal(t, "my-access-api-key", config.AccessAPIKey)
			assert.Equal(t, host, config.Client.Host)
		},
	))

	t.Run("successfully enroll when a slash is defined at the end of host", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/fleet/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`
{
    "action": "created",
    "item": {
        "id": "a9328860-ec54-11e9-93c4-d72ab8a69391",
        "active": true,
        "policy_id": "69f3f5a0-ec52-11e9-93c4-d72ab8a69391",
        "type": "PERMANENT",
        "enrolled_at": "2019-10-11T18:26:37.158Z",
        "user_provided_metadata": {
						"custom": "customize"
				},
        "local_metadata": {
            "platform": "linux",
            "version": "8.0.0"
        },
        "actions": [],
        "access_api_key": "my-access-api-key"
    }
}`))
			})
			return mux
		}, func(t *testing.T, host string) {
			url := "http://" + host + "/"
			store := &mockStore{}
			cmd, err := newEnrollCmd(
				log,
				&enrollCmdOption{
					URL:                  url,
					CAs:                  []string{},
					EnrollAPIKey:         "my-enrollment-api-key",
					Insecure:             true,
					UserProvidedMetadata: map[string]interface{}{"custom": "customize"},
					SkipCreateSecret:     skipCreateSecret,
					SkipDaemonRestart:    true,
				},
				"",
				store,
			)
			require.NoError(t, err)

			streams, _, _, _ := cli.NewTestingIOStreams()
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			if err := cmd.Execute(ctx, streams); err != nil {
				t.Fatalf("enroll command returned and unexpected error: %v", err)
			}

			assert.True(t, store.Called)
			config, err := readConfig(store.Content)
			require.NoError(t, err, "readConfig returned an error")
			assert.Equal(t, "my-access-api-key", config.AccessAPIKey,
				"The stored 'Access API Key' must be the same returned by Fleet-Server")
			assert.Equal(t, host, config.Client.Host,
				"The stored Fleet-Server host must match the one used during enrol")
		},
	))

	t.Run("successfully enroll without TLS and save access api key in the store", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/fleet/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`
{
    "action": "created",
    "item": {
        "id": "a9328860-ec54-11e9-93c4-d72ab8a69391",
        "active": true,
        "policy_id": "69f3f5a0-ec52-11e9-93c4-d72ab8a69391",
        "type": "PERMANENT",
        "enrolled_at": "2019-10-11T18:26:37.158Z",
        "user_provided_metadata": {
						"custom": "customize"
				},
        "local_metadata": {
            "platform": "linux",
            "version": "8.0.0"
        },
        "actions": [],
        "access_api_key": "my-access-api-key"
    }
}`))
			})
			return mux
		}, func(t *testing.T, host string) {
			url := "http://" + host
			store := &mockStore{}
			cmd, err := newEnrollCmd(
				log,
				&enrollCmdOption{
					URL:                  url,
					CAs:                  []string{},
					EnrollAPIKey:         "my-enrollment-api-key",
					Insecure:             true,
					UserProvidedMetadata: map[string]interface{}{"custom": "customize"},
					SkipCreateSecret:     skipCreateSecret,
					SkipDaemonRestart:    true,
				},
				"",
				store,
			)
			require.NoError(t, err)

			streams, _, _, _ := cli.NewTestingIOStreams()
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()
			err = cmd.Execute(ctx, streams)
			require.NoError(t, err, "enroll command should return no error")

			assert.True(t, store.Called)
			config, err := readConfig(store.Content)
			require.NoError(t, err)
			assert.Equal(t, "my-access-api-key", config.AccessAPIKey)
			assert.Equal(t, host, config.Client.Host)
		},
	))

	t.Run("fail to enroll without TLS", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/fleet/agents/enroll", func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`
{
		"statusCode": 500,
		"error": "Internal Server Error"
}`))
			})
			return mux
		}, func(t *testing.T, host string) {
			url := "http://" + host
			store := &mockStore{}
			cmd, err := newEnrollCmd(
				log,
				&enrollCmdOption{
					URL:                  url,
					CAs:                  []string{},
					EnrollAPIKey:         "my-enrollment-token",
					Insecure:             true,
					UserProvidedMetadata: map[string]interface{}{"custom": "customize"},
					SkipCreateSecret:     skipCreateSecret,
				},
				"",
				store,
			)
			require.NoError(t, err)

			streams, _, _, _ := cli.NewTestingIOStreams()
			err = cmd.Execute(context.Background(), streams)
			require.Error(t, err)
			require.False(t, store.Called)
		},
	))

	counter := int32(0)

	t.Run("there is a retry on a temporary server error", withServer(
		func(t *testing.T) *http.ServeMux {
			mux := http.NewServeMux()
			mux.HandleFunc("/api/fleet/agents/enroll", func(w http.ResponseWriter, r *http.Request) {

				// first request fails with 503, retry is expected
				if atomic.CompareAndSwapInt32(&counter, 0, 1) {
					w.WriteHeader(http.StatusServiceUnavailable)
					_, _ = w.Write([]byte(`
{
		"statusCode": 503,
		"error": "Internal Server Error"
}`))
					return
				}

				// second attempt is successful
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`
{
    "action": "created",
    "item": {
        "id": "a9328860-ec54-11e9-93c4-d72ab8a69391",
        "active": true,
        "policy_id": "69f3f5a0-ec52-11e9-93c4-d72ab8a69391",
        "type": "PERMANENT",
        "enrolled_at": "2019-10-11T18:26:37.158Z",
        "user_provided_metadata": {
						"custom": "customize"
				},
        "local_metadata": {
            "platform": "linux",
            "version": "8.0.0"
        },
        "actions": [],
        "access_api_key": "my-access-api-key"
    }
}`))
			})
			return mux
		}, func(t *testing.T, host string) {
			url := "http://" + host
			store := &mockStore{}
			cmd, err := newEnrollCmd(
				log,
				&enrollCmdOption{
					URL:                  url,
					CAs:                  []string{},
					EnrollAPIKey:         "my-enrollment-api-key",
					Insecure:             true,
					UserProvidedMetadata: map[string]interface{}{"custom": "customize"},
					SkipCreateSecret:     skipCreateSecret,
					SkipDaemonRestart:    true,
				},
				"",
				store,
			)
			require.NoError(t, err)

			streams, _, _, _ := cli.NewTestingIOStreams()
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()
			err = cmd.Execute(ctx, streams)
			require.NoError(t, err, "enroll command should return no error")

			assert.True(t, store.Called, "the store should have been called")
			config, err := readConfig(store.Content)
			require.NoError(t, err)
			assert.Equal(t, "my-access-api-key", config.AccessAPIKey)
			assert.Equal(t, host, config.Client.Host)
		},
	))
}

func TestValidateArgs(t *testing.T) {
	url := "http://localhost:8220"
	enrolmentToken := "my-enrollment-token"
	streams, _, _, _ := cli.NewTestingIOStreams()

	t.Run("comma separated tags are parsed", func(t *testing.T) {
		cmd := newEnrollCommandWithArgs([]string{}, streams)
		err := cmd.Flags().Set("tag", "windows,production")
		require.NoError(t, err)
		err = cmd.Flags().Set("insecure", "true")
		require.NoError(t, err)
		args := buildEnrollmentFlags(cmd, url, enrolmentToken)
		require.NotNil(t, args)
		require.Equal(t, len(args), 11)
		require.Contains(t, args, "--tag")
		require.Contains(t, args, "windows")
		require.Contains(t, args, "production")
		require.Contains(t, args, "--insecure")
		require.Contains(t, args, enrolmentToken)
		require.Contains(t, args, url)
		require.Contains(t, args, "--fleet-server-client-auth")
		require.Contains(t, args, "none")
		cleanedTags := cleanTags(args)
		require.Contains(t, cleanedTags, "windows")
		require.Contains(t, cleanedTags, "production")
	})

	t.Run("comma separated tags and duplicated tags are cleaned", func(t *testing.T) {
		cmd := newEnrollCommandWithArgs([]string{}, streams)
		err := cmd.Flags().Set("tag", "windows, production, windows")
		require.NoError(t, err)
		args := buildEnrollmentFlags(cmd, url, enrolmentToken)
		require.Contains(t, args, "--tag")
		require.Contains(t, args, "windows")
		require.Contains(t, args, " production")
		require.Contains(t, args, "--fleet-server-client-auth")
		require.Contains(t, args, "none")
		cleanedTags := cleanTags(args)
		require.Contains(t, cleanedTags, "windows")
		require.Contains(t, cleanedTags, "production")
		// Validate that we remove the duplicates
		require.Equal(t, len(args), 12)
		require.Equal(t, len(cleanedTags), 9)
	})

	t.Run("valid tag and empty tag", func(t *testing.T) {
		cmd := newEnrollCommandWithArgs([]string{}, streams)
		err := cmd.Flags().Set("tag", "windows, ")
		require.NoError(t, err)
		args := buildEnrollmentFlags(cmd, url, enrolmentToken)
		require.Contains(t, args, "--tag")
		require.Contains(t, args, "windows")
		require.Contains(t, args, " ")
		require.Contains(t, args, "--fleet-server-client-auth")
		require.Contains(t, args, "none")
		cleanedTags := cleanTags(args)
		require.Contains(t, cleanedTags, "windows")
		require.NotContains(t, cleanedTags, " ")
		require.NotContains(t, cleanedTags, "")
	})

	t.Run("secret paths are passed", func(t *testing.T) {
		cmd := newEnrollCommandWithArgs([]string{}, streams)
		err := cmd.Flags().Set("fleet-server-cert-key-passphrase", "/path/to/passphrase")
		require.NoError(t, err)
		err = cmd.Flags().Set("fleet-server-service-token-path", "/path/to/token")
		require.NoError(t, err)
		args := buildEnrollmentFlags(cmd, url, enrolmentToken)
		require.Contains(t, args, "--fleet-server-cert-key-passphrase")
		require.Contains(t, args, "/path/to/passphrase")
		require.Contains(t, args, "--fleet-server-service-token-path")
		require.Contains(t, args, "/path/to/token")
	})

	t.Run("fleet-es client certificates are passed", func(t *testing.T) {
		cmd := newEnrollCommandWithArgs([]string{}, streams)
		err := cmd.Flags().Set("fleet-server-es-cert", "/path/to/cert")
		require.NoError(t, err)
		err = cmd.Flags().Set("fleet-server-es-cert-key", "/path/to/key")
		require.NoError(t, err)
		args := buildEnrollmentFlags(cmd, url, enrolmentToken)
		require.Contains(t, args, "--fleet-server-es-cert")
		require.Contains(t, args, "/path/to/cert")
		require.Contains(t, args, "--fleet-server-es-cert-key")
		require.Contains(t, args, "/path/to/key")
	})

	t.Run("elastic-agent client certificates are passed", func(t *testing.T) {
		cmd := newEnrollCommandWithArgs([]string{}, streams)
		err := cmd.Flags().Set("elastic-agent-cert", "/path/to/cert")
		require.NoError(t, err)
		err = cmd.Flags().Set("elastic-agent-cert-key", "/path/to/key")
		require.NoError(t, err)
		args := buildEnrollmentFlags(cmd, url, enrolmentToken)
		require.Contains(t, args, "--elastic-agent-cert")
		require.Contains(t, args, "/path/to/cert")
		require.Contains(t, args, "--elastic-agent-cert-key")
		require.Contains(t, args, "/path/to/key")
	})
}

func TestValidateEnrollFlags(t *testing.T) {
	streams, _, _, _ := cli.NewTestingIOStreams()

	t.Run("no flags", func(t *testing.T) {
		cmd := newEnrollCommandWithArgs([]string{}, streams)
		err := validateEnrollFlags(cmd)

		assert.NoError(t, err)
	})

	t.Run("service_token and a service_token_path are mutually exclusive", func(t *testing.T) {
		absPath, err := filepath.Abs("/path/to/token")
		require.NoError(t, err, "could not get absolute absPath")

		cmd := newEnrollCommandWithArgs([]string{}, streams)
		err = cmd.Flags().Set("fleet-server-service-token-path", absPath)
		require.NoError(t, err)
		err = cmd.Flags().Set("fleet-server-service-token", "token-value")
		require.NoError(t, err)

		err = validateEnrollFlags(cmd)
		assert.Error(t, err)

		var agentErr errors.Error
		assert.ErrorAs(t, err, &agentErr)
		assert.Equal(t, errors.TypeConfig, agentErr.Type())
	})

	t.Run("elastic-agent-cert-key does not require key-passphrase", func(t *testing.T) {
		absPath, err := filepath.Abs("/path/to/elastic-agent-cert-key")
		require.NoError(t, err, "could not get absolute absPath")

		cmd := newEnrollCommandWithArgs([]string{}, streams)
		err = cmd.Flags().Set("elastic-agent-cert-key", absPath)
		require.NoError(t, err, "could not set flag 'elastic-agent-cert-key'")

		err = validateEnrollFlags(cmd)

		assert.NoError(t, err, "validateEnrollFlags should have succeeded")
	})

	t.Run("elastic-agent-cert-key-passphrase requires certificate and key", func(t *testing.T) {
		absPath, err := filepath.Abs("/path/to/elastic-agent-cert-key-passphrase")
		require.NoError(t, err, "could not get absolute absPath")

		cmd := newEnrollCommandWithArgs([]string{}, streams)
		err = cmd.Flags().Set("elastic-agent-cert-key-passphrase", absPath)
		require.NoError(t, err, "could not set flag 'elastic-agent-cert-key-passphrase'")

		err = validateEnrollFlags(cmd)

		assert.Error(t, err, "validateEnrollFlags should not accept only --elastic-agent-cert-key-passphrase")
		var agentErr errors.Error
		assert.ErrorAs(t, err, &agentErr)
		assert.Equal(t, errors.TypeConfig, agentErr.Type())
	})
}

func TestDaemonReloadWithBackoff(t *testing.T) {
	log, _ := logger.New("tst", false)

	ctx, cn := context.WithCancel(context.Background())
	// Cancel context
	cn()

	tests := []struct {
		name             string
		daemonReloadFunc func(ctx context.Context) error
		wantErr          error
	}{
		{
			name:             "daemonReloadSucceeded",
			daemonReloadFunc: func(ctx context.Context) error { return nil },
		},
		{
			name: "retryWithContextCancelled",
			daemonReloadFunc: func(ctx context.Context) error {
				return errors.New("failed") // Return some (not context's) error so it retries
			},
			wantErr: context.Canceled,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cmd := enrollCmd{
				log:              log,
				daemonReloadFunc: tc.daemonReloadFunc,
			}

			err := cmd.daemonReloadWithBackoff(ctx)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestWaitForFleetServer_timeout(t *testing.T) {
	log, _ := loggertest.New("TestWaitForFleetServer_timeout")
	timeout := 5 * time.Second
	testTimeout := 2 * timeout

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var got string
	var err error
	require.Eventuallyf(t,
		func() bool {
			got, err = waitForFleetServer(ctx, make(chan *os.ProcessState, 1), log, timeout)
			return true
		},
		testTimeout,
		500*time.Millisecond,
		"waitForFleetServer never returned")

	assert.Empty(t, got, "waitForFleetServer should have returned and empty enrollmentToken")
	assert.Error(t, err, "waitForFleetServer should have returned an error")
}

func withServer(
	m func(t *testing.T) *http.ServeMux,
	test func(t *testing.T, host string),
) func(t *testing.T) {
	return func(t *testing.T) {
		s := httptest.NewServer(m(t))
		defer s.Close()
		test(t, s.Listener.Addr().String())
	}
}

func withTLSServer(
	m func(t *testing.T) *http.ServeMux,
	test func(t *testing.T, caBytes []byte, host string),
) func(t *testing.T) {
	return func(t *testing.T) {
		ca, err := authority.NewCA()
		require.NoError(t, err)
		pair, err := ca.GeneratePair()
		require.NoError(t, err)

		serverCert, err := tls.X509KeyPair(pair.Crt, pair.Key)
		require.NoError(t, err)

		listener, err := net.Listen("tcp", "127.0.0.1:0")
		require.NoError(t, err)
		defer listener.Close()

		port := listener.Addr().(*net.TCPAddr).Port

		s := http.Server{ //nolint:gosec // testing server
			Handler: m(t),
			TLSConfig: &tls.Config{
				Certificates: []tls.Certificate{serverCert},
				MinVersion:   tls.VersionTLS12,
			},
		}

		// Uses the X509KeyPair pair defined in the TLSConfig struct instead of file on disk.
		go s.ServeTLS(listener, "", "") //nolint:errcheck // not required

		test(t, ca.Crt(), "localhost:"+strconv.Itoa(port))
	}
}

// mTLSServer generates the necessary certificates and tls.Config for a mTLS
// server. If agentPassphrase is given, it'll encrypt the agent's client
// certificate key.
// It returns the *tls.Config to be used with httptest.NewUnstartedServer,
// the agentRootPair, agentChildPair, fleetRootPathPair, fleetCertPathPair.
// Theirs Cert and Key values are the path to the respective certificate and
// certificate key in PEM format.
func mTLSServer(t *testing.T, agentPassphrase string) (
	*tls.Config, certutil.Pair, certutil.Pair, certutil.Pair, certutil.Pair) {

	dir := t.TempDir()

	// generate certificates
	agentRootPair, agentCertPair, err := certutil.NewRootAndChildCerts()
	require.NoError(t, err, "could not create agent's root CA and child certificate")

	// encrypt keys if needed
	if agentPassphrase != "" {
		agentChildDERKey, _ := pem.Decode(agentCertPair.Key)
		require.NoError(t, err, "could not create tls.Certificates from child certificate")

		encPem, err := x509.EncryptPEMBlock( //nolint:staticcheck // we need to drop support for this, but while we don't, it needs to be tested.
			rand.Reader,
			"EC PRIVATE KEY",
			agentChildDERKey.Bytes,
			[]byte(agentPassphrase),
			x509.PEMCipherAES128)
		require.NoError(t, err, "failed encrypting agent child certificate key block")

		agentCertPair.Key = pem.EncodeToMemory(encPem)
	}

	agentRootPathPair := savePair(t, dir, "agent_ca", agentRootPair)
	agentCertPathPair := savePair(t, dir, "agent_cert", agentCertPair)

	fleetRootPair, fleetChildPair, err := certutil.NewRootAndChildCerts()
	require.NoError(t, err, "could not create fleet-server's root CA and child certificate")
	fleetRootPathPair := savePair(t, dir, "fleet_ca", fleetRootPair)
	fleetCertPathPair := savePair(t, dir, "fleet_cert", fleetChildPair)

	// configure server's TLS
	fleetRootCertPool := x509.NewCertPool()
	fleetRootCertPool.AppendCertsFromPEM(fleetRootPair.Cert)
	cert, err := tls.X509KeyPair(fleetChildPair.Cert, fleetChildPair.Key)
	require.NoError(t, err, "could not create tls.Certificates from child certificate")

	agentRootCertPool := x509.NewCertPool()
	agentRootCertPool.AppendCertsFromPEM(agentRootPair.Cert)

	cfg := &tls.Config{ //nolint:gosec // it's just a test
		RootCAs:      fleetRootCertPool,
		Certificates: []tls.Certificate{cert},
		ClientCAs:    agentRootCertPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}

	return cfg, agentRootPathPair, agentCertPathPair, fleetRootPathPair, fleetCertPathPair
}

// savePair saves the key pair on {dest}/{name}.pem and {dest}/{name}_key.pem
func savePair(t *testing.T, dest string, name string, pair certutil.Pair) certutil.Pair {
	certPath := filepath.Join(dest, name+".pem")
	err := os.WriteFile(certPath, pair.Cert, 0o600)
	require.NoErrorf(t, err, "could not save %s certificate", name)

	keyPath := filepath.Join(dest, name+"_key.pem")
	err = os.WriteFile(keyPath, pair.Key, 0o600)
	require.NoErrorf(t, err, "could not save %s certificate key", name)

	return certutil.Pair{
		Cert: []byte(certPath),
		Key:  []byte(keyPath),
	}
}

func bytesToTMPFile(b []byte) (string, error) {
	f, err := os.CreateTemp("", "prefix")
	if err != nil {
		return "", err
	}
	f.Write(b) //nolint:errcheck // not required
	if err := f.Close(); err != nil {
		return "", err
	}

	return f.Name(), nil
}

func readConfig(raw []byte) (*configuration.FleetAgentConfig, error) {
	r := bytes.NewReader(raw)
	config, err := config.NewConfigFrom(r)
	if err != nil {
		return nil, err
	}

	cfg := configuration.DefaultConfiguration()
	if err := config.Unpack(cfg); err != nil {
		return nil, err
	}
	return cfg.Fleet, nil
}
