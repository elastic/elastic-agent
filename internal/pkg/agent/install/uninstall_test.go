// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
)

func Test_checkForUnprivilegedVault(t *testing.T) {
	type postVaultInit func(t *testing.T, vaultPath string)

	type setup struct {
		createFileVault bool
		setupKeys       map[string][]byte
		postVaultInit   postVaultInit
	}
	tests := []struct {
		name    string
		setup   setup
		want    bool
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "No file vault exists - unprivileged is false",
			setup:   setup{},
			want:    false,
			wantErr: assert.NoError,
		},
		{
			name: "file vault exists but no secret - unprivileged is false",
			setup: setup{
				createFileVault: true,
			},
			want:    false,
			wantErr: assert.NoError,
		},
		{
			name: "file vault exists with agent secret - unprivileged is false",
			setup: setup{
				createFileVault: true,
				setupKeys:       map[string][]byte{secret.AgentSecretKey: []byte("this is the agent secret")},
			},
			want:    true,
			wantErr: assert.NoError,
		},
		{
			name: "file vault exists but it's unreadable - return error",
			setup: setup{
				createFileVault: true,
				setupKeys:       map[string][]byte{secret.AgentSecretKey: []byte("this is the agent secret")},
				postVaultInit: func(t *testing.T, vaultPath string) {
					if runtime.GOOS == "windows" {
						t.Skip("writable-only files are not really testable on windows")
					}
					err := os.Chmod(vaultPath, 0222)
					require.NoError(t, err, "error setting the file vault write-only, no exec")
					t.Cleanup(func() {
						err = os.Chmod(vaultPath, 0777)
						assert.NoError(t, err, "error restoring read/execute permissions to test vault")
					})
				},
			},
			want: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "permission denied")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			testVaultPath := filepath.Join(tempDir, filepath.Base(paths.AgentVaultPath()))

			//setup
			if tt.setup.createFileVault {
				initFileVault(t, ctx, testVaultPath, tt.setup.setupKeys)
				if tt.setup.postVaultInit != nil {
					tt.setup.postVaultInit(t, testVaultPath)
				}
			}

			got, err := checkForUnprivilegedVault(ctx, vault.WithVaultPath(testVaultPath))
			if !tt.wantErr(t, err, fmt.Sprintf("checkForUnprivilegedVault(ctx, vault.WithVaultPath(%q))", testVaultPath)) {
				return
			}
			assert.Equalf(t, tt.want, got, "checkForUnprivilegedVault(ctx, vault.WithVaultPath(%q))", testVaultPath)
		})
	}
}

func initFileVault(t *testing.T, ctx context.Context, testVaultPath string, keys map[string][]byte) {
	opts, err := vault.ApplyOptions(vault.WithVaultPath(testVaultPath))
	require.NoError(t, err)
	newFileVault, err := vault.NewFileVault(ctx, opts)
	require.NoError(t, err, "setting up test file vault store")
	defer func(newFileVault *vault.FileVault) {
		err := newFileVault.Close()
		require.NoError(t, err, "error closing test file vault after setup")
	}(newFileVault)
	for k, v := range keys {
		err = newFileVault.Set(ctx, k, v)
		require.NoError(t, err, "error setting up key %q = %0x", k, v)
	}
}

func TestNotifyFleetAuditUnenroll(t *testing.T) {
	fleetAuditWait = time.Millisecond * 10
	t.Cleanup(func() {
		fleetAuditWait = time.Second * 10
	})

	tests := []struct {
		name      string
		getServer func() *httptest.Server
		err       error
	}{{
		name: "suceeds after a retry",
		getServer: func() *httptest.Server {
			callCount := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if callCount == 0 {
					callCount++
					w.WriteHeader(http.StatusNotFound)
					return
				}
				callCount++
				w.WriteHeader(http.StatusOK)
			}))
			return server
		},
		err: nil,
	}, {
		name: "returns 401",
		getServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}))
		},
		err: client.ErrInvalidAPIKey,
	}, {
		name: "returns 409",
		getServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusConflict)
			}))
		},
		err: fmt.Errorf("unretryable return status: 409"),
	}}

	log, _ := logp.NewInMemory("test", zap.NewDevelopmentEncoderConfig())
	pt := progressbar.NewOptions(-1, progressbar.OptionSetWriter(io.Discard))
	ai := &info.AgentInfo{}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := tc.getServer()
			defer server.Close()

			cfg := &configuration.Configuration{
				Fleet: &configuration.FleetAgentConfig{
					AccessAPIKey: "example-key",
					Client: remote.Config{
						Protocol: remote.ProtocolHTTP,
						Host:     server.URL,
					},
				},
			}
			err := notifyFleetAuditUninstall(context.Background(), log, pt, cfg, ai)
			if tc.err == nil {
				assert.NoError(t, err)
			} else {
				assert.ErrorContains(t, err, tc.err.Error())
			}
		})
	}

	t.Run("fails with no retries", func(t *testing.T) {
		fleetAuditAttempts = 1
		t.Cleanup(func() {
			fleetAuditAttempts = 10
		})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()

		cfg := &configuration.Configuration{
			Fleet: &configuration.FleetAgentConfig{
				AccessAPIKey: "example-key",
				Client: remote.Config{
					Protocol: remote.ProtocolHTTP,
					Host:     server.URL,
				},
			},
		}
		err := notifyFleetAuditUninstall(context.Background(), log, pt, cfg, ai)
		assert.EqualError(t, err, "notify Fleet: failed")

	})
}
