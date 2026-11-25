// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package install

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/elastic/beats/v7/pkg/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths/pathstest"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	pkgfleetapi "github.com/elastic/elastic-agent/pkg/fleetapi"
)

// noopProgressDescriber is a no-op ProgressDescriber for use in tests.
type noopProgressDescriber struct{}

func (n *noopProgressDescriber) Describe(string) {}

func TestEnableUninstallFileLog(t *testing.T) {
	pathstest.SetTop(t, t.TempDir())

	teed, closeLog, err := enableUninstallFileLog(logp.NewLogger("uninstall"))
	require.NoError(t, err)
	require.NotNil(t, teed)

	teed.Info("streamed-uninstall-line")
	// The reason a uninstall fails is logged at error level (see Uninstall's
	// deferred error log); make sure that level reaches the file too.
	teed.Errorf("uninstall failed: %v", errors.New("boom"))
	// The file must be readable (closed) before the install tree is removed, and
	// closing must be idempotent (called explicitly and via defer).
	closeLog()
	closeLog()

	logPath := filepath.Join(paths.BuildLogs(), uninstallLogName)
	data, err := os.ReadFile(logPath)
	require.NoError(t, err)
	assert.Contains(t, string(data), "streamed-uninstall-line",
		"the uninstaller log line must be streamed to the collectable log file")
	assert.Contains(t, string(data), "uninstall failed: boom",
		"the uninstall failure reason must be streamed to the collectable log file")
}

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
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
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
	fleetAuditWaitInit = time.Millisecond * 10
	fleetAuditWaitMax = time.Millisecond * 100
	t.Cleanup(func() {
		fleetAuditWaitInit = time.Second
		fleetAuditWaitMax = time.Second * 10
	})

	tests := []struct {
		name      string
		getServer func() *httptest.Server
		err       error
	}{{
		name: "succeeds after a retry",
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
		err: nil,
	}, {
		name: "returns 409",
		getServer: func() *httptest.Server {
			return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusConflict)
			}))
		},
		err: fmt.Errorf("unretryable return status: 409"),
	}}

	log, _ := logp.NewInMemoryLocal("test", zap.NewDevelopmentEncoderConfig())
	pt := &noopProgressDescriber{}
	var agentID agentInfo = "testID"

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
			err := notifyFleetAuditUninstall(context.Background(), log, pt, cfg, &agentID)
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
		err := notifyFleetAuditUninstall(context.Background(), log, pt, cfg, &agentID)
		assert.EqualError(t, err, "notify Fleet: failed")

	})
}

func TestAckFleetUninstallAction(t *testing.T) {
	const actionID = "uninstall-action-id"
	log, _ := logp.NewInMemoryLocal("test", zap.NewDevelopmentEncoderConfig())
	pt := &noopProgressDescriber{}
	var agentID agentInfo = "testID"

	newCfg := func(host string) *configuration.Configuration {
		return &configuration.Configuration{
			Fleet: &configuration.FleetAgentConfig{
				AccessAPIKey: "example-key",
				Client: remote.Config{
					Protocol: remote.ProtocolHTTP,
					Host:     host,
				},
			},
		}
	}

	t.Run("acks the action successfully", func(t *testing.T) {
		var gotPath string
		var gotBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"action":"acks"}`))
		}))
		defer server.Close()

		err := ackFleetUninstallAction(context.Background(), log, pt, newCfg(server.URL), &agentID, actionID, nil)
		require.NoError(t, err)
		assert.Equal(t, fmt.Sprintf("/api/fleet/agents/%s/acks", agentID), gotPath,
			"ack must be sent to the agent's acks endpoint")
		assert.Contains(t, gotBody, actionID, "ack request must carry the action id")
	})

	t.Run("a failure ack carries the error", func(t *testing.T) {
		var gotBody string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			gotBody = string(b)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"action":"acks"}`))
		}))
		defer server.Close()

		err := ackFleetUninstallAction(context.Background(), log, pt, newCfg(server.URL), &agentID, actionID,
			errors.New("uninstall failed before point of no return"))
		require.NoError(t, err)
		assert.Contains(t, gotBody, "uninstall failed before point of no return",
			"a failure ack must include the action error so Fleet learns the uninstall did not complete")
	})

	t.Run("returns an error when Fleet rejects the ack", func(t *testing.T) {
		fleetAuditAttempts = 1
		t.Cleanup(func() { fleetAuditAttempts = 10 })
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		err := ackFleetUninstallAction(context.Background(), log, pt, newCfg(server.URL), &agentID, actionID, nil)
		require.Error(t, err)
	})

	t.Run("returns an error when Fleet returns HTTP 200 with a failed item", func(t *testing.T) {
		fleetAuditAttempts = 1
		t.Cleanup(func() { fleetAuditAttempts = 10 })
		// Fleet Server can reject an acknowledgement at the item level while still
		// returning HTTP 200 (errors: true). This must be treated as a failure (and
		// retried) rather than success; otherwise the uninstaller removes its
		// credentials and can never acknowledge the terminal action again.
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"action":"acks","errors":true,"items":[{"status":409}]}`))
		}))
		defer server.Close()

		err := ackFleetUninstallAction(context.Background(), log, pt, newCfg(server.URL), &agentID, actionID, nil)
		require.Error(t, err, "an HTTP-200 ack with errors:true must be reported as a failure")
	})

	t.Run("returns an error when no fleet configuration is available", func(t *testing.T) {
		err := ackFleetUninstallAction(context.Background(), log, pt, &configuration.Configuration{}, &agentID, actionID, nil)
		require.Error(t, err)
	})
}

type MockNotifyFleetAuditUninstall struct {
	Called bool
}

func (m *MockNotifyFleetAuditUninstall) Call(ctx context.Context, log *logp.Logger, pt ProgressDescriber, cfg *configuration.Configuration, ai pkgfleetapi.AgentInfo) {
	m.Called = true
}

func TestSkipFleetAuditUnenroll(t *testing.T) {
	log := &logp.Logger{}
	pt := &noopProgressDescriber{}
	cfg := &configuration.Configuration{}
	var agentID agentInfo = "testID"

	testCases := []struct {
		notifyFleet    bool
		localFleet     bool
		skipFleetAudit bool
	}{
		{true, true, true},
		{true, true, false},
		{true, false, true},
		{false, true, true},
		{false, true, false},
		{false, false, true},
		{false, false, false},
	}

	for i, tc := range testCases {
		t.Run(
			fmt.Sprintf("test case #%d: %t:%t:%t", i, tc.notifyFleet, tc.localFleet, tc.skipFleetAudit),
			func(t *testing.T) {
				mockNotify := &MockNotifyFleetAuditUninstall{}
				notifyFleetIfNeeded(context.Background(), log, pt, cfg, agentID, tc.notifyFleet, tc.localFleet, tc.skipFleetAudit, notifyFleetAuditUninstall)
				assert.False(t, mockNotify.Called, "NotifyFleetAuditUninstall should not be invoked when notifyFleet: %t - localFleet: %t - skipFleetAudit: %t", tc.notifyFleet, tc.localFleet, tc.skipFleetAudit)
			},
		)
	}

}

func TestRemovePathContext(t *testing.T) {
	t.Run("removes the path", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "remove-me")
		require.NoError(t, os.MkdirAll(filepath.Join(dir, "sub"), 0o755))

		require.NoError(t, RemovePathContext(t.Context(), logp.NewNopLogger(), dir))

		assert.NoDirExists(t, dir)
	})

	t.Run("a done context stops before removing anything", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "keep-me")
		require.NoError(t, os.MkdirAll(dir, 0o755))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		err := RemovePathContext(ctx, logp.NewNopLogger(), dir)

		assert.ErrorIs(t, err, context.Canceled)
		assert.DirExists(t, dir)
	})

	t.Run("a path that does not exist is not an error", func(t *testing.T) {
		assert.NoError(t, RemovePathContext(t.Context(), logp.NewNopLogger(), filepath.Join(t.TempDir(), "missing")))
	})
}
