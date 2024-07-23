// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package install

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
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
