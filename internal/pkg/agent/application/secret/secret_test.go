// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package secret

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault/aesgcm"
)

func getTestVaultPath(t *testing.T) string {
	dir := t.TempDir()
	return filepath.Join(dir, "vault", "co.elastic.agent")
}

func getTestOptions(t *testing.T) []vault.OptionFunc {
	return []vault.OptionFunc{
		vault.WithVaultPath(getTestVaultPath(t)),
		vault.WithUnprivileged(true),
	}
}

func TestCreate(t *testing.T) {
	opts := getTestOptions(t)

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	start := time.Now().UTC()
	keys := []string{"secret1", "secret2", "secret3"}
	for _, key := range keys {
		err := Create(ctx, key, opts...)
		if err != nil {
			t.Fatal(err)
		}
	}
	end := time.Now().UTC()

	for _, key := range keys {
		secret, err := Get(ctx, key, opts...)
		if err != nil {
			t.Error(err)
		}

		if secret.CreatedOn.Before(start) || secret.CreatedOn.After(end) {
			t.Errorf("invalid created on date/time: %v", secret.CreatedOn)
		}

		diff := cmp.Diff(int(aesgcm.AES256), len(secret.Value))
		if diff != "" {
			t.Error(diff)
		}
	}

	for _, key := range keys {
		err := Remove(ctx, key, opts...)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestHasUnprivilegedVault(t *testing.T) {
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
			name: "file vault exists with agent secret - unprivileged is true",
			setup: setup{
				createFileVault: true,
				setupKeys:       map[string][]byte{AgentSecretKey: []byte("this is the agent secret")},
			},
			want:    true,
			wantErr: assert.NoError,
		},
		{
			name: "file vault exists but it's unreadable - return error",
			setup: setup{
				createFileVault: true,
				setupKeys:       map[string][]byte{AgentSecretKey: []byte("this is the agent secret")},
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
			testVaultPath := filepath.Join(tempDir, "vault")

			//setup
			if tt.setup.createFileVault {
				initFileVault(t, ctx, testVaultPath, tt.setup.setupKeys)
				if tt.setup.postVaultInit != nil {
					tt.setup.postVaultInit(t, testVaultPath)
				}
			}

			got, err := HasUnprivilegedVault(ctx, vault.WithVaultPath(testVaultPath))
			if !tt.wantErr(t, err, fmt.Sprintf("HasUnprivilegedVault(ctx, vault.WithVaultPath(%q))", testVaultPath)) {
				return
			}
			assert.Equalf(t, tt.want, got, "HasUnprivilegedVault(ctx, vault.WithVaultPath(%q))", testVaultPath)
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
