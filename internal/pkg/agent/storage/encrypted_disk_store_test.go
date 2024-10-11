// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

func TestNewEncryptedDiskStore(t *testing.T) {

	hasRoot, err := utils.HasRoot()
	require.NoError(t, err, "error checking for administrative privileges")

	type StoreAssertionFunction func(*testing.T, Storage)

	type args struct {
		target string
		opts   []EncryptedOptionFunc
	}
	tests := []struct {
		name    string
		args    args
		want    StoreAssertionFunction
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "simple encrypted store",
			args: args{
				target: "simplestore.enc",
				opts:   nil,
			},
			want: func(t *testing.T, storage Storage) {
				if assert.IsType(t, (*EncryptedDiskStore)(nil), storage, "a *EncryptedDiskStore should have been returned") {
					eds := storage.(*EncryptedDiskStore)
					assert.Equal(t, "simplestore.enc", filepath.Base(eds.target))
					// without override we should have the unprivileged flag set to (not root)
					assert.Equal(t, !hasRoot, eds.unprivileged)
					assert.Equal(t, paths.AgentVaultPath(), eds.vaultPath)
				}
			},
			wantErr: assert.NoError,
		},
		{
			// This testcase sets the unprivileged override to the opposite of the default value ( the default is !hasRoot)
			// and verifies that we respect the override
			name: fmt.Sprintf("encrypted store with unprivileged=%v override", hasRoot),
			args: args{
				target: "privilegedoverridestore.enc",
				opts:   []EncryptedOptionFunc{WithUnprivileged(hasRoot)},
			},
			want: func(t *testing.T, storage Storage) {
				if assert.IsType(t, (*EncryptedDiskStore)(nil), storage, "a *EncryptedDiskStore should have been returned") {
					eds := storage.(*EncryptedDiskStore)
					assert.Equal(t, "privilegedoverridestore.enc", filepath.Base(eds.target))
					// override should have kicked in
					assert.Equal(t, hasRoot, eds.unprivileged)
					assert.Equal(t, paths.AgentVaultPath(), eds.vaultPath)
				}
			},
			wantErr: assert.NoError,
		},
		{
			name: "encrypted store with custom vault path override",
			args: args{
				target: "customvaultpathstore.enc",
				opts:   []EncryptedOptionFunc{WithVaultPath("somecustomvault")},
			},
			want: func(t *testing.T, storage Storage) {
				if assert.IsType(t, (*EncryptedDiskStore)(nil), storage, "a *EncryptedDiskStore should have been returned") {
					eds := storage.(*EncryptedDiskStore)
					assert.Equal(t, "customvaultpathstore.enc", filepath.Base(eds.target))
					// we are running unit tests as non-root so unprivileged should be true by default
					assert.Equal(t, !hasRoot, eds.unprivileged)
					assert.Equal(t, "somecustomvault", eds.vaultPath)
				}
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			tmpDir := t.TempDir()
			got, err := NewEncryptedDiskStore(ctx, filepath.Join(tmpDir, tt.args.target), tt.args.opts...)
			if !tt.wantErr(t, err, fmt.Sprintf("NewEncryptedDiskStore(%v, %v, %v)", ctx, tt.args.target, tt.args.opts)) {
				return
			}
			if tt.want != nil {
				tt.want(t, got)
			}
		})
	}
}
