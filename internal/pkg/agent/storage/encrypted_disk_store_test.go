package storage

import (
	"context"
	"fmt"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

func TestNewEncryptedDiskStore(t *testing.T) {
	type StoreAssertionFunction func(*testing.T, Storage)

	type args struct {
		target string
		opts   []OptionFunc
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
					// we are running unit tests as non-root so unprivileged should be true by default
					assert.Equal(t, true, eds.unprivileged)
					assert.Equal(t, paths.AgentVaultPath(), eds.vaultPath)
				}
			},
			wantErr: assert.NoError,
		},
		{
			name: "encrypted store with unprivileged=false override",
			args: args{
				target: "privilegedstore.enc",
				opts:   []OptionFunc{WithUnprivileged(false)},
			},
			want: func(t *testing.T, storage Storage) {
				if assert.IsType(t, (*EncryptedDiskStore)(nil), storage, "a *EncryptedDiskStore should have been returned") {
					eds := storage.(*EncryptedDiskStore)
					assert.Equal(t, "privilegedstore.enc", filepath.Base(eds.target))
					// override should have kicked in
					assert.Equal(t, false, eds.unprivileged)
					assert.Equal(t, paths.AgentVaultPath(), eds.vaultPath)
				}
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				if runtime.GOOS == "darwin" {
					// on Mac OS this test will fail since we are not root and try to force instantiating a keychain vault
					// expecting an error is still a good way to validate that the override took effect
					return assert.Error(t, err, "on Mac OS we expect an error when instantiating an encrypted store with a privileged vault")
				}
				return assert.NoError(t, err)
			},
		},
		{
			name: "encrypted store with custom vault path override",
			args: args{
				target: "customvaultpathstore.enc",
				opts:   []OptionFunc{WithVaultPath("somecustomvault")},
			},
			want: func(t *testing.T, storage Storage) {
				if assert.IsType(t, (*EncryptedDiskStore)(nil), storage, "a *EncryptedDiskStore should have been returned") {
					eds := storage.(*EncryptedDiskStore)
					assert.Equal(t, "customvaultpathstore.enc", filepath.Base(eds.target))
					// we are running unit tests as non-root so unprivileged should be true by default
					assert.Equal(t, true, eds.unprivileged)
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
