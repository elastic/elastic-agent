// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows

package migration

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
)

type configfile struct {
	name        string
	create      bool
	permissions fs.FileMode
	content     []byte
}

func TestMigrateToEncryptedConfig(t *testing.T) {
	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	testcases := []struct {
		name                     string
		unencryptedConfig        configfile
		encryptedConfig          configfile
		expectedFiles            []string
		expectedEncryptedContent []byte
	}{
		{
			name: "no files, no migration",
			unencryptedConfig: configfile{
				name:   "fleet.yml",
				create: false,
			},
			encryptedConfig: configfile{
				name:   "fleet.enc",
				create: false,
			},
			expectedFiles: []string{},
		},
		{
			name: "unencrypted exists encrypted does not -> migrated",
			unencryptedConfig: configfile{
				name:        "fleet.yml",
				create:      true,
				content:     []byte("some legacy fleet config here"),
				permissions: 0644,
			},
			encryptedConfig: configfile{
				name: "fleet.enc",
			},
			expectedFiles:            []string{"fleet.enc"},
			expectedEncryptedContent: []byte("some legacy fleet config here"),
		},
		{
			name: "unencrypted exists encrypted is empty -> migrated",
			unencryptedConfig: configfile{
				name:        "fleet.yml",
				create:      true,
				content:     []byte("some legacy fleet config here"),
				permissions: 0644,
			},
			encryptedConfig: configfile{
				name:        "fleet.enc",
				create:      true,
				permissions: 0644,
			},
			expectedFiles:            []string{"fleet.enc"},
			expectedEncryptedContent: []byte("some legacy fleet config here"),
		},
		{
			name: "both unencrypted and encrypted exist and not empty -> not migrated",
			unencryptedConfig: configfile{
				name:        "fleet.yml",
				create:      true,
				content:     []byte("some legacy fleet config here"),
				permissions: 0644,
			},
			encryptedConfig: configfile{
				name:        "fleet.enc",
				create:      true,
				content:     []byte("some new shiny fleet config here"),
				permissions: 0644,
			},
			expectedFiles:            []string{"fleet.enc"},
			expectedEncryptedContent: []byte("some new shiny fleet config here"),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			//setup begin
			top := t.TempDir()
			paths.SetTop(top)

			vaultPath := paths.AgentVaultPath()
			err := secret.CreateAgentSecret(ctx, secret.WithVaultPath(vaultPath))

			require.NoError(t, err)

			createAndPersistStore(t, ctx, top, tc.unencryptedConfig, false)
			encryptedStore := createAndPersistStore(t, ctx, top, tc.encryptedConfig, true)

			absUnencryptedFile := path.Join(top, tc.unencryptedConfig.name)
			absEncryptedFile := path.Join(top, tc.encryptedConfig.name)

			defer func() {
				// make sure we can delete all the stuff in the temp dir
				err = os.Chmod(absUnencryptedFile, 0777&os.ModePerm)
				if err != nil {
					t.Logf("error setting file permission for %s: %v", absUnencryptedFile, err)
				}
				err = os.Chmod(absEncryptedFile, 0777&os.ModePerm)
				if err != nil {
					t.Logf("error setting file permission for %s: %v", absEncryptedFile, err)
				}
			}()

			log := logp.NewLogger("test_migrate_config")
			// setup end

			err = MigrateToEncryptedConfig(ctx, log, absUnencryptedFile, absEncryptedFile)

			assert.NoError(t, err)
			if len(tc.expectedEncryptedContent) > 0 {
				readCloser, err := encryptedStore.Load()
				require.NoError(t, err)
				defer func() {
					err = readCloser.Close()
					assert.NoError(t, err)
				}()
				actualEncryptedContent, err := io.ReadAll(readCloser)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedEncryptedContent, actualEncryptedContent)
			}

			for _, filename := range tc.expectedFiles {
				assert.FileExistsf(t, path.Join(top, filename), "file %s should exist", filename)
			}
		})
	}
}

func TestErrorMigrateToEncryptedConfig(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("cannot reliably reproduce permission errors on windows")
	}

	ctx, cn := context.WithCancel(context.Background())
	defer cn()

	testcases := []struct {
		name              string
		unencryptedConfig configfile
		encryptedConfig   configfile
	}{
		{
			name: "unencrypted present, encrypted not writable -> error",
			unencryptedConfig: configfile{
				name:        "fleet.yml",
				create:      true,
				content:     []byte("some legacy fleet config here"),
				permissions: 0644,
			},
			encryptedConfig: configfile{
				name:        "fleet.enc",
				create:      true,
				permissions: 0400,
			},
		},
		{
			name: "unencrypted not readable, encrypted does not exist -> error",
			unencryptedConfig: configfile{
				name:        "fleet.yml",
				create:      true,
				content:     []byte("some legacy fleet config here"),
				permissions: 0200,
			},
			encryptedConfig: configfile{
				name:        "fleet.enc",
				permissions: 0644,
			},
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			//setup begin
			top := t.TempDir()
			paths.SetTop(top)

			vaultPath := paths.AgentVaultPath()
			err := secret.CreateAgentSecret(ctx, secret.WithVaultPath(vaultPath))

			require.NoError(t, err)

			createAndPersistStore(t, ctx, top, tc.unencryptedConfig, false)
			createAndPersistStore(t, ctx, top, tc.encryptedConfig, true)

			err = os.Chmod(top, 0555&os.ModePerm)
			require.NoError(t, err)

			absUnencryptedFile := path.Join(top, tc.unencryptedConfig.name)
			absEncryptedFile := path.Join(top, tc.encryptedConfig.name)

			defer func() {
				// make sure we can delete all the stuff in the temp dir
				err = os.Chmod(absUnencryptedFile, 0777&os.ModePerm)
				if err != nil {
					t.Logf("error setting file permission for %s: %v", absUnencryptedFile, err)
				}
				err = os.Chmod(absEncryptedFile, 0777&os.ModePerm)
				if err != nil {
					t.Logf("error setting file permission for %s: %v", absEncryptedFile, err)
				}
				err = os.Chmod(top, 0777&os.ModePerm)
				if err != nil {
					t.Logf("error setting permissions for directory %s: %v", top, err)
				}
			}()

			log := logp.NewLogger("test_migrate_config")
			// setup end

			err = MigrateToEncryptedConfig(ctx, log, absUnencryptedFile, absEncryptedFile)

			assert.Error(t, err)
		})
	}

}

func createAndPersistStore(t *testing.T, ctx context.Context, baseDir string, cf configfile, encrypted bool) storage.Storage {
	var store storage.Storage

	asbFilePath := path.Join(baseDir, cf.name)

	if encrypted {
		store = storage.NewEncryptedDiskStore(ctx, asbFilePath)
	} else {
		store = storage.NewDiskStore(asbFilePath)
	}

	if !cf.create {
		return store
	}

	err := store.Save(bytes.NewReader(cf.content))
	require.NoError(t, err)

	err = os.Chmod(asbFilePath, cf.permissions&fs.ModePerm)
	require.NoError(t, err)

	return store
}
