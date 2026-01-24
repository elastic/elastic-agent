// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package cmd

import (
	_ "embed"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/testutils/fipsutils"
)

var testdata = filepath.Join("testdata", "encrypt")

func TestCheckInputIsStandalone(t *testing.T) {
	t.Run("file does not exist", func(t *testing.T) {
		err := checkInputIsStandalone(filepath.Join(testdata, "does-not-exist.yaml"))
		require.ErrorIs(t, err, os.ErrNotExist)
	})
	t.Run("file is standalone", func(t *testing.T) {
		err := checkInputIsStandalone(filepath.Join(testdata, "standalone.yaml"))
		require.NoError(t, err)
	})
	t.Run("fleet managed config", func(t *testing.T) {
		err := checkInputIsStandalone(filepath.Join(testdata, "fleet.yaml"))
		require.Error(t, err)
	})
}

func TestEncryptConfig(t *testing.T) {
	fipsutils.SkipIfFIPSOnly(t, "encrypted disk storage does not use NewGCMWithRandomNonce.")
	streams, _, _, _ := cli.NewTestingIOStreams()

	vaultDir := t.TempDir()
	err := secret.CreateAgentSecret(t.Context(), vault.WithVaultPath(vaultDir), vault.WithUnprivileged(true))
	require.NoError(t, err)

	t.Run("failed to load source", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "dest.enc")

		err := encryptConfig(streams, filepath.Join(testdata, "does-not-exist.yaml"), dest, storage.WithVaultPath(vaultDir))
		require.Error(t, err)

		_, err = os.Stat(dest)
		require.ErrorIs(t, err, os.ErrNotExist, "expected no destination file to exist")

		t.Run("checkExistingEnc", func(t *testing.T) {
			err := checkExistingEnc(dest, storage.WithVaultPath(vaultDir))
			require.NoError(t, err)
			_, err = os.Stat(dest)
			require.ErrorIs(t, err, os.ErrNotExist)
		})
	})
	t.Run("success writes new file", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "dest.enc")
		err := encryptConfig(streams, filepath.Join(testdata, "standalone.yaml"), dest, storage.WithVaultPath(vaultDir))
		require.NoError(t, err)
		_, err = os.Stat(dest)
		require.NoError(t, err, "expected destination file to exist")

		t.Run("checkExistingEnc", func(t *testing.T) {
			err := checkExistingEnc(filepath.Join(testdata, "standalone.enc"), storage.WithVaultPath(vaultDir))
			require.NoError(t, err)
		})

	})
	t.Run("success replaces existing file", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "dest.enc")
		err := encryptConfig(streams, filepath.Join(testdata, "standalone.yaml"), dest, storage.WithVaultPath(vaultDir))
		require.NoError(t, err)
		_, err = os.Stat(dest)
		require.NoError(t, err)

		origBytes, err := os.ReadFile(dest)
		require.NoError(t, err)

		err = encryptConfig(streams, filepath.Join(testdata, "fleet.yaml"), dest, storage.WithVaultPath(vaultDir))
		require.NoError(t, err)

		replaceBytes, err := os.ReadFile(dest)
		require.NoError(t, err)

		require.NotEqualValues(t, origBytes, replaceBytes, "Expected encrypted config to be replaced.")

		t.Run("checkExistingEnc", func(t *testing.T) {
			err := checkExistingEnc(dest, storage.WithVaultPath(vaultDir))
			require.Error(t, err)
		})
	})
}
