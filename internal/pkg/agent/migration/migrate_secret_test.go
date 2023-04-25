// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build linux || windows

package migration

import (
	"errors"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofrs/uuid"
	"github.com/google/go-cmp/cmp"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
	"github.com/elastic/elastic-agent/internal/pkg/agent/vault"
)

func TestFindAgentSecretFromHomePath(t *testing.T) {

	tests := []struct {
		name    string
		setupFn func(homePath string) error
		wantErr error
	}{
		{
			name:    "no data dir",
			wantErr: fs.ErrNotExist,
		},
		{
			name: "no vault dir",
			setupFn: func(homePath string) error {
				return os.MkdirAll(homePath, 0750)
			},
			wantErr: fs.ErrNotExist,
		},
		{
			name: "vault file instead of directory",
			setupFn: func(homePath string) error {
				err := os.MkdirAll(homePath, 0750)
				if err != nil {
					return err
				}
				return ioutil.WriteFile(getLegacyVaultPathFromPath(homePath), []byte{}, 0600)
			},
			wantErr: fs.ErrNotExist,
		},
		{
			name: "empty vault directory",
			setupFn: func(homePath string) error {
				return os.MkdirAll(getLegacyVaultPathFromPath(homePath), 0750)
			},
			wantErr: fs.ErrNotExist,
		},
		{
			name: "empty vault",
			setupFn: func(homePath string) error {
				v, err := vault.New(getLegacyVaultPathFromPath(homePath))
				if err != nil {
					return err
				}
				defer v.Close()
				return nil
			},
			wantErr: fs.ErrNotExist,
		},
		{
			name: "vault dir with no seed",
			setupFn: func(homePath string) error {
				vaultPath := getLegacyVaultPathFromPath(homePath)
				v, err := vault.New(vaultPath)
				if err != nil {
					return err
				}
				defer v.Close()
				return os.Remove(filepath.Join(vaultPath, ".seed"))
			},
			wantErr: fs.ErrNotExist,
		},
		{
			name: "vault with secret and misplaced seed vault",
			setupFn: func(homePath string) error {
				vaultPath := getLegacyVaultPathFromPath(homePath)
				err := secret.CreateAgentSecret(secret.WithVaultPath(vaultPath))
				if err != nil {
					return err
				}
				return os.Remove(filepath.Join(vaultPath, ".seed"))
			},
			wantErr: fs.ErrNotExist,
		},
		{
			name: "vault with valid secret",
			setupFn: func(homePath string) error {
				vaultPath := getLegacyVaultPathFromPath(homePath)
				err := secret.CreateAgentSecret(secret.WithVaultPath(vaultPath))
				if err != nil {
					return err
				}
				return generateTestConfig(vaultPath)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			top := t.TempDir()
			paths.SetTop(top)
			homePath := paths.Home()

			if tc.setupFn != nil {
				if err := tc.setupFn(homePath); err != nil {
					t.Fatal(err)
				}
			}

			sec, err := getAgentSecretFromHomePath(homePath)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want err: %v, got err: %v", tc.wantErr, err)
			}

			foundSec, err := findPreviousAgentSecret(filepath.Dir(homePath))
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want err: %v, got err: %v", tc.wantErr, err)
			}
			diff := cmp.Diff(sec, foundSec)
			if diff != "" {
				t.Fatal(diff)
			}

		})
	}
}

type configType int

const (
	NoConfig configType = iota
	MatchingConfig
	NonMatchingConfig
)

func TestFindNewestAgentSecret(t *testing.T) {

	tests := []struct {
		name    string
		cfgType configType
		wantErr error
	}{
		{
			name:    "missing config",
			cfgType: NoConfig,
			wantErr: fs.ErrNotExist,
		},
		{
			name:    "matching config",
			cfgType: MatchingConfig,
		},
		{
			name:    "non-matching config",
			cfgType: NonMatchingConfig,
			wantErr: fs.ErrNotExist,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			top := t.TempDir()
			paths.SetTop(top)
			paths.SetConfig(top)
			dataDir := paths.Data()

			wantSecret, err := generateTestSecrets(dataDir, 3, tc.cfgType)
			if err != nil {
				t.Fatal(err)
			}
			sec, err := findPreviousAgentSecret(dataDir)

			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want err: %v, got err: %v", tc.wantErr, err)
			}
			diff := cmp.Diff(sec, wantSecret)
			if diff != "" {
				t.Fatal(diff)
			}
		})
	}
}

func TestMigrateAgentSecret(t *testing.T) {
	top := t.TempDir()
	paths.SetTop(top)
	paths.SetConfig(top)
	dataDir := paths.Data()

	// No vault home path
	homePath := generateTestHomePath(dataDir)
	if err := os.MkdirAll(homePath, 0750); err != nil {
		t.Fatal(err)
	}

	// Empty vault home path
	homePath = generateTestHomePath(dataDir)
	vaultPath := getLegacyVaultPathFromPath(homePath)
	if err := os.MkdirAll(vaultPath, 0750); err != nil {
		t.Fatal(err)
	}

	// Vault with missing seed
	homePath = generateTestHomePath(dataDir)
	vaultPath = getLegacyVaultPathFromPath(homePath)
	v, err := vault.New(vaultPath)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()

	if err = os.Remove(filepath.Join(vaultPath, ".seed")); err != nil {
		t.Fatal(err)
	}

	// Generate few valid secrets to scan for
	wantSecret, err := generateTestSecrets(dataDir, 5, MatchingConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Expect no agent secret found
	_, err = secret.GetAgentSecret(secret.WithVaultPath(paths.AgentVaultPath()))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("expected err: %v", fs.ErrNotExist)
	}

	// Perform migration
	log := logp.NewLogger("test_agent_secret")
	err = MigrateAgentSecret(log)
	if err != nil {
		t.Fatal(err)
	}

	// Expect the agent secret is migrated now
	sec, err := secret.GetAgentSecret(secret.WithVaultPath(paths.AgentVaultPath()))
	if err != nil {
		t.Fatal(err)
	}

	// Compare the migrated secret with the expected newest one
	diff := cmp.Diff(sec, wantSecret)
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestMigrateAgentSecretAlreadyExists(t *testing.T) {
	top := t.TempDir()
	paths.SetTop(top)
	err := secret.CreateAgentSecret(secret.WithVaultPath(paths.AgentVaultPath()))
	if err != nil {
		t.Fatal(err)
	}

	// Expect agent secret created
	wantSecret, err := secret.GetAgentSecret(secret.WithVaultPath(paths.AgentVaultPath()))
	if err != nil {
		t.Fatal(err)
	}

	// Perform migration
	log := logp.NewLogger("test_agent_secret")
	err = MigrateAgentSecret(log)
	if err != nil {
		t.Fatal(err)
	}

	sec, err := secret.GetAgentSecret(secret.WithVaultPath(paths.AgentVaultPath()))
	if err != nil {
		t.Fatal(err)
	}

	// Compare, should be the same secret
	diff := cmp.Diff(sec, wantSecret)
	if diff != "" {
		t.Fatal(diff)
	}
}

func TestMigrateAgentSecretFromLegacyLocation(t *testing.T) {
	top := t.TempDir()
	paths.SetTop(top)
	paths.SetConfig(top)
	vaultPath := getLegacyVaultPath()
	err := secret.CreateAgentSecret(secret.WithVaultPath(vaultPath))
	if err != nil {
		t.Fatal(err)
	}

	// Expect agent secret created
	wantSecret, err := secret.GetAgentSecret(secret.WithVaultPath(vaultPath))
	if err != nil {
		t.Fatal(err)
	}

	// Perform migration
	log := logp.NewLogger("test_agent_secret")
	err = MigrateAgentSecret(log)
	if err != nil {
		t.Fatal(err)
	}

	sec, err := secret.GetAgentSecret(secret.WithVaultPath(paths.AgentVaultPath()))
	if err != nil {
		t.Fatal(err)
	}

	// Compare, should be the same secret
	diff := cmp.Diff(sec, wantSecret)
	if diff != "" {
		t.Fatal(diff)
	}
}

func generateTestHomePath(dataDir string) string {
	suffix := uuid.Must(uuid.NewV4()).String()[:6]
	return filepath.Join(dataDir, "elastic-agent-"+suffix)
}

func generateTestConfig(vaultPath string) error {
	fleetEncConfigFile := paths.AgentConfigFile()
	store := storage.NewEncryptedDiskStore(fleetEncConfigFile, storage.WithVaultPath(vaultPath))
	return store.Save(strings.NewReader("foo"))
}

func generateTestSecrets(dataDir string, count int, cfgType configType) (wantSecret secret.Secret, err error) {
	now := time.Now()

	// Generate multiple home paths
	//homePaths := make([]string, count)
	for i := 0; i < count; i++ {
		homePath := generateTestHomePath(dataDir)
		k, err := vault.NewKey(vault.AES256)
		if err != nil {
			return wantSecret, err
		}

		sec := secret.Secret{
			Value:     k,
			CreatedOn: now.Add(-time.Duration(i+1) * time.Minute),
		}

		vaultPath := getLegacyVaultPathFromPath(homePath)
		err = secret.SetAgentSecret(sec, secret.WithVaultPath(vaultPath))
		if err != nil {
			return wantSecret, err
		}

		switch cfgType {
		case NoConfig:
		case MatchingConfig, NonMatchingConfig:
			if i == 0 {
				wantSecret = sec
				// Create matching encrypted config file, the content of the file doesn't matter for this test
				err = generateTestConfig(vaultPath)
				if err != nil {
					return wantSecret, err
				}
			}
		}
		// Delete
		if cfgType == NonMatchingConfig && i == 0 {
			_ = os.RemoveAll(vaultPath)
			wantSecret = secret.Secret{}
		}
	}

	return wantSecret, nil
}
