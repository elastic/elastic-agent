// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package migration

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/secret"
)

const (
	darwin = "darwin"
)

// MigrateAgentSecret migrates agent secret if the secret doesn't exists agent upgrade from 8.3.0 - 8.3.2 to 8.x and above on Linux and Windows platforms.
func MigrateAgentSecret(log *logp.Logger) error {
	// Nothing to migrate for darwin
	if runtime.GOOS == darwin {
		return nil
	}

	// Check if the secret already exists
	log.Debug("migrate agent secret, check if secret already exists")
	_, err := secret.GetAgentSecret()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The secret doesn't exists, perform migration below
			log.Debug("agent secret doesn't exists, perform migration")
		} else {
			log.Errorf("failed read the agent secret: %v", err)
			return err
		}
	} else {
		// The secret already exists, nothing to migrate
		log.Debug("secret already exists nothing to migrate")
		return nil
	}

	// Check if the secret was copied by the fleet upgrade handler to the legacy location
	log.Debug("check if secret was copied over by 8.3.0-8.3.2 version of the agent")
	sec, err := getAgentSecretFromHomePath(paths.Home())
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The secret is not found in this instance of the vault, continue with migration
			log.Debug("agent secret copied from 8.3.0-.8.3.2 doesn't exists, continue with migration")
		} else {
			log.Errorf("failed agent 8.3.0-8.3.2 secret check: %v", err)
			return err
		}
	} else {
		// The secret is found, save in the new agent vault
		log.Debug("agent secret from 8.3.0-.8.3.2 is found, migrate to the new vault")
		return secret.SetAgentSecret(sec)
	}

	// Scan other agent data directories, find the latest agent secret
	log.Debug("search for possible latest agent 8.3.0-.8.3.2 secret")
	dataDir := paths.Data()

	sec, err = findPreviousAgentSecret(dataDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// The secret is not found
			log.Debug("no previous agent 8.3.0-.8.3.2 secrets found, nothing to migrate")
			return nil
		}
		log.Errorf("search for possible latest agent 8.3.0-.8.3.2 secret failed: %v", err)
		return err
	}
	log.Debug("found previous agent 8.3.0-.8.3.2 secret, migrate to the new vault")
	return secret.SetAgentSecret(sec)
}

func findPreviousAgentSecret(dataDir string) (sec secret.Secret, err error) {
	found := false
	fileSystem := os.DirFS(dataDir)
	err = fs.WalkDir(fileSystem, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if strings.HasPrefix(d.Name(), "elastic-agent-") {
				vaultPath := getLegacyVaultPathFromPath(filepath.Join(dataDir, path))
				s, err := secret.GetAgentSecret(secret.WithVaultPath(vaultPath))
				// Ignore if error, keep scanning
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
				}
				if s.CreatedOn.After(sec.CreatedOn) {
					sec = s
					found = true
				}
			} else if d.Name() != "." {
				return fs.SkipDir
			}
		}
		return nil
	})
	if !found {
		return sec, fs.ErrNotExist
	}
	return sec, err
}

func getAgentSecretFromHomePath(homePath string) (sec secret.Secret, err error) {
	vaultPath := getLegacyVaultPathFromPath(homePath)
	fi, err := os.Stat(vaultPath)
	if err != nil {
		return
	}

	if !fi.IsDir() {
		return sec, fs.ErrNotExist
	}
	return secret.GetAgentSecret(secret.WithVaultPath(vaultPath))
}

func getLegacyVaultPath() string {
	return getLegacyVaultPathFromPath(paths.Home())
}

func getLegacyVaultPathFromPath(homePath string) string {
	return filepath.Join(homePath, "vault")
}
