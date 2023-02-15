// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package migration

import (
	"fmt"
	"io/fs"
	"os"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/agent/storage"
)

// MigrateToEncryptedConfig will copy content from the store specified in unencryptedConfigPath
// to the encrypted store specified in encryptedConfigPath if it doesn't exist already.
// This function is intended to be called during startup when *.yml files exist from a previous version
// but no corresponding *.enc file has been generated yet.
// Notes:
//   - The contents from the unencrypted file will be copied as a byte stream without any transformation.
//   - The function will not perform any operation if the encryptedConfigPath already exists and it's not empty to avoid overwrites.
//   - If neither the encrypted file nor the unencrypted file exist this call is a no-op
func MigrateToEncryptedConfig(l *logp.Logger, unencryptedConfigPath string, encryptedConfigPath string) error {
	encStat, encFileErr := os.Stat(encryptedConfigPath)

	if encFileErr != nil && !errors.Is(encFileErr, fs.ErrNotExist) {
		return errors.New("error checking for existence of %s: %v", encryptedConfigPath, encFileErr)
	}

	unencStat, unencFileErr := os.Stat(unencryptedConfigPath)

	l.Debugf("checking stat of enc config %q: %+v, err: %v", encryptedConfigPath, encStat, encFileErr)
	l.Debugf("checking stat of unenc config %q: %+v, err: %v", unencryptedConfigPath, unencStat, unencFileErr)

	isEncryptedConfigEmpty := errors.Is(encFileErr, fs.ErrNotExist) || encStat.Size() == 0
	isUnencryptedConfigPresent := unencFileErr == nil && unencStat.Size() > 0

	if !isEncryptedConfigEmpty || !isUnencryptedConfigPresent {
		return nil
	}

	l.Info("Initiating migration of %q to %q", unencryptedConfigPath, encryptedConfigPath)
	legacyStore := storage.NewDiskStore(unencryptedConfigPath)
	reader, err := legacyStore.Load()
	if err != nil {
		return errors.New(err, fmt.Sprintf("loading of unencrypted config from file %q failed", unencryptedConfigPath))
	}
	defer func() {
		err = reader.Close()
		if err != nil {
			l.Errorf("Error closing unencrypted store reader for %q: %v", unencryptedConfigPath, err)
		}
	}()
	store := storage.NewEncryptedDiskStore(encryptedConfigPath)
	err = store.Save(reader)
	if err != nil {
		return errors.New(err, fmt.Sprintf("error writing encrypted config from file %q to file %q", unencryptedConfigPath, encryptedConfigPath))
	}
	l.Info("Migration of %q to %q complete", unencryptedConfigPath, encryptedConfigPath)

	return nil
}
