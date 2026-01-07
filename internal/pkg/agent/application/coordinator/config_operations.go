// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package coordinator

import (
	"fmt"
	"os"

	"github.com/otiai10/copy"

	"github.com/elastic/elastic-agent-libs/file"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

const (
	backupSuffix = ".enroll.bak"
)

// RestoreConfig restores from backup if needed and signals restore was performed
func RestoreConfig() error {
	configFile := paths.AgentConfigFile()
	backup := configFile + backupSuffix

	// check backup exists
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		return nil
	}

	if err := file.SafeFileRotate(configFile, backup); err != nil {
		return fmt.Errorf("failed to safe rotate backup config file: %w", err)
	}

	return nil
}

// backupConfig creates a backup of currently used fleet config
func backupConfig() error {
	configFile := paths.AgentConfigFile()
	backup := configFile + backupSuffix

	err := copy.Copy(configFile, backup, copy.Options{
		PermissionControl: copy.AddPermission(0600),
		Sync:              true,
	})
	if err != nil {
		return fmt.Errorf("failed to backup config file %s -> %s: %w", configFile, backup, err)
	}

	return nil
}

// cleanBackupConfig removes backup config file
func cleanBackupConfig() error {
	backup := paths.AgentConfigFile() + backupSuffix
	if err := os.RemoveAll(backup); err != nil && !os.IsNotExist(err) {
		return err
	}

	if err := file.SyncParent(backup); err != nil {
		return fmt.Errorf("failed to safe rotate backup config file: %w", err)
	}

	return nil
}
