// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// preUpgradeCleanup will remove files that do not have the passed version number from the downloads directory.
func preUpgradeCleanup(version string) error {
	files, err := os.ReadDir(paths.Downloads())
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if !strings.Contains(file.Name(), version) {
			if err := os.Remove(filepath.Join(paths.Downloads(), file.Name())); err != nil {
				return err
			}
		}
	}
	return nil
}

// cleanAllDownloads will remove all files from the downloads directory
func cleanAllDownloads() error {
	files, err := os.ReadDir(paths.Downloads())
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(paths.Downloads(), file.Name())); err != nil {
			return err
		}
	}
	return nil
}
