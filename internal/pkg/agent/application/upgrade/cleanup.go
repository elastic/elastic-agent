// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
)

// preUpgradeCleanup will remove files that do not have the passed version number from the downloads directory.
func preUpgradeCleanup(version string) error {
	files, err := os.ReadDir(paths.Downloads())
	if err != nil {
		return fmt.Errorf("unable to read directory %q: %w", paths.Downloads(), err)
	}
	var rErr error
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if !strings.Contains(file.Name(), version) {
			if err := os.Remove(filepath.Join(paths.Downloads(), file.Name())); err != nil {
				rErr = muliterror.Append(rErr, fmt.Errorf("unable to remove file %q: %w", filepath.Joing(paths.Downloads(), file.Name()), err))
			}
		}
	}
	return rErr
}

// cleanAllDownloads will remove all files from the downloads directory
func cleanAllDownloads() error {
	files, err := os.ReadDir(paths.Downloads())
	if err != nil {
		return fmt.Errorf("unable to read directory %q: %w", paths.Downloads(), err)
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if err := os.Remove(filepath.Join(paths.Downloads(), file.Name())); err != nil {
			rErr = muliterror.Append(rErr, fmt.Errorf("unable to remove file %q: %w", filepath.Joing(paths.Downloads(), file.Name()), err))
		}
	}
	return rErr
}
