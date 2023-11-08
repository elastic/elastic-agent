// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// postInstall performs post installation for unix-based systems.
func postInstall(topPath string) error {
	// do nothing
	return nil
}

// createSocketDir creates the socket directory.
func createSocketDir(ownership utils.FileOwner) error {
	path := filepath.Dir(strings.TrimPrefix(paths.ControlSocketUnprivilegedPath, "unix://"))
	err := os.MkdirAll(path, 0770)
	if err != nil {
		return fmt.Errorf("failed to create path %s: %w", path, err)
	}
	err = os.Chown(path, ownership.UID, ownership.GID)
	if err != nil {
		return fmt.Errorf("failed to chown path %s: %w", path, err)
	}
	// possible that the directory existed, still set the
	// permission again to ensure that they are correct
	err = os.Chmod(path, 0770)
	if err != nil {
		return fmt.Errorf("failed to chmod path %s: %w", path, err)
	}
	return nil
}
