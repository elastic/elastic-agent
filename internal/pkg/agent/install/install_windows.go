// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build windows

package install

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/perms"
	"github.com/elastic/elastic-agent/pkg/utils"
	"github.com/elastic/elastic-agent/version"
)

// postInstall performs post installation for Windows systems.
func postInstall(topPath string) error {
	// delete the top-level elastic-agent.exe
	binary := filepath.Join(topPath, paths.BinaryName)
	err := os.Remove(binary)
	if err != nil {
		// do not handle does not exist, it should have existed
		return err
	}

	// since we removed the top-level elastic-agent.exe we can get
	// rid of the package version file (it was there only in case
	// the top .exe was called with a `version` subcommand )
	err = os.Remove(filepath.Join(topPath, version.PackageVersionFileName))
	if err != nil {
		// do not handle does not exist, it should have existed
		return err
	}

	// create top-level symlink to nested binary
	realBinary := paths.BinaryPath(paths.VersionedHome(topPath), paths.BinaryName)
	err = os.Symlink(realBinary, binary)
	if err != nil {
		return err
	}

	return nil
}

func fixInstallMarkerPermissions(markerFilePath string, ownership utils.FileOwner) error {
	return perms.FixPermissions(markerFilePath, perms.WithOwnership(ownership))
}

// withServiceOptions just sets the user/group for the service.
func withServiceOptions(username string, groupName string) ([]serviceOpt, error) {
	if username == "" {
		// not installed with --unprivileged; nothing to do
		return []serviceOpt{}, nil
	}

	// service requires a password to launch as the user
	// this sets it to a random password that is only known by the service
	password := RandomPassword()
	err := SetUserPassword(username, password)
	if err != nil {
		return nil, fmt.Errorf("failed to set user %s password for service: %w", username, err)
	}

	// username must be prefixed with `.\` so the service references the local systems users
	username = fmt.Sprintf(`.\%s`, username)
	return []serviceOpt{withUserGroup(username, groupName), withPassword(password)}, nil
}
