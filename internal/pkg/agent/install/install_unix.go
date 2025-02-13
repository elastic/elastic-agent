// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

//go:build !windows

package install

import (
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/pkg/utils"
)

// postInstall performs post installation for unix-based systems.
func postInstall(topPath string) error {
	// do nothing
	return nil
}

func fixInstallMarkerPermissions(markerFilePath string, ownership utils.FileOwner) error {
	err := os.Chown(markerFilePath, ownership.UID, ownership.GID)
	if err != nil {
		return fmt.Errorf("failed to chown %d:%d %s: %w", ownership.UID, ownership.GID, markerFilePath, err)
	}
	return nil
}

// withServiceOptions just sets the user/group for the service.
func withServiceOptions(username string, groupName string, _ string) ([]serviceOpt, error) {
	return []serviceOpt{withUserGroup(username, groupName)}, nil
}

func serviceConfigure(ownership utils.FileOwner) error {
	// do nothing on unix
	return nil
}
