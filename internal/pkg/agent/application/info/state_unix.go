// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

//go:build !windows

package info

import (
	"fmt"
	"os"

	"github.com/elastic/elastic-agent/pkg/utils"
)

func fixInstallMarkerPermissions(markerFilePath string, ownership utils.FileOwner) error {
	err := os.Chown(markerFilePath, ownership.UID, ownership.GID)
	if err != nil {
		return fmt.Errorf("failed to chown %d:%d %s: %w", ownership.UID, ownership.GID, markerFilePath, err)
	}
	return nil
}
