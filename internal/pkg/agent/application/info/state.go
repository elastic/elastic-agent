// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package info

import (
	"os"
	"path/filepath"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/pkg/utils"
)

// MarkerFileName is the name of the file that's created by
// `elastic-agent install` in the Agent's topPath folder to
// indicate that the Agent executing from the binary under
// the same topPath folder is an installed Agent.
const MarkerFileName = ".installed"

// RunningInstalled returns true when executing Agent is the installed Agent.
func RunningInstalled() bool {
	// Check if install marker created by `elastic-agent install` exists
	markerFilePath := filepath.Join(paths.Top(), MarkerFileName)
	if _, err := os.Stat(markerFilePath); err != nil {
		return false
	}

	return true
}

func CreateInstallMarker(topPath string, ownership utils.FileOwner) error {
	markerFilePath := filepath.Join(topPath, MarkerFileName)
	if _, err := os.Create(markerFilePath); err != nil {
		return err
	}
	return fixInstallMarkerPermissions(markerFilePath, ownership)
}
