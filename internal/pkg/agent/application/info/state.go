// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package info

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
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

func CreateInstallMarker(topPath string, uidStr string, gidStr string) error {
	markerFilePath := filepath.Join(topPath, MarkerFileName)
	if _, err := os.Create(markerFilePath); err != nil {
		return err
	}

	var err error
	if runtime.GOOS != "windows" {
		uid := os.Getuid()
		gid := os.Getgid()
		if uidStr != "" {
			uid, err = strconv.Atoi(uidStr)
			if err != nil {
				return fmt.Errorf("failed to convert uid(%s) to int: %w", uidStr, err)
			}
		}
		if gidStr != "" {
			gid, err = strconv.Atoi(gidStr)
			if err != nil {
				return fmt.Errorf("failed to convert gid(%s) to int: %w", gidStr, err)
			}
		}
		err = os.Chown(markerFilePath, uid, gid)
		if err != nil {
			return fmt.Errorf("failed to chown %d:%d %s: %w", uid, gid, markerFilePath, err)
		}
	}

	return nil
}
