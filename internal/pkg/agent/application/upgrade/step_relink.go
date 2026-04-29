// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	"os"
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent-libs/file"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	windowsOSName = "windows"
	exe           = ".exe"
)

func changeSymlink(log *logger.Logger, topDirPath, symlinkPath, newTarget string) error {

	// handle windows suffixes
	if runtime.GOOS == windowsOSName {
		symlinkPath += exe
		newTarget += exe
	}

	prevNewPath := prevSymlinkPath(topDirPath)
	log.Infow("Changing symlink", "symlink_path", symlinkPath, "new_path", newTarget, "prev_path", prevNewPath)

	// remove symlink to avoid upgrade failures
	if err := os.Remove(prevNewPath); !os.IsNotExist(err) {
		return err
	}

	if err := os.Symlink(newTarget, prevNewPath); err != nil {
		return errors.New(err, errors.TypeFilesystem, "failed to update agent symlink")
	}

	// safely rotate
	return file.SafeFileRotate(symlinkPath, prevNewPath)
}

func prevSymlinkPath(topDirPath string) string {
	agentPrevName := AgentName + ".prev"

	// handle windows suffixes
	if runtime.GOOS == windowsOSName {
		agentPrevName = AgentName + ".exe.prev"
	}

	return filepath.Join(topDirPath, agentPrevName)
}

// AlignActiveInstall points the top-level agent symlink at the binary inside
// versionedHome (relative to topDir) and writes hash to active.commit. Used
// by both the rollback path (target = previous install) and reconcile
// (target = current install).
func AlignActiveInstall(log *logger.Logger, topDir, versionedHome, hash string) error {
	symlinkPath := filepath.Join(topDir, AgentName)

	// paths.BinaryPath properly derives the binary directory depending on the platform. The path to the binary for macOS is inside of the app bundle.
	target := paths.BinaryPath(filepath.Join(topDir, versionedHome), AgentName)
	
	// change symlink
	if err := changeSymlink(log, topDir, symlinkPath, target); err != nil {
		return err
	}

	// revert active commit
	return UpdateActiveCommit(log, topDir, hash, os.WriteFile)
}
