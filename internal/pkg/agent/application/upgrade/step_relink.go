// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package upgrade

import (
	goerrors "errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent-libs/file"
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

	// refuse to rotate to a target that does not exist on disk: callers like the
	// rollback path can pass a stale versioned-home path, which would otherwise
	// leave a dangling live symlink that breaks the next agent restart.
	if _, err := os.Stat(newTarget); err != nil {
		return fmt.Errorf("refusing to rotate agent symlink to non-existent target %q: %w", newTarget, err)
	}

	prevNewPath := prevSymlinkPath(topDirPath)
	log.Infow("Changing symlink", "symlink_path", symlinkPath, "new_path", newTarget, "prev_path", prevNewPath)

	// Remove any leftover staging symlink from a prior interrupted rotation.
	// "Does not exist" is the happy case (nothing to clean up); any other
	// error is fatal. The leading err != nil guard is load-bearing —
	// errors.Is(nil, fs.ErrNotExist) returns false, so dropping the guard would cause
	// the success case (err == nil) to fall into the return branch and
	// skip the symlink creation and rotation below.
	if err := os.Remove(prevNewPath); err != nil && !goerrors.Is(err, fs.ErrNotExist) {
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
