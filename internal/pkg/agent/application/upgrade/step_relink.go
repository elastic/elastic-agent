// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package upgrade

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/elastic/elastic-agent-libs/file"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	windows = "windows"
	exe     = ".exe"
)

// ChangeSymlink updates symlink paths to match current version.
func ChangeSymlink(ctx context.Context, log *logger.Logger, targetHash string) error {
	// create symlink to elastic-agent-{hash}
	hashedDir := fmt.Sprintf("%s-%s", agentName, targetHash)

	symlinkPath := filepath.Join(paths.Top(), agentName)

	// paths.BinaryPath properly derives the binary directory depending on the platform. The path to the binary for macOS is inside of the app bundle.
	newPath := paths.BinaryPath(filepath.Join(paths.Top(), "data", hashedDir), agentName)

	// handle windows suffixes
	if runtime.GOOS == windows {
		symlinkPath += exe
		newPath += exe
	}

	prevNewPath := prevSymlinkPath()
	log.Infow("Changing symlink", "symlink_path", symlinkPath, "new_path", newPath, "prev_path", prevNewPath)

	// remove symlink to avoid upgrade failures
	if err := os.Remove(prevNewPath); !os.IsNotExist(err) {
		return err
	}

	if err := os.Symlink(newPath, prevNewPath); err != nil {
		return errors.New(err, errors.TypeFilesystem, "failed to update agent symlink")
	}

	// safely rotate
	return file.SafeFileRotate(symlinkPath, prevNewPath)
}

func prevSymlinkPath() string {
	agentPrevName := agentName + ".prev"

	// handle windows suffixes
	if runtime.GOOS == windows {
		agentPrevName = agentName + ".exe.prev"
	}

	return filepath.Join(paths.Top(), agentPrevName)
}
